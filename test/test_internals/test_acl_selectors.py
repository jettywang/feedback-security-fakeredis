import pytest
import redis

import fakeredis

pytestmark = [pytest.mark.fake]


@pytest.fixture
def r():
    server = fakeredis.FakeServer(version=(8,))
    return fakeredis.FakeRedis(server=server)


@pytest.fixture
def limited(r):
    client = fakeredis.FakeRedis(server=r.connection_pool.connection_kwargs["server"])
    r.acl_deluser("limited")
    yield client
    client.auth("", username="default")
    r.acl_deluser("limited")


def set_selectors(r, *rules: bytes) -> None:
    r.execute_command("ACL", "SETUSER", "limited", "reset", "on", "nopass", *rules)


def assert_denied(client: fakeredis.FakeRedis, operation) -> None:
    with pytest.raises(redis.exceptions.NoPermissionError):
        operation(client)


def test_command_and_key_permissions_are_not_combined_across_selectors(r, limited):
    r.set("app:1", "seed")
    r.set("wrong:1", "seed")
    r.set("other:1", "seed")

    # Selector 1 grants the GET command, but its write-only (%W) key pattern never matches a read.
    # Selector 2 matches app:* keys, but grants no independently usable read permission for them.
    set_selectors(r, b"(+get %W~wrong:*)", b"(+get %W~app:*)")
    limited.auth("", username="limited")

    # Expected: GET app:1 is denied because neither selector alone grants GET on an app:* key.
    assert_denied(limited, lambda c: c.get("app:1"))
    # Expected: SET app:1 is denied; neither selector grants the SET command.
    assert_denied(limited, lambda c: c.set("app:1", "changed"))
    # Expected: GET wrong:1 matches selector 1's command, but not its read key pattern.
    assert_denied(limited, lambda c: c.get("wrong:1"))
    # Expected: GET other:1 is not covered by any selector key pattern.
    assert_denied(limited, lambda c: c.get("other:1"))

    # No denied operation may mutate state.
    assert r.get("app:1") == b"seed"
    assert r.get("wrong:1") == b"seed"
    assert r.get("other:1") == b"seed"

    # Control: one selector independently granting both command and key allows the same operation.
    set_selectors(r, b"(+get %R~app:*)")
    limited.auth("", username="limited")
    assert limited.get("app:1") == b"seed"


def test_read_and_write_key_patterns_enforce_r_and_w_modes(r, limited):
    # Selector 1: GET and SET on ro:*, but only for read access (%R).
    # Selector 2: GET and SET on wo:*, but only for write access (%W).
    # Selector 3: GET and SET on rw:* for both read and write access (%RW).
    set_selectors(
        r,
        b"(+get +set %R~ro:*)",
        b"(+get +set %W~wo:*)",
        b"(+get +set %RW~rw:*)",
    )
    limited.auth("", username="limited")

    assert limited.get("rw:1") is None
    assert limited.set("rw:1", "both")
    assert limited.get("rw:1") == b"both"

    assert limited.get("ro:1") is None
    assert_denied(limited, lambda c: c.set("ro:1", "write"))
    assert not r.exists("ro:1")

    assert limited.set("wo:1", "write")
    assert_denied(limited, lambda c: c.get("wo:1"))
    assert r.get("wo:1") == b"write"


def test_multi_key_commands_need_every_key_in_one_selector(r, limited):
    # Each selector grants the commands only on its own key prefix.
    set_selectors(r, b"(+mget +mset +del ~a:*)", b"(+mget +mset +del ~b:*)")
    limited.auth("", username="limited")

    # Expected: all keys match selector 1, so the multi-key command is allowed.
    assert limited.mget("a:1", "a:2") == [None, None]
    assert limited.mset({"a:1": "1", "a:2": "2"})
    assert limited.mget("a:1", "a:2") == [b"1", b"2"]

    # Expected: key permissions cannot be split between the two selectors.
    assert_denied(limited, lambda c: c.mget("a:1", "b:1"))
    assert_denied(limited, lambda c: c.mset({"a:1": "x", "b:1": "x"}))
    assert_denied(limited, lambda c: c.delete("a:1", "b:1"))

    # Expected: the denied MSET did not create the otherwise-uncovered key.
    assert not r.exists("b:1")

    # Control: a single selector covering both patterns grants the full multi-key command.
    set_selectors(r, b"(+mget +mset +del ~a:* ~b:*)")
    limited.auth("", username="limited")
    assert limited.mget("a:1", "b:1") == [b"1", None]
    assert limited.mset({"a:1": "y", "b:1": "y"})
    assert limited.mget("a:1", "b:1") == [b"y", b"y"]


def test_category_grant_and_removal_apply_within_one_selector(r, limited):
    # Selector grants every command on cat:*, then removes the @write category.
    set_selectors(r, b"(+@all -@write ~cat:*)")
    limited.auth("", username="limited")

    assert limited.get("cat:1") is None
    assert_denied(limited, lambda c: c.set("cat:1", "value"))
    assert_denied(limited, lambda c: c.sadd("cat:2", "member"))
    assert not r.exists("cat:1")
    assert not r.exists("cat:2")

    # A narrower selector shows @string category grant and explicit command removal.
    set_selectors(r, b"(+@string -del ~str:*)")
    limited.auth("", username="limited")
    assert limited.set("str:1", "value")
    assert limited.get("str:1") == b"value"
    assert_denied(limited, lambda c: c.delete("str:1"))
    assert r.exists("str:1")

    # Expected: the category grant does not apply outside the selector's key pattern.
    assert_denied(limited, lambda c: c.get("other:1"))


def test_root_key_patterns_also_enforce_r_and_w_modes(r, limited):
    r.execute_command(
        "ACL",
        "SETUSER",
        "limited",
        "reset",
        "on",
        "nopass",
        b"+get",
        b"+set",
        b"%R~ro:*",
        b"%W~wo:*",
        b"%RW~rw:*",
    )
    limited.auth("", username="limited")

    assert limited.get("ro:1") is None
    assert_denied(limited, lambda c: c.set("ro:1", "write"))
    assert not r.exists("ro:1")

    assert limited.set("wo:1", "write")
    assert_denied(limited, lambda c: c.get("wo:1"))

    assert limited.set("rw:1", "write")
    assert limited.get("rw:1") == b"write"


def test_selector_without_key_pattern_cannot_access_keys(r, limited):
    set_selectors(r, b"(+get resetchannels)")
    limited.auth("", username="limited")

    assert_denied(limited, lambda c: c.get("app:1"))
    assert not r.exists("app:1")


def test_selector_channels_are_checked_inside_the_same_selector(r, limited):
    set_selectors(r, b"(+publish resetchannels &news:*)")
    limited.auth("", username="limited")

    assert limited.publish("news:1", "message") == 0
    assert_denied(limited, lambda c: c.publish("other:1", "message"))


def test_subcommand_selector_uses_the_subcommand_key_argument(r, limited):
    set_selectors(r, b"(+xgroup|create ~stream:*)")
    limited.auth("", username="limited")

    assert limited.xgroup_create("stream:1", "group:1", id="$", mkstream=True)
    assert_denied(limited, lambda c: c.xgroup_create("other:1", "group:1", id="$", mkstream=True))


def test_selector_rules_round_trip_without_loosing_modes(r, limited):
    set_selectors(
        r,
        b"(+set %W~app:* resetchannels)",
        b"(+get +mget %RW~app:* resetchannels &updates:*)",
    )
    rule = next(rule for rule in r.acl_list() if rule.startswith("user limited "))
    assert "(%W~app:* resetchannels -@all +set)" in rule
    assert "(%RW~app:* resetchannels &updates:* -@all +get +mget)" in rule

    limited.auth("", username="limited")
    assert limited.set("app:1", "value")
    assert limited.mget("app:1") == [b"value"]
