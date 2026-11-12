import pytest
import redis

import fakeredis
from fakeredis.model._acl import UserAccessControlList

pytestmark = [pytest.mark.fake]


@pytest.fixture
def r():
    return fakeredis.FakeRedis(server=fakeredis.FakeServer(version=(8,)))


def _user(*rules: bytes, keys: bytes = b"*", channels: bytes = b"*") -> UserAccessControlList:
    user = UserAccessControlList()
    for rule in rules:
        user.add_command_or_category(rule)
    if keys:
        user.add_key_pattern(keys)
    if channels:
        user.add_channel_pattern(channels)
    return user


def test_unrestricted():
    assert _user(b"+@all").unrestricted()
    assert not _user().unrestricted()
    assert not _user(b"+get").unrestricted()
    assert not _user(b"+@all", b"-get").unrestricted()
    assert not _user(b"+@all", b"-@dangerous").unrestricted()
    assert not _user(b"+@all", keys=b"cache:*").unrestricted()
    assert not _user(b"+@all", channels=b"news:*").unrestricted()
    assert not _user(b"+@all", keys=b"").unrestricted()


def test_restricting_the_default_user_takes_effect(r: redis.Redis):
    assert r.set("cache:0", 1)
    assert r.set("other:0", 1)

    r.acl_setuser("default", enabled=True, reset=True, nopass=True, commands=["+@all"], keys=["cache:*"])
    assert r.get("cache:0") == b"1"
    with pytest.raises(redis.exceptions.NoPermissionError):
        r.get("other:0")

    r.acl_setuser("default", enabled=True, reset=True, nopass=True, commands=["+@all"], keys=["*"], channels=["*"])
    assert r.get("other:0") == b"1"


def test_denied_command_is_logged_with_the_client_info(r: redis.Redis):
    r.acl_setuser("limited", enabled=True, reset=True, nopass=True, commands=["+get", "+auth"], keys=["cache:*"])
    limited = fakeredis.FakeRedis(server=r.connection_pool.connection_kwargs["server"])
    limited.auth("", username="limited")
    with pytest.raises(redis.exceptions.NoPermissionError):
        limited.set("cache:0", 1)
    with pytest.raises(redis.exceptions.NoPermissionError):
        limited.get("other:0")

    log = r.acl_log()
    assert [record["reason"] for record in log] == ["key", "command"]
    for record in log:
        assert record["username"] == "limited"
        assert record["client-info"]["user"] == "limited"
        assert "resp" in record["client-info"]


@pytest.fixture
def script_clients(r: redis.Redis) -> tuple[redis.Redis, redis.Redis]:
    # A user that may run scripts and GET/SET, only on keys matching cache:*.
    r.acl_setuser(
        "scripted",
        enabled=True,
        reset=True,
        nopass=True,
        commands=["+get", "+set", "+select", "+eval", "+evalsha", "+script"],
        keys=["cache:*"],
    )
    limited = fakeredis.FakeRedis(server=r.connection_pool.connection_kwargs["server"])
    limited.auth("", username="scripted")
    return r, limited


def test_script_allows_permitted_command_and_key(script_clients: tuple[redis.Redis, redis.Redis]):
    admin, limited = script_clients
    assert limited.eval("return redis.call('SET', KEYS[1], ARGV[1])", 1, "cache:1", "v") == b"OK"
    assert admin.get("cache:1") == b"v"
    assert limited.eval("return redis.call('GET', KEYS[1])", 1, "cache:1") == b"v"


def test_script_denies_command_forbidden_outside_the_script(
    script_clients: tuple[redis.Redis, redis.Redis],
):
    _, limited = script_clients
    with pytest.raises(redis.exceptions.NoPermissionError):
        limited.eval("return redis.call('HSET', KEYS[1], 'f', 'v')", 1, "cache:1")
    # The denied write must not have touched the database.
    assert limited.eval("return redis.call('GET', KEYS[1])", 1, "cache:1") is None


def test_script_denies_key_forbidden_outside_the_script(
    script_clients: tuple[redis.Redis, redis.Redis],
):
    _, limited = script_clients
    with pytest.raises(redis.exceptions.NoPermissionError):
        limited.eval("return redis.call('GET', KEYS[1])", 1, "secret:1")
    # A key built inside Lua is still checked, even though EVAL itself declares no keys.
    with pytest.raises(redis.exceptions.NoPermissionError):
        limited.eval("return redis.call('GET', 'secret:' .. ARGV[1])", 0, "1")


def test_pcall_captures_the_inner_acl_error(script_clients: tuple[redis.Redis, redis.Redis]):
    _, limited = script_clients
    # redis.pcall turns the NOPERM into an error table instead of aborting the script.
    captured = limited.eval(
        "local reply = redis.pcall('HSET', KEYS[1], 'f', 'v') "
        "if type(reply) == 'table' then return reply['err'] else return 'unexpected' end",
        1,
        "cache:1",
    )
    assert captured.startswith(b"NOPERM")
    captured_key = limited.eval(
        "local reply = redis.pcall('GET', KEYS[1]) "
        "if type(reply) == 'table' then return reply['err'] else return reply end",
        1,
        "secret:1",
    )
    assert captured_key == b"NOPERM No permissions to access a key"
    # Allowed operations through pcall still return their normal reply.
    assert (
        limited.eval(
            "local reply = redis.pcall('SET', KEYS[1], ARGV[1]); return reply['ok']",
            1,
            "cache:2",
            "v",
        )
        == b"OK"
    )


def test_failed_script_keeps_the_operations_it_already_ran(
    script_clients: tuple[redis.Redis, redis.Redis],
):
    admin, limited = script_clients
    with pytest.raises(redis.exceptions.NoPermissionError):
        limited.eval(
            "redis.call('SET', KEYS[1], 'one'); redis.call('HSET', KEYS[2], 'f', 'v'); return 'done'",
            2,
            "cache:a",
            "cache:b",
        )
    # Redis does not roll back the commands that succeeded before the error.
    assert admin.get("cache:a") == b"one"
    assert admin.exists("cache:b") == 0


def test_script_loaded_by_admin_runs_with_the_callers_permissions(
    script_clients: tuple[redis.Redis, redis.Redis],
):
    admin, limited = script_clients
    sha = admin.script_load("return redis.call('HSET', KEYS[1], 'f', 'v')")
    # The admin's privileges must not travel with the cached script.
    with pytest.raises(redis.exceptions.NoPermissionError):
        limited.evalsha(sha, 1, "cache:1")
    assert admin.exists("cache:1") == 0

    readable = admin.script_load("return redis.call('GET', KEYS[1])")
    admin.set("cache:read", "ok")
    assert limited.evalsha(readable, 1, "cache:read") == b"ok"
    with pytest.raises(redis.exceptions.NoPermissionError):
        limited.evalsha(readable, 1, "secret:read")


def test_inner_script_denials_are_logged_in_lua_context(
    script_clients: tuple[redis.Redis, redis.Redis],
):
    admin, limited = script_clients
    admin.acl_log_reset()
    with pytest.raises(redis.exceptions.NoPermissionError):
        limited.eval("return redis.call('HSET', KEYS[1], 'f', 'v')", 1, "cache:1")
    with pytest.raises(redis.exceptions.NoPermissionError):
        limited.eval("return redis.call('GET', KEYS[1])", 1, "secret:1")
    log = admin.acl_log()
    assert {(record["context"], record["reason"]) for record in log} == {
        ("lua", "command"),
        ("lua", "key"),
    }
    assert all(record["username"] == "scripted" for record in log)


def test_toplevel_eval_does_not_check_script_keys_against_numkeys(
    script_clients: tuple[redis.Redis, redis.Redis],
):
    # EVAL's static key indices point at numkeys; its real keys are enforced inside the script instead.
    _, limited = script_clients
    assert limited.eval("return redis.call('SET', KEYS[1], ARGV[1])", 1, "cache:num", "v") == b"OK"
    assert limited.eval("return 1", 0) == 1
