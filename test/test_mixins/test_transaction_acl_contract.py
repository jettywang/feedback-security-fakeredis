"""Redis version contract for transactions (MULTI/EXEC/WATCH/DISCARD) meeting ACLs.

The scenarios here pin down the two points in time at which a command's permissions matter:

* queue time, inside MULTI: a refusal (NOPERM, bad arity, an unknown command) taints the
  transaction and the later EXEC is discarded wholesale with EXECABORT;
* execution time, inside EXEC: redis runs the queued commands through ``call()`` and never
  re-runs the ACL check, so a permission revoked *after* a command queued successfully does
  not stop it.

They also pin the WATCH-abort and DISCARD contracts and check that a connection starts the
next transaction without the old queue or WATCH state hanging around.
"""

import pytest
import redis
import valkey

from test import testtools
from test.testtools import raw_command

pytestmark = [
    pytest.mark.supported_server_versions(min_redis_ver="7", min_valkey_ver="9"),
    testtools.run_test_if_redispy_ver("gte", "5"),
    pytest.mark.unsupported_server_types("dragonfly"),
]

USERNAME = "txn-acl-user"
# Everything the user needs to drive a transaction and nothing else.
USER_COMMANDS = [
    "+set",
    "+get",
    "+multi",
    "+exec",
    "+discard",
    "+watch",
    "+unwatch",
    "+select",
    "+ping",
    "+incr",
]
USER_KEYS = ["allowed:*", "blocked:*"]

NoPermission = (redis.exceptions.NoPermissionError, valkey.exceptions.NoPermissionError)
ExecAbort = (redis.exceptions.ExecAbortError, valkey.exceptions.ExecAbortError)
WatchFailure = (redis.WatchError, valkey.WatchError)
ResponseFailure = (redis.ResponseError, valkey.ResponseError)


@pytest.fixture
def acl_connections(r, create_connection, request):
    """An admin connection and the same connection logged in as a restricted user."""
    admin = create_connection(db=2)
    admin.acl_deluser(USERNAME)
    admin.acl_setuser(
        USERNAME,
        enabled=True,
        reset=True,
        nopass=True,
        commands=USER_COMMANDS,
        keys=USER_KEYS,
    )

    def teardown():
        r.auth("", username="default")
        admin.acl_deluser(USERNAME)
        admin.close()

    request.addfinalizer(teardown)
    r.auth(password="", username=USERNAME)
    return admin, r


def test_permission_revoked_after_queueing_still_executes(acl_connections):
    # The headline scenario: both writes queue while the user may touch both keys, then the
    # admin revokes the pattern for one of them before EXEC. redis authorises at queue time
    # only, so the EXEC still runs both writes and returns one reply per queued command.
    admin, user = acl_connections
    assert raw_command(user, "multi") == b"OK"
    assert raw_command(user, "set", "allowed:1", "a") == b"QUEUED"
    assert raw_command(user, "set", "blocked:1", "b") == b"QUEUED"

    admin.acl_setuser(USERNAME, enabled=True, reset_keys=True, keys=["allowed:*"])

    assert raw_command(user, "exec") == [b"OK", b"OK"]
    assert admin.get("allowed:1") == b"a"
    assert admin.get("blocked:1") == b"b"


def test_command_permission_revoked_after_queueing_still_executes(acl_connections):
    # Same contract on the command (rather than key-pattern) axis: dropping +SET between the
    # queue and the EXEC does not retroactively remove a permission the user held at queue time.
    admin, user = acl_connections
    raw_command(user, "multi")
    assert raw_command(user, "set", "allowed:1", "a") == b"QUEUED"

    admin.acl_setuser(USERNAME, enabled=True, commands=["-set"])

    assert raw_command(user, "exec") == [b"OK"]
    assert admin.get("allowed:1") == b"a"


def test_queue_time_key_noperm_discards_the_whole_transaction(acl_connections):
    # At queue time the key check is live: a refused command taints the transaction and the
    # EXEC never runs, so even the previously queued, permitted write is not applied.
    admin, user = acl_connections
    admin.acl_setuser(USERNAME, enabled=True, reset_keys=True, keys=["allowed:*"])

    raw_command(user, "multi")
    assert raw_command(user, "set", "allowed:1", "a") == b"QUEUED"
    with pytest.raises(Exception) as ctx:
        raw_command(user, "set", "blocked:1", "b")
    assert isinstance(ctx.value, NoPermission)
    assert str(ctx.value) == "No permissions to access a key"
    assert raw_command(user, "set", "allowed:2", "c") == b"QUEUED"

    with pytest.raises(Exception) as ctx:
        raw_command(user, "exec")
    assert isinstance(ctx.value, ExecAbort)
    assert admin.get("allowed:1") is None
    assert admin.get("allowed:2") is None
    assert admin.get("blocked:1") is None


def test_queue_time_command_noperm_discards_the_whole_transaction(acl_connections):
    admin, user = acl_connections
    admin.acl_setuser(USERNAME, enabled=True, commands=["-incr"])

    raw_command(user, "multi")
    assert raw_command(user, "set", "allowed:1", "a") == b"QUEUED"
    with pytest.raises(Exception) as ctx:
        raw_command(user, "incr", "allowed:1")
    assert isinstance(ctx.value, NoPermission)
    assert "has no permissions to run the 'incr' command" in str(ctx.value)

    with pytest.raises(Exception) as ctx:
        raw_command(user, "exec")
    assert isinstance(ctx.value, ExecAbort)
    assert admin.get("allowed:1") is None


def test_queue_syntax_error_aborts_and_the_next_transaction_is_clean(acl_connections):
    admin, user = acl_connections
    raw_command(user, "multi")
    assert raw_command(user, "set", "allowed:1", "a") == b"QUEUED"
    with pytest.raises(Exception) as ctx:
        raw_command(user, "set")  # wrong arity, rejected while queueing
    assert isinstance(ctx.value, ResponseFailure)

    with pytest.raises(Exception) as ctx:
        raw_command(user, "exec")
    assert isinstance(ctx.value, ExecAbort)
    assert admin.get("allowed:1") is None

    # The failed transaction left no queue behind: a fresh transaction works normally.
    raw_command(user, "multi")
    assert raw_command(user, "set", "allowed:2", "c") == b"QUEUED"
    assert raw_command(user, "exec") == [b"OK"]
    assert admin.get("allowed:2") == b"c"


def test_unknown_command_while_queueing_aborts_the_transaction(acl_connections):
    admin, user = acl_connections
    raw_command(user, "multi")
    assert raw_command(user, "set", "allowed:1", "a") == b"QUEUED"
    with pytest.raises(Exception) as ctx:
        raw_command(user, "nosuchcommand")
    assert isinstance(ctx.value, ResponseFailure)
    assert "unknown command" in str(ctx.value)

    with pytest.raises(Exception) as ctx:
        raw_command(user, "exec")
    assert isinstance(ctx.value, ExecAbort)
    assert admin.get("allowed:1") is None


def test_per_item_runtime_error_leaves_the_other_commands_intact(r):
    # Contrast with EXECABORT: a command that queues fine but fails while running is reported
    # as one error element in the EXEC array, and the rest of the batch still applies.
    r.set("string-key", "not-a-number")
    pipe = r.pipeline()
    pipe.multi()
    pipe.set("ok:1", "a")
    pipe.incr("string-key")  # WRONGTYPE at execution time, not queue time
    pipe.set("ok:2", "b")
    replies = pipe.execute(raise_on_error=False)

    assert len(replies) == 3
    assert replies[0] is True
    assert isinstance(replies[1], ResponseFailure)
    assert replies[2] is True
    assert r.get("ok:1") == b"a"
    assert r.get("ok:2") == b"b"


def test_watch_failure_returns_nil_and_writes_nothing(acl_connections):
    admin, user = acl_connections
    pipe = user.pipeline()
    pipe.watch("allowed:w")
    admin.set("allowed:w", "changed-elsewhere")  # another connection touches the watched key
    pipe.multi()
    pipe.set("allowed:1", "a")

    # redis-py turns the server's nil EXEC reply into a WatchError.
    with pytest.raises(Exception) as ctx:
        pipe.execute()
    assert isinstance(ctx.value, WatchFailure)
    assert admin.get("allowed:1") is None
    pipe.reset()

    # The watch was consumed by the aborted EXEC: changing the same key now must not break a
    # brand new transaction on this connection.
    admin.set("allowed:w", "changed-again")
    next_pipe = user.pipeline()
    next_pipe.multi()
    next_pipe.set("allowed:2", "b")
    assert next_pipe.execute() == [True]
    assert admin.get("allowed:2") == b"b"


def test_watch_inside_multi_is_rejected_but_leaves_the_queue_intact(acl_connections):
    admin, user = acl_connections
    raw_command(user, "multi")
    assert raw_command(user, "set", "allowed:1", "a") == b"QUEUED"
    with pytest.raises(Exception) as ctx:
        raw_command(user, "watch", "allowed:w")
    assert isinstance(ctx.value, ResponseFailure)
    assert "WATCH inside MULTI is not allowed" in str(ctx.value)

    # WATCH carries the transaction flag, so it runs immediately rather than being queued: its
    # error does not taint the transaction, and the queued SET still executes.
    assert raw_command(user, "exec") == [b"OK"]
    assert admin.get("allowed:1") == b"a"


def test_discard_clears_the_queue_and_the_watches(acl_connections):
    admin, user = acl_connections
    raw_command(user, "watch", "allowed:w")
    raw_command(user, "multi")
    assert raw_command(user, "set", "allowed:1", "a") == b"QUEUED"
    assert raw_command(user, "discard") == b"OK"
    assert admin.get("allowed:1") is None

    # DISCARD dropped the watch too, so this external change cannot abort the next transaction.
    admin.set("allowed:w", "changed")
    raw_command(user, "multi")
    assert raw_command(user, "set", "allowed:2", "b") == b"QUEUED"
    assert raw_command(user, "exec") == [b"OK"]
    assert admin.get("allowed:2") == b"b"


def test_exec_and_discard_without_multi_report_errors_and_keep_working(r):
    with pytest.raises(Exception) as ctx:
        raw_command(r, "exec")
    assert isinstance(ctx.value, ResponseFailure)
    assert "EXEC without MULTI" in str(ctx.value)
    with pytest.raises(Exception) as ctx:
        raw_command(r, "discard")
    assert isinstance(ctx.value, ResponseFailure)
    assert "DISCARD without MULTI" in str(ctx.value)

    # The error replies did not leave the connection in transaction state.
    raw_command(r, "multi")
    assert raw_command(r, "set", "standalone:1", "x") == b"QUEUED"
    assert raw_command(r, "exec") == [b"OK"]
    assert r.get("standalone:1") == b"x"


def test_successful_exec_leaves_no_queued_state(acl_connections):
    admin, user = acl_connections
    raw_command(user, "multi")
    assert raw_command(user, "set", "allowed:1", "a") == b"QUEUED"
    assert raw_command(user, "exec") == [b"OK"]

    # The next command runs immediately rather than being queued.
    assert user.ping() is True
    with pytest.raises(Exception) as ctx:
        raw_command(user, "exec")
    assert isinstance(ctx.value, ResponseFailure)
    assert "EXEC without MULTI" in str(ctx.value)


def test_empty_multi_exec_returns_empty_array(r):
    raw_command(r, "multi")
    assert raw_command(r, "exec") == []


def test_disabled_user_is_reported_with_noperm_prefix(acl_connections):
    admin, user = acl_connections
    raw_command(user, "multi")
    assert raw_command(user, "set", "allowed:1", "a") == b"QUEUED"
    admin.acl_setuser(USERNAME, enabled=False)

    # The top-level EXEC itself now fails the ACL check, so the queue never runs. Real redis
    # answers with the NOPERM-prefixed "User disabled" error.
    with pytest.raises(Exception) as ctx:
        raw_command(user, "exec")
    assert isinstance(ctx.value, NoPermission)
    assert str(ctx.value) == "User disabled"
    assert admin.get("allowed:1") is None
