"""What connections see when an admin disables, deletes and re-creates an ACL user.

Modeled contract: Redis 7.x/8.x (fakeredis' default ``FakeServer(version=(8,))``; these semantics
are unchanged since Redis 6.2 and match Valkey):

- ``ACL SETUSER <user> off`` blocks only NEW authentications: ``AUTH`` and ``HELLO ... AUTH`` fail
  with WRONGPASS, while connections that are already authenticated keep their permissions.
- ``ACL DELUSER <user>`` deletes the user AND terminates every connection authenticated as it.
- Re-creating the same-named user starts a fresh user: previously terminated connections stay
  terminated (reconnecting clients come back as ``default``), and new connections authenticate
  with the new credentials only.
- Authentication state is per connection: one client logging in never changes another client's
  user, and a failed login never creates the user in the ACL.
"""

import pytest
import redis

import fakeredis
from fakeredis._helpers import asbytes

pytestmark = [pytest.mark.fake]

USERNAME = "lifecycle-user"
PASSWORD = "initial-pass"
NEW_PASSWORD = "rotated-pass"
GHOST = "ghost-user"


@pytest.fixture
def server():
    return fakeredis.FakeServer(version=(8,))


@pytest.fixture
def admin(server):
    """The connection the backend administrator uses to manage ACL users."""
    client = fakeredis.FakeRedis(server=server)
    client.acl_setuser(
        USERNAME,
        enabled=True,
        reset=True,
        passwords=[f"+{PASSWORD}"],
        commands=["+@all"],
        keys=["*"],
        channels=["*"],
    )
    return client


def _auth_client(server, password=PASSWORD):
    """New connection that logs in with the AUTH command (RESP2 handshake)."""
    return fakeredis.FakeRedis(server=server, username=USERNAME, password=password)


def _hello_client(server, password=PASSWORD):
    """New connection that logs in through HELLO AUTH (RESP3 handshake)."""
    return fakeredis.FakeRedis(server=server, username=USERNAME, password=password, protocol=3)


def test_setuser_off_blocks_new_logins_but_keeps_existing_connections(server, admin):
    # t1: two connections authenticate as the user, one via AUTH, one via HELLO AUTH.
    victim_auth = fakeredis.FakeRedis(server=server)
    victim_auth.auth(PASSWORD, username=USERNAME)
    victim_hello = fakeredis.FakeRedis(server=server, protocol=3)
    victim_hello.execute_command("HELLO", 3, "AUTH", USERNAME, PASSWORD)
    bystander = fakeredis.FakeRedis(server=server)

    # Login state is per connection: the victims' logins did not leak onto other clients.
    assert asbytes(victim_auth.acl_whoami()) == asbytes(USERNAME)
    assert asbytes(victim_hello.acl_whoami()) == asbytes(USERNAME)
    assert asbytes(bystander.acl_whoami()) == b"default"
    assert asbytes(admin.acl_whoami()) == b"default"

    victim_auth.set("key", "from-auth")
    victim_hello.set("key", "from-hello")

    # t2: the admin disables the account.
    assert admin.acl_setuser(USERNAME, enabled=False)

    # Existing connections keep working: off only blocks new authentications.
    assert victim_auth.get("key") == b"from-hello"
    assert victim_hello.get("key") == b"from-hello"
    assert asbytes(victim_auth.acl_whoami()) == asbytes(USERNAME)
    assert asbytes(victim_hello.acl_whoami()) == asbytes(USERNAME)

    # New connections cannot authenticate, through neither AUTH nor HELLO AUTH.
    with pytest.raises(redis.exceptions.AuthenticationError):
        _auth_client(server).ping()
    with pytest.raises(redis.exceptions.AuthenticationError):
        _hello_client(server).ping()

    # The unrelated user is unaffected the whole time.
    assert bystander.ping()
    assert asbytes(bystander.acl_whoami()) == b"default"

    # t3: re-enabling the account lets new connections authenticate again.
    assert admin.acl_setuser(USERNAME, enabled=True)
    assert asbytes(_auth_client(server).acl_whoami()) == asbytes(USERNAME)
    assert asbytes(_hello_client(server).acl_whoami()) == asbytes(USERNAME)


def test_failed_logins_are_per_connection_and_never_create_the_user(server, admin):
    existing = fakeredis.FakeRedis(server=server)
    with pytest.raises(redis.exceptions.AuthenticationError):
        existing.auth("wrong-password", username=GHOST)
    with pytest.raises(redis.exceptions.AuthenticationError):
        existing.execute_command("HELLO", 3, "AUTH", GHOST, "wrong-password")
    # A failed login leaves the connection as it was and does not resurrect/create the user.
    assert asbytes(existing.acl_whoami()) == b"default"
    assert GHOST not in admin.acl_users()
    assert admin.acl_getuser("no-such-user") is None
    # Failed authentications are recorded in the ACL log.
    assert any(record["username"] == GHOST and record["reason"] == "auth" for record in admin.acl_log())


def test_deluser_terminates_authenticated_connections(server, admin):
    victim_auth = fakeredis.FakeRedis(server=server)
    victim_auth.auth(PASSWORD, username=USERNAME)
    victim_hello = _hello_client(server)
    victim_hello.ping()  # connect: the RESP3 handshake runs HELLO AUTH
    bystander = fakeredis.FakeRedis(server=server)
    bystander_id = bystander.client_id()
    victim_auth_id = victim_auth.client_id()
    assert asbytes(victim_auth.acl_whoami()) == asbytes(USERNAME)
    assert asbytes(victim_hello.acl_whoami()) == asbytes(USERNAME)

    # t2: the admin deletes the account.
    assert admin.acl_deluser(USERNAME) == 1
    assert admin.acl_deluser(USERNAME) == 0  # already gone
    assert USERNAME not in admin.acl_users()
    assert admin.acl_getuser(USERNAME) is None

    # Both connections authenticated as the deleted user are terminated.
    with pytest.raises(redis.exceptions.ConnectionError):
        victim_auth.ping()
    with pytest.raises(redis.exceptions.ConnectionError):
        victim_hello.ping()

    # The unrelated user keeps its connection.
    assert bystander.ping()
    assert bystander.client_id() == bystander_id

    # A client without stored credentials reconnects as default and must re-authenticate.
    assert asbytes(victim_auth.acl_whoami()) == b"default"
    assert victim_auth.client_id() != victim_auth_id
    with pytest.raises(redis.exceptions.AuthenticationError):
        victim_auth.auth(PASSWORD, username=USERNAME)
    # Clients with stored credentials cannot even complete the handshake anymore.
    with pytest.raises(redis.exceptions.AuthenticationError):
        _auth_client(server).ping()
    with pytest.raises(redis.exceptions.AuthenticationError):
        _hello_client(server).ping()
    # Failed logins did not resurrect the deleted user.
    assert USERNAME not in admin.acl_users()

    # The default user cannot be deleted.
    with pytest.raises(redis.exceptions.ResponseError, match="The 'default' user cannot be removed"):
        admin.acl_deluser("default")


def test_recreating_a_deleted_user_starts_fresh(server, admin):
    victim = fakeredis.FakeRedis(server=server)
    victim.auth(PASSWORD, username=USERNAME)
    assert admin.acl_deluser(USERNAME) == 1
    with pytest.raises(redis.exceptions.ConnectionError):
        victim.ping()

    # t3: the admin re-creates a user with the same name but a rotated password.
    admin.acl_setuser(
        USERNAME,
        enabled=True,
        reset=True,
        passwords=[f"+{NEW_PASSWORD}"],
        commands=["+@all"],
        keys=["*"],
        channels=["*"],
    )

    # The old password is gone with the old user, via AUTH and via HELLO AUTH.
    with pytest.raises(redis.exceptions.AuthenticationError):
        _auth_client(server).ping()
    with pytest.raises(redis.exceptions.AuthenticationError):
        _hello_client(server).ping()

    # New connections authenticate with the new password, through both login paths.
    assert asbytes(_auth_client(server, NEW_PASSWORD).acl_whoami()) == asbytes(USERNAME)
    assert asbytes(_hello_client(server, NEW_PASSWORD).acl_whoami()) == asbytes(USERNAME)

    # The terminated connection came back as default and can re-authenticate with the new password.
    assert asbytes(victim.acl_whoami()) == b"default"
    victim.auth(NEW_PASSWORD, username=USERNAME)
    assert asbytes(victim.acl_whoami()) == asbytes(USERNAME)


def test_auth_with_requirepass_respects_disabled_default_user(server, admin):
    r = fakeredis.FakeRedis(server=server)
    r.config_set("requirepass", "temp_pass")
    assert r.auth("temp_pass", "default") is True

    admin.acl_setuser("default", enabled=False)
    # The already-connected client keeps working; only new authentications are blocked.
    assert r.ping()
    with pytest.raises(redis.exceptions.AuthenticationError):
        fakeredis.FakeRedis(server=server).auth("temp_pass", "default")

    admin.acl_setuser("default", enabled=True)
    assert fakeredis.FakeRedis(server=server).auth("temp_pass", "default") is True
    r.config_set("requirepass", "")
