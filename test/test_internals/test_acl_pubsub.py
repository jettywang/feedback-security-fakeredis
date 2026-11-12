"""ACL channel-permission rules for Pub/Sub, pinned to the Redis 7+ behavior fakeredis emulates.

Where the checks happen:
- `SUBSCRIBE` / `PSUBSCRIBE`: every channel/pattern argument is checked against the user's `&` channel
  patterns when the command runs; if any argument is not covered, the whole command fails with NOPERM and
  no subscription is created.
- `PUBLISH`: the channel (and only the channel, not the payload) is checked when publishing.
- Keyspace notifications: the server generates them without any ACL check; the only gate is the
  subscribe-time check on the `__keyspace@<db>__:` / `__keyevent@<db>__:` channels.
- Updating a user's ACL does not touch existing subscriptions: they keep receiving messages, and the new
  rules only apply to subsequent commands. Unsubscribing is never channel-gated.
"""

import pytest
import redis

import fakeredis

pytestmark = [pytest.mark.fake]

# The audit account may use `audit:*` channels (with `audit:internal:*` granted again by a narrower,
# overlapping pattern) plus the keyspace-notification channels of `audit*` keys on db 2. Everything else -
# `secret:*`, the keyspace channels of other keys, `__keyevent@2__:*` - is denied.
AUDIT_CHANNELS = ["audit:*", "audit:internal:*", "__keyspace@2__:audit*"]
CHANNEL_NOPERM = "No permissions to access a channel"


@pytest.fixture
def server() -> fakeredis.FakeServer:
    return fakeredis.FakeServer(version=(8,))


@pytest.fixture
def admin(server: fakeredis.FakeServer) -> redis.Redis:
    client = fakeredis.FakeRedis(server=server, db=2)
    client.acl_setuser(
        "audit",
        enabled=True,
        reset=True,
        passwords=["+audit-pass"],
        commands=["+@all"],
        keys=["*"],
        channels=AUDIT_CHANNELS,
    )
    return client


def audit_client(server: fakeredis.FakeServer) -> redis.Redis:
    return fakeredis.FakeRedis(server=server, username="audit", password="audit-pass", db=2)


def get_messages(pubsub: redis.client.PubSub, timeout: float = 0.2) -> list[dict]:
    messages = []
    while True:
        message = pubsub.get_message(timeout=timeout)
        if message is None:
            return messages
        messages.append(message)
        timeout = 0.05


def test_on_connect_authentication(server: fakeredis.FakeServer, admin: redis.Redis):
    audit = audit_client(server)
    assert audit.acl_whoami() == "audit"

    with pytest.raises(redis.exceptions.NoPermissionError, match="Authentication failed"):
        fakeredis.FakeRedis(server=server, username="audit", password="wrong-pass", db=2).ping()


def test_subscribe_checks_every_channel_argument(server: fakeredis.FakeServer, admin: redis.Redis):
    audit = audit_client(server)
    pubsub = audit.pubsub()

    # One denied channel in the list fails the whole command: nothing gets subscribed.
    pubsub.subscribe("audit:events", "secret:events")
    with pytest.raises(redis.exceptions.NoPermissionError, match=CHANNEL_NOPERM):
        pubsub.get_message(timeout=0.5)
    assert server.subscribers == {}

    # A denied channel on its own is refused the same way.
    pubsub.subscribe("secret:events")
    with pytest.raises(redis.exceptions.NoPermissionError, match=CHANNEL_NOPERM):
        pubsub.get_message(timeout=0.5)
    assert server.subscribers == {}

    # Both refusals were logged, merged into a single repeated entry.
    (entry,) = admin.acl_log()
    assert entry["reason"] == "channel"
    assert entry["object"] == "secret:events"
    assert entry["username"] == "audit"
    assert entry["count"] == "2"

    # Channels covered by the granted patterns (including the overlapping narrower one) subscribe fine.
    pubsub.subscribe("audit:events", "audit:internal:ops")
    messages = get_messages(pubsub)
    assert [message["type"] for message in messages] == ["subscribe", "subscribe"]
    assert {message["channel"] for message in messages} == {b"audit:events", b"audit:internal:ops"}
    assert set(server.subscribers) == {b"audit:events", b"audit:internal:ops"}


def test_psubscribe_checks_every_pattern_argument(server: fakeredis.FakeServer, admin: redis.Redis):
    audit = audit_client(server)
    pubsub = audit.pubsub()

    # A pattern covered by a granted channel pattern is accepted...
    pubsub.psubscribe("audit:*")
    assert pubsub.get_message(timeout=0.5)["type"] == "psubscribe"
    # ...including a narrower pattern inside the granted one.
    pubsub.psubscribe("audit:internal:*")
    assert pubsub.get_message(timeout=0.5)["type"] == "psubscribe"

    # A pattern broader than every granted pattern is refused.
    pubsub.psubscribe("*")
    with pytest.raises(redis.exceptions.NoPermissionError, match=CHANNEL_NOPERM):
        pubsub.get_message(timeout=0.5)

    # A mixed list fails as a whole: the allowed pattern is not subscribed either.
    pubsub.psubscribe("audit:events:*", "secret:*")
    with pytest.raises(redis.exceptions.NoPermissionError, match=CHANNEL_NOPERM):
        pubsub.get_message(timeout=0.5)

    assert set(server.psubscribers) == {b"audit:*", b"audit:internal:*"}
    assert {(entry["reason"], entry["object"]) for entry in admin.acl_log()} == {
        ("channel", "*"),
        ("channel", "secret:*"),
    }


def test_publish_checks_the_channel_when_publishing(server: fakeredis.FakeServer, admin: redis.Redis):
    listener = admin.pubsub()  # the default user may subscribe to anything
    listener.subscribe("audit:events", "secret:events")
    assert len(get_messages(listener)) == 2

    audit = audit_client(server)
    assert audit.publish("audit:events", "hello") == 1
    # The payload is not a channel: it is never checked against channel patterns.
    assert audit.publish("audit:events", "secret:shaped-payload") == 1

    with pytest.raises(redis.exceptions.NoPermissionError, match=CHANNEL_NOPERM):
        audit.publish("secret:events", "hello")

    messages = get_messages(listener)
    assert [(message["channel"], message["data"]) for message in messages] == [
        (b"audit:events", b"hello"),
        (b"audit:events", b"secret:shaped-payload"),
    ]
    (entry,) = admin.acl_log()
    assert entry["reason"] == "channel"
    assert entry["object"] == "secret:events"


def test_keyspace_notifications_are_gated_only_at_subscribe_time(
    server: fakeredis.FakeServer, admin: redis.Redis
):
    admin.config_set("notify-keyspace-events", "KEA")
    audit = audit_client(server)
    pubsub = audit.pubsub()

    # The granted keyspace pattern subscribes fine...
    pubsub.psubscribe("__keyspace@2__:audit*")
    assert pubsub.get_message(timeout=0.5)["type"] == "psubscribe"

    # ...but keyspace channels of other keys, and keyevent channels, are not granted.
    pubsub.psubscribe("__keyspace@2__:secret*")
    with pytest.raises(redis.exceptions.NoPermissionError, match=CHANNEL_NOPERM):
        pubsub.get_message(timeout=0.5)
    pubsub.subscribe("__keyevent@2__:set")
    with pytest.raises(redis.exceptions.NoPermissionError, match=CHANNEL_NOPERM):
        pubsub.get_message(timeout=0.5)

    # Writes by any user (here the default user) make the server generate notifications with no ACL check
    # on the publishing side; the subscriber only sees the channels it was allowed to subscribe to.
    admin.set("audit:events", "1")
    admin.set("secret:events", "1")
    messages = get_messages(pubsub)
    assert [(message["pattern"], message["channel"], message["data"]) for message in messages] == [
        (b"__keyspace@2__:audit*", b"__keyspace@2__:audit:events", b"set")
    ]


def test_updating_acl_keeps_existing_subscriptions(server: fakeredis.FakeServer, admin: redis.Redis):
    admin.config_set("notify-keyspace-events", "KEA")
    audit = audit_client(server)
    pubsub = audit.pubsub()
    pubsub.subscribe("audit:events")
    pubsub.psubscribe("audit:*")
    pubsub.psubscribe("__keyspace@2__:audit*")
    assert [message["type"] for message in get_messages(pubsub)] == ["subscribe", "psubscribe", "psubscribe"]

    # Narrow the audit account to `other:*` channels only.
    admin.acl_setuser("audit", enabled=True, reset_channels=True, channels=["other:*"])

    # New subscriptions and publishes are checked against the new rules...
    late = audit.pubsub()
    late.subscribe("audit:events")
    with pytest.raises(redis.exceptions.NoPermissionError, match=CHANNEL_NOPERM):
        late.get_message(timeout=0.5)
    with pytest.raises(redis.exceptions.NoPermissionError, match=CHANNEL_NOPERM):
        audit.publish("audit:events", "denied-now")

    # ...but the subscriptions made before the change keep receiving messages, from normal publishes and
    # from server-generated notifications alike.
    admin.publish("audit:events", "still-delivered")
    admin.set("audit:events", "2")
    received = [(message["type"], message["channel"], message["data"]) for message in get_messages(pubsub)]
    assert ("message", b"audit:events", b"still-delivered") in received
    assert ("pmessage", b"audit:events", b"still-delivered") in received
    assert ("pmessage", b"__keyspace@2__:audit:events", b"set") in received

    # Unsubscribing is not channel-gated: the client can always drop a subscription, and the server
    # confirms it with an unsubscribe message.
    pubsub.unsubscribe("audit:events")
    message = pubsub.get_message(timeout=0.5)
    assert message["type"] == "unsubscribe"
    assert message["channel"] == b"audit:events"

    # The two denials were logged as one repeated entry.
    (entry,) = admin.acl_log()
    assert entry["reason"] == "channel"
    assert entry["object"] == "audit:events"
    assert entry["count"] == "2"
