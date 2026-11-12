from __future__ import annotations

import fnmatch
import hashlib
from typing import Any

from fakeredis import _msgs as msgs

from .._helpers import SimpleError, current_time
from ._client_info import ClientInfo
from ._command_info import get_command_info, get_commands_by_category

ALL_MODES = frozenset({ord("R"), ord("W")})


class Selector:
    def __init__(
        self,
        command_rules: list[bytes],
        key_patterns: list[tuple[frozenset[int], bytes]],
        channel_patterns: list[bytes],
    ) -> None:
        self.command_rules: list[bytes] = command_rules
        self.key_patterns: list[tuple[frozenset[int], bytes]] = key_patterns
        self.channel_patterns: list[bytes] = channel_patterns

    @property
    def command(self) -> bytes:
        for rule in self.command_rules:
            if not rule.startswith(b"@"):
                return rule[1:]
        return b""

    @property
    def allowed(self) -> bool:
        for rule in self.command_rules:
            if not rule.startswith(b"@"):
                return rule[0] == ord("+")
        return False

    @property
    def keys(self) -> bytes:
        return b" ".join(
            (b"%" + bytes(sorted(mode)) + b"~" + pattern if mode else b"~" + pattern)
            for mode, pattern in self.key_patterns
        )

    @property
    def channels(self) -> bytes:
        return b" ".join(b"&" + pattern for pattern in self.channel_patterns)

    def as_array(self) -> list[bytes]:
        return [
            b"+" if self.allowed else b"-",
            self.command,
            b"keys",
            self.keys,
            b"channels",
            self.channels,
        ]

    @classmethod
    def from_bytes(cls, data: bytes) -> Selector:
        command_rules: list[bytes] = []
        key_patterns: list[tuple[frozenset[int], bytes]] = []
        channel_patterns: list[bytes] = []
        for item in data.split(b" "):
            if not item or item == b"resetchannels":
                continue
            if item[0] == ord("&"):
                channel_patterns.append(item[1:])
            elif item[0] == ord("~"):
                key_patterns.append((ALL_MODES, item[1:]))
            elif item[0] == ord("%"):
                tilde = item.find(b"~")
                if tilde < 0:
                    continue
                key_patterns.append((frozenset(item[1:tilde]), item[tilde + 1 :]))
            elif item[0] in (ord("+"), ord("-")):
                command_rules.append(item)
        if b"-@all" not in command_rules:
            command_rules.insert(0, b"-@all")
        return cls(command_rules, key_patterns, channel_patterns)


class UserAccessControlList:
    def __init__(self, enabled: bool = True, nopass: bool = False):
        self._passwords: set[bytes] = set()
        self.enabled: bool = enabled
        self._nopass: bool = nopass
        self._key_patterns: list[tuple[frozenset[int], bytes]] = []
        self._channel_patterns: set[bytes] = set()
        self._commands: dict[bytes, bool] = {b"@all": False}
        self._selectors: list[Selector] = []

    def reset(self) -> None:
        self.enabled = False
        self._nopass = False
        self._commands = {b"@all": False}
        self._passwords.clear()
        self._key_patterns.clear()
        self._channel_patterns.clear()
        self._selectors.clear()

    @staticmethod
    def _get_command_info(fields: list[bytes]) -> list[Any] | None:
        return get_command_info(UserAccessControlList._command_name(fields))

    @staticmethod
    def _command_name(fields: list[bytes]) -> bytes:
        command = fields[0].lower()
        subcommand = command + b" " + fields[1].lower() if len(fields) > 1 else b""
        if subcommand and get_command_info(subcommand) is not None:
            return subcommand
        return command

    @staticmethod
    def _rule_name(rule: bytes) -> bytes:
        return rule.replace(b"|", b" ")

    @staticmethod
    def _required_mode(command_info: list[Any]) -> int | None:
        flags = command_info[2]
        if b"write" in flags:
            return ord("W")
        if b"readonly" in flags:
            return ord("R")
        return None

    @staticmethod
    def _patterns_allow(
        patterns: list[tuple[frozenset[int], bytes]],
        keys: list[bytes],
        required_mode: int | None,
    ) -> bool:
        for key in keys:
            if not any(
                (required_mode is None or required_mode in modes) and fnmatch.fnmatchcase(key, pattern)
                for modes, pattern in patterns
            ):
                return False
        return True

    def unrestricted(self) -> bool:
        """Whether no rule of this user can refuse a command: every command is granted and none is revoked, on every
        key and every channel. This is what the default user looks like, so it lets the per-command check skip the
        command lookup and the pattern matching.
        """
        return (
            self._commands.get(b"@all", False)
            and (ALL_MODES, b"*") in self._key_patterns
            and b"*" in self._channel_patterns
            and all(self._commands.values())
        )

    def command_allowed(self, command_info: list[Any] | None, fields: list[bytes]) -> bool:
        if fields[0].lower() == b"auth":
            return True
        if not command_info:
            return self._commands.get(fields[0].lower(), False) or self._commands.get(b"@all", False)
        return self._command_allowed_by_rules(command_info, self._command_name(fields), self._commands)

    def _get_keys(self, command_info: list[Any] | None, fields: list[bytes]) -> list[bytes]:
        if not command_info:
            return []
        from .._commands import Key, SUPPORTED_COMMANDS

        signature = SUPPORTED_COMMANDS.get(self._command_name(fields).decode())
        if signature is not None:
            subcommand_count = self._command_name(fields).count(b" ")
            types = list(signature.fixed)
            extra = len(fields) - 1 - len(types)
            if extra > 0 and signature.repeat:
                types.extend(signature.repeat[i % len(signature.repeat)] for i in range(extra))
            return [
                fields[index + 1 + subcommand_count]
                for index, type_ in enumerate(types)
                if isinstance(type_, Key)
            ]
        first_key, last_key, step = command_info[3:6]
        if first_key == 0:
            return []
        last_key = (last_key + 1) if last_key >= 0 else last_key
        step = step + 1
        return fields[first_key : last_key + 1 : step]

    def keys_not_allowed(self, command_info: list[Any] | None, fields: list[bytes]) -> list[bytes]:
        if len(self._key_patterns) == 0 or command_info is None:
            return []
        keys = self._get_keys(command_info, fields)
        required_mode = self._required_mode(command_info)
        return [key for key in keys if not self._patterns_allow(self._key_patterns, [key], required_mode)]

    def channels_not_allowed(self, command_info: list[Any] | None, fields: list[bytes]) -> list[bytes]:
        if len(self._channel_patterns) == 0:
            return []
        channels = fields[1:2]
        return [
            channel
            for channel in channels
            if not any(fnmatch.fnmatchcase(channel, pattern) for pattern in self._channel_patterns)
        ]

    def set_nopass(self) -> None:
        self._nopass = True
        self._passwords.clear()

    def check_password(self, password: bytes | None) -> bool:
        password_provided: bool = password is not None and password != b""
        if self._nopass:
            return not password_provided
        elif not password_provided or password is None:
            return False
        password_hex = hashlib.sha256(password).hexdigest().encode()
        return password_hex in self._passwords and self.enabled

    def add_password_hex(self, password_hex: bytes) -> None:
        self._nopass = False
        self._passwords.add(password_hex)

    def add_password(self, password: bytes) -> None:
        self._nopass = False
        password_hex = hashlib.sha256(password).hexdigest().encode()
        self.add_password_hex(password_hex)

    def remove_password_hex(self, password_hex: bytes) -> None:
        self._passwords.discard(password_hex)

    def remove_password(self, password: bytes) -> None:
        password_hex = hashlib.sha256(password).hexdigest().encode()
        self.remove_password_hex(password_hex)

    def add_command_or_category(self, selector: bytes) -> None:
        enabled, command = selector[0] == ord("+"), selector[1:]
        if command[0] == ord("@"):
            self._commands[command] = enabled
            category_commands = get_commands_by_category(command[1:])
            for command in category_commands:
                if command in self._commands:
                    del self._commands[command]
        else:
            self._commands[self._rule_name(command)] = enabled

    def add_key_pattern(self, key_pattern: bytes) -> None:
        if key_pattern[:1] == b"%":
            tilde = key_pattern.find(b"~")
            mode = frozenset(key_pattern[1:tilde]) if tilde > 0 else ALL_MODES
            pattern = key_pattern[tilde + 1 :] if tilde >= 0 else key_pattern
        else:
            mode = ALL_MODES
            pattern = key_pattern[1:] if key_pattern[:1] == b"~" else key_pattern
        entry = (mode, pattern)
        if entry not in self._key_patterns:
            self._key_patterns.append(entry)

    def reset_key_patterns(self) -> None:
        self._key_patterns.clear()

    def reset_channels_patterns(self) -> None:
        self._channel_patterns.clear()

    def add_channel_pattern(self, channel_pattern: bytes) -> None:
        self._channel_patterns.add(channel_pattern)

    def add_selector(self, selector: bytes) -> None:
        self._selectors.append(Selector.from_bytes(selector))

    def _selector_commands(self, selector: Selector) -> bytes:
        rules = list(selector.command_rules)
        if b"-@all" not in rules:
            rules.insert(0, b"-@all")
        return b" ".join(rules)

    def _get_selectors(self) -> list[list[bytes]]:
        return [
            [b"commands", self._selector_commands(selector), b"keys", selector.keys, b"channels", selector.channels]
            for selector in self._selectors
        ]

    def _get_commands(self) -> list[bytes]:
        res = []
        for command, enabled in self._commands.items():
            inc = b"+" if enabled else b"-"
            res.append(inc + command)
        return res

    def _get_key_patterns(self) -> list[bytes]:
        return [
            (b"%" + bytes(sorted(modes)) + b"~" + pattern if modes != ALL_MODES else b"~" + pattern)
            for modes, pattern in self._key_patterns
        ]

    def _get_channel_patterns(self) -> list[bytes]:
        return [b"&" + channel_pattern for channel_pattern in self._channel_patterns]

    def _get_flags(self) -> list[bytes]:
        flags: list[bytes] = []
        flags.append(b"on" if self.enabled else b"off")
        if self._nopass:
            flags.append(b"nopass")
        if (ALL_MODES, b"*") in self._key_patterns:
            flags.append(b"allkeys")
        if b"*" in self._channel_patterns:
            flags.append(b"allchannels")
        return flags

    def as_array(self) -> list[Any]:
        results: list[Any] = []
        results.extend(
            [
                b"flags",
                self._get_flags(),
                b"passwords",
                list(self._passwords),
                b"commands",
                b" ".join(self._get_commands()),
                b"keys",
                b" ".join(self._get_key_patterns()),
                b"channels",
                b" ".join(self._get_channel_patterns()),
                b"selectors",
                self._get_selectors(),
            ]
        )
        return results

    def _command_allowed_by_rules(
        self,
        command_info: list[Any],
        command_name: bytes,
        rules: dict[bytes, bool],
    ) -> bool:
        explicit = rules.get(command_name)
        if explicit is not None:
            return explicit
        if any(rules.get(category) is False for category in command_info[6]):
            return False
        return rules.get(b"@all", False) or any(
            rules.get(category, False) for category in command_info[6]
        )

    def _root_allows(self, command_info: list[Any], fields: list[bytes], keys: list[bytes]) -> bool:
        if not self.command_allowed(command_info, fields):
            return False
        if not self._patterns_allow(self._key_patterns, keys, self._required_mode(command_info)):
            return False
        return b"@pubsub" not in command_info[6] or not self.channels_not_allowed(command_info, fields)

    def _selector_rules(self, selector: Selector) -> dict[bytes, bool]:
        return {self._rule_name(rule[1:]): rule[0] == ord("+") for rule in selector.command_rules}

    def _selector_allows(
        self,
        selector: Selector,
        command_info: list[Any],
        fields: list[bytes],
        keys: list[bytes],
    ) -> bool:
        command_name = self._command_name(fields)
        rules = self._selector_rules(selector)
        if not self._command_allowed_by_rules(command_info, command_name, rules):
            return False
        required_mode = self._required_mode(command_info)
        if not self._patterns_allow(selector.key_patterns, keys, required_mode):
            return False
        if b"@pubsub" in command_info[6]:
            channels = fields[1:2]
            return all(
                any(fnmatch.fnmatchcase(channel, pattern) for pattern in selector.channel_patterns)
                for channel in channels
            )
        return True

    def _get_selectors_for_rule(self) -> list[bytes]:
        results: list[bytes] = []
        for selector in self._selectors:
            channels = b"resetchannels" + ((b" " + selector.channels) if selector.channels != b"" else b"")
            results.append(b"(" + b" ".join([selector.keys, channels, self._selector_commands(selector)]) + b")")
        return results

    def as_rule(self) -> bytes:
        selectors = self._get_selectors_for_rule()
        channels = self._get_channel_patterns()
        if channels != [b"&*"]:
            channels = [b"resetchannels"] + channels
        rule_parts: list[bytes] = (
            self._get_flags()
            + [b"#" + password for password in self._passwords]
            + self._get_commands()
            + self._get_key_patterns()
            + channels
            + selectors
        )
        return b" ".join(rule_parts)


class AclLogRecord:
    def __init__(
        self,
        count: int,
        reason: bytes,
        context: bytes,
        _object: bytes,
        username: bytes,
        created_ts: int,
        updated_ts: int,
        client_info: bytes,
        entry_id: int,
    ):
        self.count: int = count
        self.reason: bytes = reason  # command, key, channel, or auth
        self.context: bytes = context  # toplevel, multi, lua, or module
        self.object: bytes = _object  # resource user couldn't access. AUTH when the reason is auth
        self.username: bytes = username
        self.created_ts: int = created_ts  # milliseconds
        self.updated_ts: int = updated_ts
        self.client_info: bytes = client_info
        self.entry_id: int = entry_id

    def as_dict(self) -> dict[str, bytes]:
        age_seconds = (current_time() - self.created_ts) / 1000
        res: dict[str, bytes] = {
            "count": str(self.count).encode(),
            "reason": self.reason,
            "context": self.context,
            "object": self.object,
            "username": self.username,
            "age-seconds": f"{age_seconds:.3f}".encode(),
            "client-info": self.client_info,
            "entry-id": str(self.entry_id).encode(),
            "timestamp-created": str(self.created_ts).encode(),
            "timestamp-last-updated": str(self.updated_ts).encode(),
        }
        return res


class AccessControlList:
    def __init__(self) -> None:
        default_user_acl = UserAccessControlList(nopass=True)
        default_user_acl.add_key_pattern(b"*")
        default_user_acl.add_channel_pattern(b"*")
        default_user_acl.add_command_or_category(b"+@all")
        self._user_acl: dict[bytes, UserAccessControlList] = {b"default": default_user_acl}
        self._log: list[AclLogRecord] = []

    def get_users(self) -> list[bytes]:
        return list(self._user_acl.keys())

    def get_user_acl(self, username: bytes) -> UserAccessControlList:
        return self._user_acl.setdefault(username, UserAccessControlList())

    def as_rules(self) -> list[bytes]:
        res: list[bytes] = []
        for username, user_acl in self._user_acl.items():
            rule_str = b"user " + username + b" " + user_acl.as_rule()
            res.append(rule_str)
        return res

    def del_user(self, username: bytes) -> None:
        self._user_acl.pop(username, None)

    def reset_log(self) -> None:
        self._log.clear()

    def log(self, count: int) -> list[dict[str, bytes]]:
        if count > len(self._log) or count < 0:
            count = 0
        res = [x.as_dict() for x in self._log[-count:]]
        res.reverse()
        return res

    def add_log_record(
        self,
        reason: bytes,
        context: bytes,
        _object: bytes,
        username: bytes,
        client_info: bytes,
    ) -> None:
        if len(self._log) > 0:
            last_entry = self._log[-1]
            if (
                last_entry.reason == reason
                and last_entry.context == context
                and last_entry.object == _object
                and last_entry.username == username
            ):
                last_entry.count += 1
                last_entry.updated_ts = current_time()
                return
        entry = AclLogRecord(
            1, reason, context, _object, username, current_time(), current_time(), client_info, len(self._log) + 1
        )
        self._log.append(entry)

    def validate_command(self, username: bytes, client_info: ClientInfo, fields: list[bytes]) -> None:
        """Raise if `username` may not run the command in `fields`.

        `client_info` is only rendered when a denial is logged: doing it for every command costs more than the check.
        """
        if username not in self._user_acl:
            return
        if fields and fields[0].lower() == b"auth":
            # auth command is always allowed
            return
        user_acl = self._user_acl[username]
        if not user_acl.enabled:
            raise SimpleError("User disabled")
        if user_acl.unrestricted():
            return
        command_info = UserAccessControlList._get_command_info(fields)
        if command_info is None:
            return
        keys = user_acl._get_keys(command_info, fields)
        if user_acl._root_allows(command_info, fields, keys) or any(
            user_acl._selector_allows(selector, command_info, fields, keys)
            for selector in user_acl._selectors
        ):
            return
        command_name = user_acl._command_name(fields)
        if not user_acl.command_allowed(command_info, fields) and not any(
            user_acl._command_allowed_by_rules(
                command_info, command_name, user_acl._selector_rules(selector)
            )
            for selector in user_acl._selectors
        ):
            self.add_log_record(b"command", b"toplevel", fields[0], username, client_info.as_bytes())
            raise SimpleError(
                msgs.NO_PERMISSION_ERROR.format(username.decode(), fields[0].lower().decode())
            )
        if b"@pubsub" in command_info[6] and (
            not user_acl.command_allowed(command_info, fields)
            or user_acl.channels_not_allowed(command_info, fields)
        ):
            self.add_log_record(b"channel", b"toplevel", fields[1], username, client_info.as_bytes())
            raise SimpleError(msgs.NO_PERMISSION_CHANNEL_ERROR)
        keys_not_allowed = user_acl.keys_not_allowed(command_info, fields)
        denied_key = keys_not_allowed[0] if keys_not_allowed else (keys[0] if keys else b"")
        self.add_log_record(b"key", b"toplevel", denied_key, username, client_info.as_bytes())
        raise SimpleError(msgs.NO_PERMISSION_KEY_ERROR)
