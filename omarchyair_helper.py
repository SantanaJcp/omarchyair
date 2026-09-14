"""Privileged, narrowly-scoped network helper for Omarchy Air.

The network state and firewall policy below are intentionally kept as the
reviewed helper baseline. This module is imported only from the packaged
/usr/lib/omarchyair tree by the fixed wrapper.
"""

import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import sys

from omarchyair_runtime import (
    closed_environment,
    fixed_executable,
    open_directory,
    read_regular,
    run,
)


VERSION = "0.3.1"
API_VERSION = 1

STATE_ROOT = Path("/var/lib/omarchyair")
STATE_FILE = "network.json"
STATE_OWNER = 0
COMMENT = "omarchyair-managed"
STATE_LIMIT = 64 * 1024
LOCK_FILE = ".network.lock"

# These are deliberately the complete firewall surface of this helper.  Do
# not turn this into a port-range or arbitrary-command interface.
RAOP_PORT = "6001:6002"
MDNS_PORT = "5353"
_ALLOWED_PORTS = frozenset((RAOP_PORT, MDNS_PORT))
_AVAHI_UNITS = ("avahi-daemon.service", "avahi-daemon.socket")
_INTERFACE_RE = re.compile(r"(?!-)[A-Za-z0-9_.-]{1,15}\Z")


def _reject_json_constant(value):
    raise ValueError(f"Invalid JSON constant: {value}")


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _secure_file_stat(dir_fd, name, owner, *, missing_ok=False, file_fd=None):
    """Return a private, singly-linked regular entry below dir_fd.

    lstat-style lookup is intentional: a state file, lock, or temporary file
    must never be followed through a symlink.  The state directory is private,
    but these checks remain useful against accidental replacement and in
    isolated filesystem tests.
    """
    try:
        entry = (
            os.fstat(file_fd)
            if file_fd is not None
            else os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        )
    except FileNotFoundError:
        if missing_ok:
            return None
        raise
    if not stat.S_ISREG(entry.st_mode):
        raise ValueError(f"Unsafe non-regular network state entry: {name}")
    if entry.st_uid != owner:
        raise ValueError(f"Network state entry has unexpected owner: {name}")
    if entry.st_nlink != 1:
        raise ValueError(f"Network state entry has unexpected links: {name}")
    # Journal and lock files contain privileged state and are always private.
    if entry.st_mode & 0o077:
        raise ValueError(f"Network state entry is not private: {name}")
    return entry


def _secure_directory_stat(dir_fd, owner, *, name="network state", private=True):
    entry = os.fstat(dir_fd)
    if not stat.S_ISDIR(entry.st_mode):
        raise ValueError(f"Unsafe {name} directory")
    if entry.st_uid != owner:
        raise ValueError(f"{name} directory has unexpected owner")
    if private:
        if entry.st_mode & 0o077:
            raise ValueError(f"{name} directory is not private")
    elif entry.st_mode & 0o022:
        raise ValueError(f"{name} directory is writable by group or other")
    return entry


def _identity(entry):
    return (entry.st_dev, entry.st_ino, entry.st_uid, entry.st_mode & 0o7777)


def _validate_interface(interface):
    if not isinstance(interface, str) or not _INTERFACE_RE.fullmatch(interface):
        raise ValueError("Interface name is invalid.")
    return interface


def _parse_lan(subnet):
    if not isinstance(subnet, str):
        raise ValueError("Use an RFC1918 IPv4 LAN subnet, never the Internet.")
    try:
        network = ipaddress.ip_network(subnet, strict=True)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "Use an RFC1918 IPv4 LAN subnet, never the Internet."
        ) from error
    private = tuple(
        ipaddress.ip_network(value)
        for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    )
    if network.version != 4 or not any(network.subnet_of(lan) for lan in private):
        raise ValueError("Use an RFC1918 IPv4 LAN subnet, never the Internet.")
    return network


def validate_lan(interface, subnet):
    """Validate an RFC1918 IPv4 directly-connected route on interface."""
    interface = _validate_interface(interface)
    network = _parse_lan(subnet)
    try:
        route_output = run("ip", "-j", "-4", "route", "show", "dev", interface).stdout
        routes = json.loads(
            route_output,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_json_object,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("The kernel returned invalid IPv4 route data.") from error
    if not isinstance(routes, list):
        raise ValueError("The kernel returned invalid IPv4 route data.")
    if not any(
        isinstance(route, dict)
        and route.get("dst") == str(network)
        and route.get("scope") == "link"
        for route in routes
    ):
        raise ValueError(
            "Subnet must be a directly connected route on the named interface."
        )
    return str(network)


def rule_key(rule):
    """Return UFW selectors independent of action, logging, and comment."""
    if not isinstance(rule, (list, tuple)) or not rule:
        return ("invalid-rule",)
    if any(not isinstance(token, str) for token in rule):
        return ("invalid-rule",)
    tokens = list(rule[1:])
    if not tokens:
        return tuple(rule)
    if "comment" in tokens:
        tokens = tokens[: tokens.index("comment")]
    if not tokens:
        return tuple(rule)
    fields = {}
    for keyword in ("on", "proto"):
        try:
            index = tokens.index(keyword)
        except ValueError:
            continue
        if index + 1 >= len(tokens):
            return tuple(rule)
        fields[keyword] = tokens[index + 1]
        del tokens[index : index + 2]
    if "from" not in tokens or "to" not in tokens:
        return tuple(rule)
    try:
        source = tokens.index("from")
        destination = tokens.index("to")
    except ValueError:
        return tuple(rule)
    if destination <= source:
        return tuple(rule)
    logging = tuple(token for token in tokens[1:source] if token in ("log", "log-all"))
    qualifiers = tuple(
        token for token in tokens[1:source] if token not in ("log", "log-all")
    )
    return (
        tokens[0],
        logging,
        qualifiers,
        fields.get("on"),
        fields.get("proto"),
        tuple(tokens[source + 1 : destination]),
        tuple(tokens[destination + 1 :]),
    )


def rules():
    """Read UFW's added-rule listing without accepting shell syntax."""
    output = run("ufw", "show", "added").stdout
    if not isinstance(output, str):
        raise ValueError("UFW returned invalid rule data.")
    result = []
    for line in output.splitlines():
        if not line.startswith("ufw "):
            continue
        try:
            parsed = shlex.split(line, comments=False, posix=True)
        except ValueError as error:
            raise ValueError("UFW returned malformed rule data.") from error
        if not parsed or parsed[0] != "ufw":
            raise ValueError("UFW returned malformed rule data.")
        result.append(parsed)
    return result


def _selectors(rule):
    return rule_key(rule)[2:]


def _managed_comment(rule):
    return (
        isinstance(rule, (list, tuple))
        and len(rule) >= 2
        and list(rule[-2:]) == ["comment", COMMENT]
    )


def _rule_for(interface, subnet, port):
    if port not in _ALLOWED_PORTS:
        raise ValueError("Unsupported network port.")
    return [
        "ufw",
        "allow",
        "in",
        "on",
        interface,
        "from",
        subnet,
        "to",
        "any",
        "port",
        port,
        "proto",
        "udp",
        "comment",
        COMMENT,
    ]


def _validate_recorded_rule(rule, interface, subnet):
    if (
        not isinstance(rule, list)
        or len(rule) != 15
        or any(not isinstance(token, str) for token in rule)
        or rule != _rule_for(interface, subnet, rule[10])
    ):
        raise ValueError("Malformed recorded firewall rule.")
    return tuple(rule)


def _validate_state(state):
    """Validate every journal field before any rollback command is issued."""
    if not isinstance(state, dict) or set(state) != {
        "rules",
        "avahi",
        "interface",
        "subnet",
    }:
        raise ValueError("Malformed network state journal.")
    interface = _validate_interface(state["interface"])
    network = _parse_lan(state["subnet"])
    subnet = str(network)
    if subnet != state["subnet"]:
        raise ValueError("Malformed network state journal.")
    recorded = state["rules"]
    if not isinstance(recorded, list):
        raise ValueError("Malformed network state journal.")
    seen = set()
    for item in recorded:
        identity = _validate_recorded_rule(item, interface, subnet)
        if identity in seen:
            raise ValueError("Malformed network state journal.")
        seen.add(identity)
    previous = state["avahi"]
    if previous is not None:
        if not isinstance(previous, dict) or set(previous) != set(_AVAHI_UNITS):
            raise ValueError("Malformed Avahi state journal.")
        for unit in _AVAHI_UNITS:
            status = previous[unit]
            if not isinstance(status, dict) or set(status) != {"enabled", "active"}:
                raise ValueError("Malformed Avahi state journal.")
            if status["enabled"] not in ("enabled", "disabled"):
                raise ValueError("Malformed Avahi state journal.")
            if status["active"] not in ("active", "inactive"):
                raise ValueError("Malformed Avahi state journal.")
    return state


def _new_state(interface, subnet):
    state = {"rules": [], "avahi": None, "interface": interface, "subnet": subnet}
    return _validate_state(state)


class NetworkStateStore:
    """Hold verified state-directory descriptors and an exclusive lock."""

    def __init__(self, root=None, owner=None):
        self.root = Path(STATE_ROOT if root is None else root)
        if not self.root.is_absolute() or not self.root.name:
            raise ValueError("Network state root must be an absolute directory path.")
        self.owner = STATE_OWNER if owner is None else owner
        if not isinstance(self.owner, int) or self.owner < 0:
            raise ValueError("Network state owner is invalid.")
        self.parent_path = self.root.parent
        self.root_name = self.root.name
        self._parent_fd = None
        self._dir_fd = None
        self._lock_fd = None
        self._parent_identity = None
        self._dir_identity = None
        self._lock_identity = None

    @property
    def dir_fd(self):
        if self._dir_fd is None:
            raise RuntimeError("Network state store is not open.")
        return self._dir_fd

    def __enter__(self):
        try:
            self._parent_fd = open_directory(
                str(self.parent_path), self.owner, create=True
            )
            self._parent_identity = _identity(
                _secure_directory_stat(
                    self._parent_fd,
                    self.owner,
                    name="network state parent",
                    private=False,
                )
            )
            flags = (
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0)
            )
            try:
                self._dir_fd = os.open(self.root_name, flags, dir_fd=self._parent_fd)
            except FileNotFoundError:
                os.mkdir(self.root_name, 0o700, dir_fd=self._parent_fd)
                os.fsync(self._parent_fd)
                self._dir_fd = os.open(self.root_name, flags, dir_fd=self._parent_fd)
            self._dir_identity = _identity(
                _secure_directory_stat(self._dir_fd, self.owner)
            )
            self._lock_fd = self._open_lock()
            self._lock_identity = _identity(
                _secure_file_stat(
                    self.dir_fd, LOCK_FILE, self.owner, file_fd=self._lock_fd
                )
            )
            self._assert_identity()
            return self
        except BaseException:
            self._close_fds()
            raise

    def __exit__(self, exc_type, exc_value, traceback):
        self._close_fds()
        return False

    def _close_fds(self):
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_fd)
            self._lock_fd = None
        if self._dir_fd is not None:
            os.close(self._dir_fd)
            self._dir_fd = None
        if self._parent_fd is not None:
            os.close(self._parent_fd)
            self._parent_fd = None

    def _open_lock(self):
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_NOFOLLOW
            | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            lock_fd = os.open(LOCK_FILE, flags | os.O_EXCL, 0o600, dir_fd=self.dir_fd)
        except FileExistsError:
            lock_fd = os.open(LOCK_FILE, flags, dir_fd=self.dir_fd)
        try:
            _secure_file_stat(self.dir_fd, LOCK_FILE, self.owner, file_fd=lock_fd)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError) as error:
                if isinstance(error, BlockingIOError) or getattr(
                    error, "errno", None
                ) in (getattr(os, "EACCES", 13), getattr(os, "EAGAIN", 11)):
                    raise ValueError(
                        "Network state is locked by another operation."
                    ) from error
                raise
            return lock_fd
        except BaseException:
            os.close(lock_fd)
            raise

    def _assert_identity(self):
        """Reject a substituted parent or state directory before mutation."""
        parent = _secure_directory_stat(
            self._parent_fd, self.owner, name="network state parent", private=False
        )
        if _identity(parent) != self._parent_identity:
            raise ValueError("Network state parent directory changed.")
        try:
            path_parent = os.stat(self.parent_path, follow_symlinks=False)
        except OSError as error:
            raise ValueError("Network state parent directory changed.") from error
        if _identity(path_parent) != self._parent_identity:
            raise ValueError("Network state parent directory changed.")
        directory = _secure_directory_stat(self.dir_fd, self.owner)
        if _identity(directory) != self._dir_identity:
            raise ValueError("Network state directory changed.")
        try:
            path_directory = os.stat(
                self.root_name, dir_fd=self._parent_fd, follow_symlinks=False
            )
        except OSError as error:
            raise ValueError("Network state directory changed.") from error
        if _identity(path_directory) != self._dir_identity:
            raise ValueError("Network state directory changed.")
        lock = _secure_file_stat(self.dir_fd, LOCK_FILE, self.owner)
        held_lock = _secure_file_stat(
            self.dir_fd, LOCK_FILE, self.owner, file_fd=self._lock_fd
        )
        if (
            _identity(lock) != self._lock_identity
            or _identity(held_lock) != self._lock_identity
        ):
            raise ValueError("Network state lock changed.")

    def load(self):
        self._assert_identity()
        try:
            _secure_file_stat(self.dir_fd, STATE_FILE, self.owner)
        except FileNotFoundError:
            return None
        raw = read_regular(
            self.dir_fd, STATE_FILE, self.owner, STATE_LIMIT, private=True
        )
        if not isinstance(raw, (bytes, bytearray)):
            raise ValueError("Network state is not a byte stream.")
        if len(raw) > STATE_LIMIT:
            raise ValueError("Network state is too large.")
        try:
            state = json.loads(
                bytes(raw).decode("utf-8"),
                parse_constant=_reject_json_constant,
                object_pairs_hook=_json_object,
            )
        except (UnicodeDecodeError, TypeError, ValueError, RecursionError) as error:
            raise ValueError("Malformed network state journal.") from error
        return _validate_state(state)

    def save(self, state):
        self._assert_identity()
        _validate_state(state)
        payload = (
            json.dumps(state, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        ).encode("utf-8")
        if len(payload) > STATE_LIMIT:
            raise ValueError("Network state is too large.")
        temp_fd = None
        temp_name = None
        temp_identity = None
        try:
            for _ in range(8):
                candidate = f".{STATE_FILE}.{secrets.token_hex(16)}.tmp"
                try:
                    temp_fd = os.open(
                        candidate,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_NOFOLLOW
                        | getattr(os, "O_CLOEXEC", 0),
                        0o600,
                        dir_fd=self.dir_fd,
                    )
                except FileExistsError:
                    continue
                temp_name = candidate
                break
            if temp_fd is None or temp_name is None:
                raise FileExistsError(
                    "Could not allocate a unique network state temporary file."
                )
            temp_identity = _identity(
                _secure_file_stat(self.dir_fd, temp_name, self.owner, file_fd=temp_fd)
            )
            view = memoryview(payload)
            while view:
                written = os.write(temp_fd, view)
                if written <= 0:
                    raise OSError("Short write while saving network state.")
                view = view[written:]
            os.fsync(temp_fd)
            self._assert_identity()
            _secure_file_stat(self.dir_fd, STATE_FILE, self.owner, missing_ok=True)
            if (
                _identity(_secure_file_stat(self.dir_fd, temp_name, self.owner))
                != temp_identity
            ):
                raise ValueError("Network state temporary file changed.")
            os.replace(
                temp_name, STATE_FILE, src_dir_fd=self.dir_fd, dst_dir_fd=self.dir_fd
            )
            temp_name = None
            os.fsync(self.dir_fd)
        finally:
            if temp_fd is not None:
                os.close(temp_fd)
            if temp_name is not None:
                try:
                    entry = os.stat(
                        temp_name, dir_fd=self.dir_fd, follow_symlinks=False
                    )
                    if _identity(entry) == temp_identity:
                        os.unlink(temp_name, dir_fd=self.dir_fd)
                except FileNotFoundError:
                    pass

    def remove(self):
        self._assert_identity()
        _secure_file_stat(self.dir_fd, STATE_FILE, self.owner)
        os.unlink(STATE_FILE, dir_fd=self.dir_fd)
        os.fsync(self.dir_fd)


def _store():
    return NetworkStateStore(STATE_ROOT, STATE_OWNER)


def _unit_snapshot():
    previous = {}
    for unit in _AVAHI_UNITS:
        enabled = run("systemctl", "is-enabled", unit, check=False).stdout.strip()
        active = run("systemctl", "is-active", unit, check=False).stdout.strip()
        if enabled not in ("enabled", "disabled") or active not in (
            "active",
            "inactive",
        ):
            raise ValueError("Avahi has a nonstandard state; configure it manually.")
        previous[unit] = {"enabled": enabled, "active": active}
    return previous


def _matching(existing, wanted):
    wanted_key = _selectors(wanted)
    return [item for item in existing if _selectors(item) == wanted_key]


def _live_rule_exists(rule):
    # UFW stores generic comments in tuple metadata, not an iptables comment match.
    interface, subnet, port = rule[4], rule[6], rule[10]
    match = ["-m", "multiport", "--dports", port] if ":" in port else ["--dport", port]
    result = run(
        "iptables",
        "--wait",
        "2",
        "-C",
        "ufw-user-input",
        "-i",
        interface,
        "-p",
        "udp",
        *match,
        "-s",
        subnet,
        "-j",
        "ACCEPT",
        check=False,
    )
    if result.returncode not in (0, 1):
        raise subprocess.CalledProcessError(
            result.returncode, result.args, result.stdout, result.stderr
        )
    return result.returncode == 0


def _require_live_rule(rule, present):
    if _live_rule_exists(rule) != present:
        raise ValueError(
            "Persisted and live UFW policy differ; journal retained. "
            "Inspect the firewall, reconcile explicitly with sudo ufw reload, "
            "then retry. No global reload was performed."
        )


def network_enable(args):
    """Enable the narrowly-scoped LAN rules and optional Avahi service."""
    interface = _validate_interface(getattr(args, "interface", None))
    subnet = validate_lan(interface, getattr(args, "subnet", None))
    want_mdns = bool(getattr(args, "mdns", False))
    want_avahi = bool(getattr(args, "avahi", False))
    with _store() as store:
        state = store.load()
        if state is None:
            state = _new_state(interface, subnet)
        elif (state["interface"], state["subnet"]) != (interface, subnet):
            raise ValueError(
                "Revert the previous LAN preparation before changing networks."
            )
        store._assert_identity()
        if "Status: active" not in run("ufw", "status").stdout:
            raise ValueError("UFW is not active; no network changes were made.")
        if want_avahi and state["avahi"] is None:
            store._assert_identity()
            state["avahi"] = _unit_snapshot()
            store.save(state)
        if want_avahi:
            store._assert_identity()
            run("systemctl", "enable", "--now", "avahi-daemon.service")
        ports = [RAOP_PORT] + ([MDNS_PORT] if want_mdns else [])
        for port in ports:
            wanted = _rule_for(interface, subnet, port)
            store._assert_identity()
            existing = rules()
            matching = _matching(existing, wanted)
            if matching:
                if any(len(item) < 2 or item[1] != "allow" for item in matching):
                    raise ValueError(
                        f"Existing firewall policy conflicts with UDP {port}; refusing to replace it."
                    )
                _require_live_rule(wanted, True)
                print(f"Preserving existing UDP {port} rule.")
                continue
            if wanted not in state["rules"]:
                state["rules"].append(wanted)
                # Record intent before touching UFW so an interrupted command
                # remains safely reversible.
                store.save(state)
            store._assert_identity()
            print(run(*wanted).stdout.strip())
            _require_live_rule(wanted, True)
        print(
            "LAN preparation recorded. Revert with: sudo /usr/bin/omarchyair-helper network disable"
        )


def _preflight_managed(existing, recorded_selectors):
    for item in existing:
        if _managed_comment(item) and _selectors(item) not in recorded_selectors:
            raise ValueError(
                "A managed rule has changed selectors; inspect it before reverting."
            )


def _restore_avahi(store, previous):
    # Service operations also affect its socket via Also=. Restore service
    # enablement first, then explicitly restore the socket, matching the
    # historical reversal order and allowing a later retry after interruption.
    for unit in _AVAHI_UNITS:
        if previous[unit]["active"] == "inactive":
            store._assert_identity()
            run("systemctl", "stop", unit)
    for unit in _AVAHI_UNITS:
        action = "enable" if previous[unit]["enabled"] == "enabled" else "disable"
        store._assert_identity()
        run("systemctl", action, unit)
    for unit in _AVAHI_UNITS:
        if previous[unit]["active"] == "active":
            store._assert_identity()
            run("systemctl", "start", unit)


def network_disable():
    """Safely reverse only the validated journal entries."""
    with _store() as store:
        state = store.load()
        if state is None:
            print("No managed network changes to revert.")
            return
        recorded_selectors = {_selectors(item) for item in state["rules"]}
        store._assert_identity()
        existing = rules()
        _preflight_managed(existing, recorded_selectors)
        for recorded in list(state["rules"]):
            store._assert_identity()
            current = rules()
            _preflight_managed(current, recorded_selectors)
            matching = _matching(current, recorded)
            for item in matching:
                if rule_key(item) != rule_key(recorded) or not _managed_comment(item):
                    raise ValueError(
                        "A managed rule was edited; refusing to delete it."
                    )
                store._assert_identity()
                # Delete canonical validated arguments, not UFW's potentially
                # reordered listing of the equivalent rule.
                run("ufw", "--force", "delete", *recorded[1:])
            _require_live_rule(recorded, False)
            state["rules"].remove(recorded)
            store.save(state)
        previous = state["avahi"]
        if previous is not None:
            _restore_avahi(store, previous)
            state["avahi"] = None
            store.save(state)
        store.remove()
        print("Managed network changes reverted; pre-existing rules retained.")


def _parser():
    parser = argparse.ArgumentParser(
        prog="omarchyair-helper",
        description="Apply Omarchy Air's narrow LAN network policy.",
    )
    actions = parser.add_subparsers(dest="command", required=True)

    actions.add_parser("protocol", help="Print the helper protocol metadata.")

    network = actions.add_parser("network", help="Manage the LAN network policy.")
    network_actions = network.add_subparsers(dest="action", required=True)

    enable = network_actions.add_parser("enable", help="Enable LAN policy.")
    enable.add_argument("--interface", required=True)
    enable.add_argument("--subnet", required=True)
    enable.add_argument("--mdns", action="store_true")
    enable.add_argument("--avahi", action="store_true")

    network_actions.add_parser("disable", help="Disable managed LAN policy.")
    return parser


def _require_privileged_runtime():
    if os.geteuid() != 0:
        raise PermissionError("Network operations require root.")
    if not sys.flags.isolated:
        raise PermissionError(
            "Network operations require the isolated packaged interpreter."
        )
    interpreter = os.stat(fixed_executable("python3"))
    actual = os.stat("/proc/self/exe")
    if (actual.st_dev, actual.st_ino) != (interpreter.st_dev, interpreter.st_ino):
        raise PermissionError("Use the packaged /usr/bin/python3 interpreter.")
    environment = closed_environment()
    os.environ.clear()
    os.environ.update(environment)
    os.umask(0o077)


def main(argv=None):
    args = _parser().parse_args(argv)
    if args.command == "protocol":
        print(
            json.dumps({"api": API_VERSION, "version": VERSION}, separators=(",", ":"))
        )
        return 0

    _require_privileged_runtime()
    if args.action == "enable":
        network_enable(args)
    else:
        network_disable()
    return 0
