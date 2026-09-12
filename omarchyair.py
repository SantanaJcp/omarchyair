#!/usr/bin/python3 -I
"""Omarchy Air: explicit setup, reversible LAN preparation, and supervised discovery."""

import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import fcntl
import ipaddress
import secrets
import shlex


def _file_snapshot(info):
    return (
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
        int(info.st_mode),
        int(info.st_uid),
        int(info.st_gid),
        int(info.st_nlink),
    )


PLUGIN_ID = "community.omarchyair"
TOOLS = frozenset(
    (
        "python3",
        "pw-cli",
        "ip",
        "ufw",
        "systemctl",
        "omarchy",
        "omarchy-shell",
        "pacman",
        "pactl",
        "sudo",
        "env",
        "iptables",
    )
)
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def open_directory(path, owner, create=False, *, final_allow_root=False):
    """Walk from the trusted root, never following a symlink or writable ancestor."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Expected an absolute path without parent traversal")
    fd = os.open("/", DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            try:
                child = os.open(component, DIRECTORY_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
                child = os.open(component, DIRECTORY_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid not in (0, owner) or info.st_mode & 0o022:
                raise ValueError(f"Untrusted directory owner or permissions: {path}")
        if os.fstat(fd).st_uid not in ((0, owner) if final_allow_root else (owner,)):
            raise ValueError(f"Unexpected directory owner: {path}")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_regular(dirfd, name, owner, limit, *, private=False):
    """Read at most limit bytes from a held, single-link, no-follow regular file."""
    if not name or name in (".", "..") or "/" in name:
        raise ValueError("Expected a file basename")
    owners = (owner,) if isinstance(owner, int) else owner
    fd = os.open(name, FILE_FLAGS, dir_fd=dirfd)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in owners
            or before.st_mode & (0o077 if private else 0o022)
            or before.st_nlink != 1
        ):
            raise ValueError(f"Untrusted file: {name}")
        if before.st_size > limit:
            raise ValueError(f"File exceeds {limit} bytes: {name}")
        result = bytearray()
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
            if len(result) > limit:
                raise ValueError(f"File exceeds {limit} bytes: {name}")
        after = os.fstat(fd)
        if _file_snapshot(before) != _file_snapshot(after):
            raise ValueError(f"File changed while reading: {name}")
        current = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError(f"File replaced while reading: {name}")
        return bytes(result)
    finally:
        os.close(fd)


def fixed_executable(name):
    if name not in TOOLS:
        raise ValueError(f"Unsupported executable: {name}")
    original = "/usr/bin/" + name
    pending = ["usr", "bin", name]
    directories = [os.open("/", DIRECTORY_FLAGS)]
    links = 0
    try:
        while pending:
            component = pending.pop(0)
            if component in ("", "."):
                continue
            if component == "..":
                if len(directories) > 1:
                    os.close(directories.pop())
                continue
            parent = directories[-1]
            info = os.stat(component, dir_fd=parent, follow_symlinks=False)
            if info.st_uid != 0:
                raise ValueError(
                    f"Non-root executable resolution component: {original}"
                )
            if stat.S_ISLNK(info.st_mode):
                links += 1
                if links > 40:
                    raise ValueError("Excessive executable symlink indirection")
                target = os.readlink(component, dir_fd=parent)
                if target.startswith("/"):
                    while len(directories) > 1:
                        os.close(directories.pop())
                pending = target.split("/") + pending
            elif pending:
                fd = os.open(component, DIRECTORY_FLAGS, dir_fd=parent)
                directories.append(fd)
                checked = os.fstat(fd)
                if checked.st_uid != 0 or checked.st_mode & 0o022:
                    raise ValueError(f"Untrusted executable directory: {original}")
            else:
                fd = os.open(component, FILE_FLAGS, dir_fd=parent)
                try:
                    checked = os.fstat(fd)
                    if (
                        not stat.S_ISREG(checked.st_mode)
                        or checked.st_uid != 0
                        or checked.st_mode & 0o022
                        or not checked.st_mode & 0o111
                    ):
                        raise ValueError(f"Unsafe system executable: {original}")
                finally:
                    os.close(fd)
    finally:
        for fd in directories:
            os.close(fd)
    # Every component, including symlink detours, is root-controlled. Keep the
    # packaged script's original path because Omarchy dispatches relative to it.
    return original


def closed_environment(desktop=False):
    account = pwd.getpwuid(os.geteuid())
    result = {
        "PATH": "/usr/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "HOME": account.pw_dir,
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "OMARCHY_PATH": "/usr/share/omarchy",
    }
    if desktop:
        if os.geteuid() == 0:
            raise ValueError("Desktop commands must not run as root")
        runtime = Path("/run/user") / str(os.getuid())
        fd = open_directory(runtime, os.getuid())
        try:
            if os.fstat(fd).st_mode & 0o077:
                raise ValueError("Desktop runtime directory must be private")
            display = os.environ.get("WAYLAND_DISPLAY", "")
            if not re.fullmatch(r"wayland-[0-9]{1,6}", display):
                raise ValueError("Expected a local WAYLAND_DISPLAY socket name")
            for name in (display, "bus"):
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                    raise ValueError(f"Untrusted session socket: {name}")
        finally:
            os.close(fd)
        result.update(
            XDG_RUNTIME_DIR=str(runtime),
            WAYLAND_DISPLAY=display,
            DBUS_SESSION_BUS_ADDRESS=f"unix:path={runtime}/bus",
            XDG_CONFIG_HOME=f"{account.pw_dir}/.config",
        )
    return result


def _prctl(option, value):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(ctypes.c_int(option), ctypes.c_ulong(value), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl failed")


def _guardian(argv, environment, pipes, parent_pid, timeout, interactive):
    """Own the process group independently of the caller, including caller death."""
    out_r, out_w, err_r, err_w, in_r, in_w, ctl_r, ctl_w, status_r, status_w = pipes
    stopped = False

    def stop(signum, frame):
        nonlocal stopped
        stopped = True

    try:
        if interactive:
            os.setpgid(0, 0)
        else:
            os.setsid()
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGHUP, stop)
        _prctl(36, 1)  # PR_SET_CHILD_SUBREAPER: reap orphaned group descendants.
        _prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG, followed by the fork-race check.
        if os.getppid() != parent_pid:
            os._exit(125)
        for fd in (out_r, err_r, in_w, ctl_w, status_r):
            os.close(fd)
        if interactive:
            with selectors.DefaultSelector() as start:
                start.register(ctl_r, selectors.EVENT_READ)
                if not start.select(min(timeout, 5)) or not os.read(ctl_r, 1):
                    raise ValueError("Foreground terminal handoff timed out")
        child = subprocess.Popen(
            argv,
            stdin=None if interactive else in_r,
            stdout=out_w,
            stderr=err_w,
            env=environment,
            cwd="/",
            close_fds=True,
            restore_signals=True,
        )
        for fd in (in_r, out_w, err_w):
            os.close(fd)
        deadline = time.monotonic() + timeout
        os.set_blocking(ctl_r, False)
        result = None
        while not stopped:
            result = child.poll()
            if result is not None:
                break
            try:
                lease = os.read(ctl_r, 64)
                if not lease:
                    stopped = True
                elif lease:
                    deadline = time.monotonic() + timeout
            except BlockingIOError:
                pass
            if time.monotonic() >= deadline:
                stopped = True
            if not stopped:
                time.sleep(0.025)
        # Record command outcome separately: killing surviving group members also
        # kills this guardian, so its own wait status is not the command status.
        os.write(status_w, str(result if result is not None else 124).encode() + b"\n")
        os.close(status_w)
        os.killpg(os.getpid(), signal.SIGTERM)
        grace = time.monotonic() + 1.0
        while time.monotonic() < grace:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                os._exit(0)
            if pid == 0:
                time.sleep(0.025)
        os.killpg(os.getpid(), signal.SIGKILL)
    except BaseException as error:
        try:
            os.write(err_w, ("Process guardian: " + str(error)[:512] + "\n").encode())
            os.write(status_w, b"125\n")
        except OSError:
            pass
        # If exec/setup failed after a child was created, leave no owned group.
        if os.getpgrp() == os.getpid():
            os.killpg(os.getpid(), signal.SIGKILL)
    os._exit(125)


def _set_foreground(fd, group):
    previous = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    try:
        os.tcsetpgrp(fd, group)
    finally:
        signal.signal(signal.SIGTTOU, previous)


class ManagedProcess:
    """A bounded lease owns one process group, not just its immediate child."""

    def __init__(self, args, *, timeout=30, desktop=False, interactive=False):
        if not 0 < timeout <= 900:
            raise ValueError("Process deadline must be between zero and 900 seconds")
        if interactive and not sys.stdin.isatty():
            raise ValueError("Package installation requires an interactive terminal")
        argv = [fixed_executable(args[0]), *args[1:]]
        environment = closed_environment(desktop)
        self.terminal = None
        self.foreground = None
        if interactive:
            self.terminal = os.dup(0)
            self.foreground = os.tcgetpgrp(self.terminal)
            if self.foreground != os.getpgrp():
                os.close(self.terminal)
                raise ValueError("Run package installation in the foreground terminal")
        pipes = tuple(fd for _ in range(5) for fd in os.pipe2(os.O_CLOEXEC))
        parent_pid = os.getpid()
        try:
            self.pid = os.fork()
        except BaseException:
            for fd in pipes:
                os.close(fd)
            if self.terminal is not None:
                os.close(self.terminal)
            raise
        if self.pid == 0:
            if self.terminal is not None:
                os.close(self.terminal)
            _guardian(argv, environment, pipes, parent_pid, timeout, interactive)
        out_r, out_w, err_r, err_w, in_r, in_w, ctl_r, ctl_w, status_r, status_w = pipes
        for fd in (out_w, err_w, in_r, ctl_r, status_w):
            os.close(fd)
        self.stdout, self.stderr, self.stdin = out_r, err_r, in_w
        self.control, self.status = ctl_w, status_r
        self.reaped = False
        self.returncode = None
        for fd in (self.stdout, self.stderr, self.stdin, self.control, self.status):
            os.set_blocking(fd, False)
        if interactive:
            try:
                os.setpgid(self.pid, self.pid)
                _set_foreground(self.terminal, self.pid)
                self.renew()  # Release the guardian only after terminal handoff.
            except BaseException:
                self.close()
                raise

    def send(self, data):
        if os.write(self.stdin, data) != len(data):
            raise ValueError("Incomplete process command write")

    def close_stdin(self):
        os.close(self.stdin)
        self.stdin = -1

    def renew(self):
        os.write(self.control, b".")

    def poll(self):
        if not self.reaped:
            pid, _ = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.reaped = True
                outcome = os.read(self.status, 32)
                self.returncode = int(outcome.strip()) if outcome.strip() else 125
        return self.returncode

    def close(self):
        if not self.reaped:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 2
            while self.poll() is None and time.monotonic() < deadline:
                time.sleep(0.025)
            if not self.reaped:
                # The guardian holds its group ID until reaped, preventing reuse.
                try:
                    os.killpg(self.pid, signal.SIGKILL)
                except ProcessLookupError:
                    os.kill(self.pid, signal.SIGKILL)
                os.waitpid(self.pid, 0)
                self.reaped = True
                self.returncode = 124
        for fd in (self.stdout, self.stderr, self.stdin, self.control, self.status):
            if fd >= 0:
                os.close(fd)
        if self.terminal is not None:
            try:
                _set_foreground(self.terminal, self.foreground)
            finally:
                os.close(self.terminal)
                self.terminal = None


def run(
    *args,
    check=True,
    timeout=30,
    output_limit=1048576,
    desktop=False,
    interactive=False,
):
    if not 0 < output_limit <= 8 * 1048576:
        raise ValueError("Invalid command output budget")
    child = ManagedProcess(
        args, timeout=timeout, desktop=desktop, interactive=interactive
    )
    buffers = {child.stdout: bytearray(), child.stderr: bytearray()}
    deadline = time.monotonic() + timeout
    count = 0
    try:
        if not interactive:
            child.close_stdin()
        with selectors.DefaultSelector() as selector:
            for fd in buffers:
                selector.register(fd, selectors.EVENT_READ)
            while selector.get_map() or child.poll() is None:
                if time.monotonic() >= deadline:
                    raise ValueError(f"{args[0]} exceeded its {timeout}s deadline")
                for key, _ in selector.select(
                    min(0.1, max(0, deadline - time.monotonic()))
                ):
                    chunk = os.read(key.fd, min(65536, output_limit + 1 - count))
                    if not chunk:
                        selector.unregister(key.fd)
                        continue
                    count += len(chunk)
                    if count > output_limit:
                        raise ValueError(f"{args[0]} exceeded its output budget")
                    buffers[key.fd].extend(chunk)
        result = subprocess.CompletedProcess(
            args,
            child.returncode,
            buffers[child.stdout].decode("utf-8", "replace"),
            buffers[child.stderr].decode("utf-8", "replace"),
        )
        if check and result.returncode:
            raise subprocess.CalledProcessError(
                result.returncode, args, result.stdout, result.stderr
            )
        return result
    finally:
        child.close()


RAOP_MODULE = "libpipewire-module-raop-discover"
RAOP_ARGUMENTS = (
    '{ stream.rules = [ { matches = [ { raop.ip = "~.*" } ] '
    "actions = { create-stream = { stream.props = { priority.session = 0 } } } } ] }"
)


def discover():
    child = ManagedProcess(("pw-cli",), timeout=15, desktop=True)
    return _supervise_discovery(child, 0)


def _supervise_discovery(child, lease_fd, *, startup_timeout=10, lease_timeout=15):
    """Require shell leases and module acknowledgements; never forward raw logs."""
    stopped = False

    def stop(signum, frame):
        nonlocal stopped
        stopped = True

    handlers = {
        sig: signal.signal(sig, stop)
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    }
    buffers = {child.stdout: bytearray(), child.stderr: bytearray()}
    shell_lease = time.monotonic() + lease_timeout
    response_deadline = time.monotonic() + startup_timeout
    next_probe = None
    ready = False
    last_diagnostic = ""
    window_start, window_bytes = time.monotonic(), 0
    original_blocking = os.get_blocking(lease_fd)
    try:
        os.set_blocking(lease_fd, False)
        child.send(
            ("load-module " + RAOP_MODULE + " " + RAOP_ARGUMENTS + "\n").encode()
        )
        with selectors.DefaultSelector() as selector:
            for fd in (lease_fd, child.stdout, child.stderr):
                selector.register(fd, selectors.EVENT_READ)
            while not stopped:
                now = time.monotonic()
                if now >= shell_lease:
                    raise ValueError("Shell lease expired")
                if response_deadline is not None and now >= response_deadline:
                    raise ValueError(
                        "PipeWire module acknowledgement timed out: " + last_diagnostic
                    )
                if child.poll() is not None:
                    raise ValueError(f"PipeWire process exited ({child.returncode})")
                if next_probe is not None and now >= next_probe:
                    child.send(b"list-vars\n")
                    response_deadline, next_probe = now + 5, None
                if now - window_start >= 10:
                    window_start, window_bytes = now, 0
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fd, 4096)
                    if key.fd == lease_fd:
                        if not chunk:
                            stopped = True
                            break
                        if chunk.strip(b".\n"):
                            raise ValueError("Invalid shell lease message")
                        shell_lease = time.monotonic() + lease_timeout
                        continue
                    if not chunk:
                        raise ValueError("PipeWire output channel closed")
                    window_bytes += len(chunk)
                    if window_bytes > 262144:
                        raise ValueError(
                            "PipeWire exceeded its 256 KiB/10s output budget"
                        )
                    buffer = buffers[key.fd]
                    buffer.extend(chunk)
                    while b"\n" in buffer:
                        line, _, remainder = buffer.partition(b"\n")
                        buffer[:] = remainder
                        if len(line) > 8192:
                            raise ValueError("PipeWire output line exceeds 8 KiB")
                        if key.fd == child.stderr:
                            # Registry diagnostics are not command outcomes.
                            # Only a module acknowledgement proves readiness.
                            last_diagnostic = line[:512].decode("utf-8", "replace")
                        if key.fd == child.stdout and re.search(
                            rb"\b[0-9]+ = @module:[0-9]+\s*$", line
                        ):
                            response_deadline, next_probe = None, time.monotonic() + 5
                            child.renew()
                            if not ready:
                                ready = True
                                print('{"ready":true}', flush=True)
                    if len(buffer) > 8192:
                        raise ValueError("PipeWire output line exceeds 8 KiB")
        return 0
    finally:
        child.close()
        os.set_blocking(lease_fd, original_blocking)
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


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
            "LAN preparation recorded. Revert with: sudo /usr/bin/python3 -I omarchyair.py network disable"
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


SOURCE = Path(os.path.abspath(os.path.dirname(__file__)))
FILES = ("manifest.json", "Service.qml", "omarchyair.py", "README.md", "LICENSE")
_MAX_INSTALL_FILE_BYTES = 1048576
_INSTALL_STAGE_ATTEMPTS = 64
_BACKUP_ATTEMPTS = 1024
_RENAME_NOREPLACE = 1
_DEST_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


def _normal_user():
    """Return the invoking uid and its passwd-database home directory."""
    uid = os.getuid()
    if uid == 0 or os.geteuid() == 0:
        raise ValueError("Run installer commands as the desktop user, not root")
    try:
        account = pwd.getpwuid(uid)
    except KeyError as error:
        raise ValueError(f"No passwd entry for invoking uid {uid}") from error
    home = Path(account.pw_dir)
    if not home.is_absolute() or ".." in home.parts:
        raise ValueError("Passwd home directory is not a safe absolute path")
    return uid, home


def _source_path():
    source = Path(SOURCE)
    if not source.is_absolute() or ".." in source.parts:
        raise ValueError("Installer source must be an absolute directory path")
    return source


def _target_parent(home):
    return home / ".config" / "omarchy" / "plugins"


def _node_identity(info):
    return int(info.st_dev), int(info.st_ino)


def _same_node(left, right):
    return _node_identity(left) == _node_identity(right)


def _safe_mode(info):
    return not bool(info.st_mode & 0o022)


def _check_directory(info, owner, allow_root, label):
    allowed = {owner}
    if allow_root:
        allowed.add(0)
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"Expected a directory: {label}")
    if info.st_uid not in allowed or not _safe_mode(info):
        raise ValueError(f"Untrusted directory owner or permissions: {label}")


def _check_regular(info, owners, label):
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid not in owners
        or not _safe_mode(info)
        or info.st_nlink != 1
    ):
        raise ValueError(f"Untrusted regular file: {label}")


def _verify_directory_path(path, expected_fd, owner, *, final_allow_root=False):
    """Confirm the pathname still names the held directory inode."""
    fresh = open_directory(path, owner, final_allow_root=final_allow_root)
    try:
        if not _same_node(os.fstat(expected_fd), os.fstat(fresh)):
            raise ValueError(f"Directory changed while operating: {path}")
    finally:
        os.close(fresh)


def _basename(name):
    if (
        not isinstance(name, str)
        or not name
        or name in (".", "..")
        or "/" in name
        or "\x00" in name
    ):
        raise ValueError("Expected a file basename")
    return name


def _copy_regular(sourcefd, stagefd, name, owner, created):
    """Copy one bounded source file into an O_EXCL destination."""
    _basename(name)
    source_file = os.open(name, FILE_FLAGS, dir_fd=sourcefd)
    destination_file = None
    try:
        before = os.fstat(source_file)
        _check_regular(before, {owner, 0}, name)
        if before.st_size > _MAX_INSTALL_FILE_BYTES:
            raise ValueError(f"File exceeds {_MAX_INSTALL_FILE_BYTES} bytes: {name}")
        destination_file = os.open(name, _DEST_FILE_FLAGS, 0o600, dir_fd=stagefd)
        destination_info = os.fstat(destination_file)
        # Record the inode immediately.  If a later read/write check fails,
        # cleanup can remove exactly this file and nothing a caller inserted.
        created[name] = _node_identity(destination_info)
        _check_regular(destination_info, {owner}, name)
        if destination_info.st_mode & 0o777 != 0o600:
            raise ValueError(f"Unexpected destination mode: {name}")
        copied = 0
        while True:
            chunk = os.read(
                source_file, min(65536, _MAX_INSTALL_FILE_BYTES + 1 - copied)
            )
            if not chunk:
                break
            if copied + len(chunk) > _MAX_INSTALL_FILE_BYTES:
                raise ValueError(
                    f"File exceeds {_MAX_INSTALL_FILE_BYTES} bytes: {name}"
                )
            offset = 0
            while offset < len(chunk):
                written = os.write(destination_file, chunk[offset:])
                if written <= 0:
                    raise OSError(errno.EIO, f"Could not write {name}")
                offset += written
            copied += len(chunk)
        after = os.fstat(source_file)
        if _file_snapshot(before) != _file_snapshot(after) or after.st_size != copied:
            raise ValueError(f"Source changed while copying: {name}")
        path_info = os.stat(name, dir_fd=sourcefd, follow_symlinks=False)
        if not _same_node(before, path_info):
            raise ValueError(f"Source was replaced while copying: {name}")
        _check_regular(path_info, {owner, 0}, name)
        os.fsync(destination_file)
        destination_info = os.fstat(destination_file)
        _check_regular(destination_info, {owner}, name)
        if destination_info.st_mode & 0o777 != 0o600:
            raise ValueError(f"Unexpected destination mode: {name}")
        created[name] = _node_identity(destination_info)
        return destination_info
    finally:
        os.close(source_file)
        if destination_file is not None:
            os.close(destination_file)


def _new_stage(parentfd, owner):
    for _ in range(_INSTALL_STAGE_ATTEMPTS):
        name = f".omarchyair.install.{os.getpid()}.{secrets.token_hex(12)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parentfd)
        except FileExistsError:
            continue
        os.fsync(parentfd)
        path_info = os.stat(name, dir_fd=parentfd, follow_symlinks=False)
        _check_directory(path_info, owner, False, name)
        fd = None
        try:
            fd = os.open(name, DIRECTORY_FLAGS, dir_fd=parentfd)
            fd_info = os.fstat(fd)
            if not _same_node(path_info, fd_info):
                raise ValueError("Install staging directory was replaced")
            _check_directory(fd_info, owner, False, name)
            return name, fd, fd_info
        except BaseException:
            if fd is not None:
                os.close(fd)
            raise
    raise FileExistsError(errno.EEXIST, "Could not reserve install staging name")


def _cleanup_stage(stagefd, parentfd, stage_name, stage_info, created, owner):
    """Remove only files made by this transaction; leave unknown entries."""
    try:
        current = os.stat(stage_name, dir_fd=parentfd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if _node_identity(current) != _node_identity(stage_info):
        return False
    for name, expected in tuple(created.items()):
        try:
            info = os.stat(name, dir_fd=stagefd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if _node_identity(info) != expected:
            raise ValueError(f"Staging file was replaced; refusing cleanup: {name}")
        _check_regular(info, {owner}, name)
        os.unlink(name, dir_fd=stagefd)
    os.fsync(stagefd)
    try:
        os.rmdir(stage_name, dir_fd=parentfd)
    except OSError as error:
        if error.errno in (errno.ENOTEMPTY, errno.EEXIST):
            return False  # Preserve unknown entries; never recurse.
        raise
    os.fsync(parentfd)
    return True


def _rename_noreplace(old_dirfd, old_name, new_dirfd, new_name):
    """Atomically rename without replacing an existing destination."""
    _basename(old_name)
    _basename(new_name)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except AttributeError as error:
        raise OSError(errno.ENOSYS, "renameat2 is unavailable") from error
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        old_dirfd,
        os.fsencode(old_name),
        new_dirfd,
        os.fsencode(new_name),
        _RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise FileExistsError(error_number, os.strerror(error_number), new_name)
        raise OSError(error_number, os.strerror(error_number), new_name)


def _assert_target(parentfd, expected, owner):
    try:
        info = os.stat(PLUGIN_ID, dir_fd=parentfd, follow_symlinks=False)
    except FileNotFoundError as error:
        raise ValueError("Installed plugin path disappeared") from error
    if not _same_node(info, expected):
        raise ValueError("Installed plugin path was replaced; refusing to continue")
    _check_directory(info, owner, False, PLUGIN_ID)
    return info


def _publish_files(sourcefd, parentfd, source_info, owner):
    """Copy the fixed payload and atomically publish it, or accept self-install."""
    try:
        target_info = os.stat(PLUGIN_ID, dir_fd=parentfd, follow_symlinks=False)
    except FileNotFoundError:
        target_info = None
    if target_info is not None:
        if stat.S_ISLNK(target_info.st_mode):
            raise ValueError("Installed plugin path is a symlink; refusing overwrite")
        _check_directory(target_info, owner, False, PLUGIN_ID)
        targetfd = os.open(PLUGIN_ID, DIRECTORY_FLAGS, dir_fd=parentfd)
        try:
            held_target = os.fstat(targetfd)
            if not _same_node(target_info, held_target):
                raise ValueError("Installed plugin path was replaced")
            if _same_node(held_target, source_info):
                return True, held_target
        finally:
            os.close(targetfd)
        raise ValueError(
            f"{PLUGIN_ID} already exists; refusing to overwrite it. "
            "Use the installed copy or uninstall first."
        )

    stage_name, stagefd, stage_info = _new_stage(parentfd, owner)
    created = {}
    published = False
    try:
        for name in FILES:
            _copy_regular(sourcefd, stagefd, name, owner, created)
        # Rewind a directory opened before its new entries were written.
        os.lseek(stagefd, 0, os.SEEK_SET)
        count = 0
        with os.scandir(stagefd) as entries:
            for entry in entries:
                if (
                    entry.name not in created
                    or _node_identity(entry.stat(follow_symlinks=False))
                    != created[entry.name]
                ):
                    raise ValueError("Install staging directory changed unexpectedly")
                count += 1
        if count != len(FILES):
            raise ValueError("Install staging payload is incomplete")
        current_stage = os.stat(stage_name, dir_fd=parentfd, follow_symlinks=False)
        if not _same_node(current_stage, stage_info):
            raise ValueError("Install staging directory was replaced")
        os.fsync(stagefd)
        try:
            _rename_noreplace(parentfd, stage_name, parentfd, PLUGIN_ID)
        except FileExistsError as error:
            raise ValueError(
                f"{PLUGIN_ID} already exists; refusing to overwrite it. "
                "Use the installed copy or uninstall first."
            ) from error
        published = True
        target_info = os.stat(PLUGIN_ID, dir_fd=parentfd, follow_symlinks=False)
        if _node_identity(target_info) != _node_identity(stage_info):
            raise ValueError("Published plugin path identity changed")
        _check_directory(target_info, owner, False, PLUGIN_ID)
        os.fsync(parentfd)
        return False, target_info
    finally:
        if not published:
            try:
                _cleanup_stage(
                    stagefd, parentfd, stage_name, stage_info, created, owner
                )
            finally:
                os.close(stagefd)
        else:
            os.close(stagefd)


def catalog():
    result = run("omarchy", "plugin", "list", "--json", timeout=30, desktop=True)
    try:
        value = json.loads(result.stdout)
    except (TypeError, ValueError) as error:
        raise ValueError("Omarchy returned invalid plugin catalog JSON") from error
    if not isinstance(value, list):
        raise ValueError("Omarchy returned an invalid plugin catalog")
    return value


def _manifest(sourcefd, owner):
    raw = read_regular(sourcefd, "manifest.json", {owner, 0}, _MAX_INSTALL_FILE_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("Source manifest is not valid UTF-8 JSON") from error
    if not isinstance(value, dict) or value.get("id") != PLUGIN_ID:
        raise ValueError("Source manifest id does not match the plugin id")
    if not isinstance(value.get("version"), str) or not value["version"]:
        raise ValueError("Source manifest has no version")
    return value


def _wait_for_discovery(parentfd, parent_path, expected, owner):
    deadline = time.monotonic() + 10
    while True:
        _verify_directory_path(parent_path, parentfd, owner)
        _assert_target(parentfd, expected, owner)
        if any(
            item.get("id") == PLUGIN_ID for item in catalog() if isinstance(item, dict)
        ):
            return
        if time.monotonic() >= deadline:
            raise ValueError(
                "Shell has not discovered the installed plugin; files retained for diagnosis."
            )
        time.sleep(0.1)


def install():
    """Validate, atomically install, and enable the Omarchy Air plugin."""
    owner, home = _normal_user()
    source_path = _source_path()
    parent_path = _target_parent(home)
    sourcefd = open_directory(source_path, owner, final_allow_root=True)
    parentfd = None
    try:
        parentfd = open_directory(parent_path, owner, create=True)
        source_info = os.fstat(sourcefd)
        _check_directory(source_info, owner, True, str(source_path))
        manifest = _manifest(sourcefd, owner)
        read_regular(sourcefd, "omarchyair.py", {owner, 0}, _MAX_INSTALL_FILE_BYTES)
        _verify_directory_path(parent_path, parentfd, owner)
        run("omarchy", "plugin", "validate", str(source_path), timeout=30)
        _verify_directory_path(source_path, sourcefd, owner, final_allow_root=True)
        if run("pacman", "-Q", "pipewire-zeroconf", check=False, timeout=30).returncode:
            # Elevation is explicit, narrow, foreground, and bounded.  The
            # consolidated executable's root-only install-dependency command
            # invokes `omarchy pkg add` under its own process-group guardian.
            _verify_directory_path(source_path, sourcefd, owner, final_allow_root=True)
            run(
                "sudo",
                "--",
                fixed_executable("env"),
                "-i",
                "PATH=/usr/bin",
                "LC_ALL=C",
                fixed_executable("python3"),
                "-I",
                str(source_path / "omarchyair.py"),
                "install-dependency",
                timeout=660,
                output_limit=8 * 1048576,
                interactive=True,
            )
            _verify_directory_path(source_path, sourcefd, owner, final_allow_root=True)
        if run(
            "systemctl",
            "is-active",
            "--quiet",
            "avahi-daemon.service",
            check=False,
            timeout=30,
        ).returncode:
            raise ValueError(
                "Avahi is not running. Prepare the LAN explicitly with: "
                "/usr/bin/python3 -I omarchyair.py network enable --avahi"
            )
        _verify_directory_path(source_path, sourcefd, owner, final_allow_root=True)
        same_install, expected = _publish_files(sourcefd, parentfd, source_info, owner)
        _verify_directory_path(parent_path, parentfd, owner)
        _assert_target(parentfd, expected, owner)
        entries = catalog()
        if not any(
            item.get("id") == PLUGIN_ID for item in entries if isinstance(item, dict)
        ):
            _verify_directory_path(parent_path, parentfd, owner)
            _assert_target(parentfd, expected, owner)
            run("omarchy-shell", "shell", "rescanPlugins", timeout=30, desktop=True)
        _wait_for_discovery(parentfd, parent_path, expected, owner)
        _verify_directory_path(parent_path, parentfd, owner)
        _assert_target(parentfd, expected, owner)
        run("omarchy", "plugin", "enable", PLUGIN_ID, timeout=30, desktop=True)
        deadline = time.monotonic() + 10
        while True:
            _verify_directory_path(parent_path, parentfd, owner)
            _assert_target(parentfd, expected, owner)
            probe = run(
                "omarchy-shell",
                "omarchyair",
                "status",
                check=False,
                timeout=30,
                desktop=True,
            )
            if probe.returncode == 0:
                try:
                    status = json.loads(probe.stdout)
                except (TypeError, ValueError) as error:
                    raise ValueError(
                        "Plugin service returned invalid status JSON"
                    ) from error
                if not isinstance(status, dict):
                    raise ValueError("Plugin returned invalid status")
                if (
                    "ready" not in status
                    or status.get("version") != manifest["version"]
                ):
                    raise ValueError(
                        "Omarchy cached an older service. Run omarchy restart shell, then retry."
                    )
                if status.get("ready"):
                    break
                if status.get("lastExitCode") is not None:
                    raise ValueError(f"Discovery process stopped: {status}")
            if time.monotonic() >= deadline:
                raise ValueError(
                    "Plugin service did not start; run doctor and inspect shell logs."
                )
            time.sleep(0.1)
        print("Omarchy Air enabled. Select a receiver in the existing audio panel.")
        print(
            "Discovery is not proof of playback. Run doctor; prepare LAN timing ports only if blocked."
        )
        return same_install
    finally:
        if parentfd is not None:
            os.close(parentfd)
        os.close(sourcefd)


def _raise_result_failure(result):
    raise subprocess.CalledProcessError(
        result.returncode, result.args, result.stdout, result.stderr
    )


def _disable_native_record():
    """Remove this third-party id from shell.json through the native IPC."""
    result = run(
        "omarchy-shell",
        "shell",
        "setPluginEnabled",
        PLUGIN_ID,
        "false",
        check=False,
        timeout=30,
        desktop=True,
    )
    if result.returncode:
        _raise_result_failure(result)
    response = result.stdout.strip()
    if response not in ("ok", "unknown"):
        raise ValueError(f"Unexpected native plugin settings response: {response!r}")
    return response


def _move_to_backup(parentfd, targetfd, target_info, owner):
    timestamp = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    base = f".{PLUGIN_ID}.bak.{timestamp}"
    for number in range(_BACKUP_ATTEMPTS):
        backup = base if number == 0 else f"{base}-{number}"
        current = os.stat(PLUGIN_ID, dir_fd=parentfd, follow_symlinks=False)
        if not _same_node(current, target_info):
            raise ValueError(
                "Installed plugin path was replaced; refusing to remove it"
            )
        _check_directory(current, owner, False, PLUGIN_ID)
        try:
            _rename_noreplace(parentfd, PLUGIN_ID, parentfd, backup)
        except FileExistsError:
            continue
        moved = os.stat(backup, dir_fd=parentfd, follow_symlinks=False)
        if not _same_node(moved, target_info):
            raise ValueError("Backup path identity changed; refusing cleanup")
        _check_directory(moved, owner, False, backup)
        os.fsync(parentfd)
        # targetfd remains open and anchors the exact inode that was moved.
        if not _same_node(os.fstat(targetfd), moved):
            raise ValueError("Installed plugin inode changed during backup")
        return backup
    raise FileExistsError(errno.EEXIST, "Could not reserve plugin backup name", base)


def uninstall():
    """Disable the plugin and move its opaque tree to a safe native-style backup."""
    owner, home = _normal_user()
    parent_path = _target_parent(home)
    try:
        parentfd = open_directory(parent_path, owner, create=False)
    except FileNotFoundError:
        print("Plugin is not installed.")
        return
    targetfd = None
    try:
        _verify_directory_path(parent_path, parentfd, owner)
        try:
            target_info = os.stat(PLUGIN_ID, dir_fd=parentfd, follow_symlinks=False)
        except FileNotFoundError:
            print("Plugin is not installed.")
            return
        if stat.S_ISLNK(target_info.st_mode):
            raise ValueError("Installed path is a symlink; inspect it before removal.")
        _check_directory(target_info, owner, False, PLUGIN_ID)
        targetfd = os.open(PLUGIN_ID, DIRECTORY_FLAGS, dir_fd=parentfd)
        held_target = os.fstat(targetfd)
        if not _same_node(target_info, held_target):
            raise ValueError("Installed plugin path was replaced; refusing removal")
        _check_directory(held_target, owner, False, PLUGIN_ID)
        raw_manifest = read_regular(
            targetfd, "manifest.json", {owner}, _MAX_INSTALL_FILE_BYTES
        )
        try:
            manifest = json.loads(raw_manifest.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("Installed manifest is not valid UTF-8 JSON") from error
        if not isinstance(manifest, dict) or manifest.get("id") != PLUGIN_ID:
            raise ValueError("Installed manifest does not match; refusing removal.")

        # Native `plugin remove` uses rm -rf for git checkouts and pathname mv
        # for others.  Both can be redirected after an identity check.  The
        # native IPC is retained for settings semantics; the whole tree is
        # then moved atomically without traversing any child (including .git).
        _verify_directory_path(parent_path, parentfd, owner)
        _disable_native_record()
        _verify_directory_path(parent_path, parentfd, owner)
        backup = _move_to_backup(parentfd, targetfd, held_target, owner)
        _verify_directory_path(parent_path, parentfd, owner)
        run("omarchy-shell", "shell", "rescanPlugins", timeout=30, desktop=True)
        print(f"Removed {PLUGIN_ID}. Backup at: {parent_path / backup}")
        print(
            "Shared packages are intentionally retained. No PipeWire configuration was changed."
        )
    finally:
        if targetfd is not None:
            os.close(targetfd)
        os.close(parentfd)


def doctor():
    """Report package, service, discovery, and receiver health."""
    owner, _ = _normal_user()
    sourcefd = open_directory(_source_path(), owner, final_allow_root=True)
    try:
        version = _manifest(sourcefd, owner)["version"]
    finally:
        os.close(sourcefd)
    checks = {}
    for package in ("pipewire", "pipewire-zeroconf", "wireplumber", "avahi"):
        checks[package] = (
            run("pacman", "-Q", package, check=False, timeout=30).returncode == 0
        )
    checks["avahi-running"] = (
        run(
            "systemctl",
            "is-active",
            "--quiet",
            "avahi-daemon.service",
            check=False,
            timeout=30,
        ).returncode
        == 0
    )
    status = run(
        "omarchy-shell", "omarchyair", "status", check=False, timeout=30, desktop=True
    )
    try:
        service = json.loads(status.stdout) if status.returncode == 0 else None
    except (TypeError, ValueError) as error:
        raise ValueError("Discovery service returned invalid status JSON") from error
    checks["discovery-ready"] = bool(service and service.get("ready"))
    checks["service-version"] = bool(service and service.get("version") == version)
    sinks = json.loads(
        run("pactl", "-f", "json", "list", "sinks", timeout=30, desktop=True).stdout
    )
    receivers = [
        {
            "name": sink["name"],
            "description": sink["description"],
            "state": sink["state"],
        }
        for sink in sinks
        if sink["name"].startswith("raop_sink.")
    ]
    checks["receivers-discovered"] = bool(receivers)
    default_sink = run(
        "pactl", "get-default-sink", timeout=30, desktop=True
    ).stdout.strip()
    print(
        json.dumps(
            {
                "checks": checks,
                "service": service,
                "receivers": receivers,
                "defaultSink": default_sink,
                "note": "A discovered or RUNNING sink does not prove audible playback.",
            },
            indent=2,
        )
    )
    return 0 if all(checks.values()) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="command", required=True)
    for action in ("install", "uninstall", "doctor", "discover", "install-dependency"):
        actions.add_parser(action)
    network_parser = actions.add_parser(
        "network", help="Explicit privileged LAN preparation"
    )
    network_actions = network_parser.add_subparsers(dest="action", required=True)
    enable_parser = network_actions.add_parser("enable")
    enable_parser.add_argument("--interface", required=True)
    enable_parser.add_argument("--subnet", required=True)
    enable_parser.add_argument("--mdns", action="store_true")
    enable_parser.add_argument("--avahi", action="store_true")
    network_actions.add_parser("disable")
    args = parser.parse_args()
    if not sys.flags.isolated:
        parser.error(
            "Use /usr/bin/python3 -I omarchyair.py; isolated Python is required"
        )
    interpreter = os.stat(fixed_executable("python3"))
    actual = os.stat("/proc/self/exe")
    if (actual.st_dev, actual.st_ino) != (interpreter.st_dev, interpreter.st_ino):
        parser.error("Use the packaged /usr/bin/python3 interpreter")
    os.umask(0o077)
    if args.command in ("network", "install-dependency"):
        if os.geteuid() != 0:
            parser.error(
                "Network and dependency changes require explicit sudo or pkexec"
            )
        environment = closed_environment()
        os.environ.clear()
        os.environ.update(environment)
        if args.command == "install-dependency":
            result = run(
                "omarchy",
                "pkg",
                "add",
                "pipewire-zeroconf",
                timeout=600,
                output_limit=8 * 1048576,
            )
            print(result.stdout)
        elif args.action == "enable":
            network_enable(args)
        else:
            network_disable()
    else:
        if os.geteuid() == 0:
            parser.error("Run desktop commands as your normal user, never root")
        if args.command == "install":
            install()
        elif args.command == "uninstall":
            uninstall()
        elif args.command == "doctor":
            return doctor()
        else:
            return discover()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        message = str(error)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            message += ": " + error.stderr[:512]
        print("Omarchy Air: " + message[:1024], file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print(
            "Omarchy Air: interrupted; recorded network state is retained",
            file=sys.stderr,
        )
        sys.exit(130)
