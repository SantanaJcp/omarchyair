#!/usr/bin/python3 -I
"""Shared bounded execution and filesystem primitives for Omarchy Air."""

import ctypes
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
        "omarchyair-helper",
        "pacman-key",
        "gpg",
        "pacman-conf",
        "timeout",
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


def _guardian(argv, environment, pipes, parent_pid, timeout, interactive, piped_stdin):
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
            stdin=in_r if not interactive or piped_stdin else None,
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

    def __init__(
        self, args, *, timeout=30, desktop=False, interactive=False, piped_stdin=False
    ):
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
            _guardian(
                argv, environment, pipes, parent_pid, timeout, interactive, piped_stdin
            )
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
    input_data=None,
):
    if not 0 < output_limit <= 8 * 1048576:
        raise ValueError("Invalid command output budget")
    if input_data is not None and (
        not isinstance(input_data, bytes) or len(input_data) > 4096
    ):
        raise ValueError("Command input must be immutable bytes, at most 4096 bytes")
    child = ManagedProcess(
        args,
        timeout=timeout,
        desktop=desktop,
        interactive=interactive,
        piped_stdin=input_data is not None,
    )
    buffers = {child.stdout: bytearray(), child.stderr: bytearray()}
    deadline = time.monotonic() + timeout
    count = 0
    try:
        if input_data:
            child.send(input_data)
        if not interactive or input_data is not None:
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
