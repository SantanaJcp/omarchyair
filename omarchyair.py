#!/usr/bin/python3 -I
"""Omarchy Air: supervised discovery and setup through a packaged system helper."""

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
import secrets

if os.getuid() == 0 or os.geteuid() == 0:
    raise SystemExit("Run Omarchy Air as your normal user, never root")

# Isolated Python deliberately excludes the script directory. These adjacent
# modules are normal-user plugin code; the root helper imports only its package.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from omarchyair_runtime import (
    DIRECTORY_FLAGS,
    FILE_FLAGS,
    ManagedProcess,
    _file_snapshot,
    fixed_executable,
    open_directory,
    read_regular,
    run,
)
from omarchyair_bootstrap import ensure_helper, validate_helper

SIGNING_FINGERPRINT = "D1E431E8B1F91F6A6C28A0A2B78190C1F45FCB18"


PLUGIN_ID = "community.omarchyair"


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


SOURCE = Path(os.path.abspath(os.path.dirname(__file__)))
FILES = (
    "manifest.json",
    "Service.qml",
    "omarchyair.py",
    "omarchyair_runtime.py",
    "omarchyair_bootstrap.py",
    "signing-key.asc",
    "README.md",
    "LICENSE",
)
_MAX_INSTALL_FILE_BYTES = 1048576
_INSTALL_STAGE_ATTEMPTS = 64
_BACKUP_ATTEMPTS = 1024
_RENAME_NOREPLACE = 1
_DEST_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


def _normal_user():
    """Return the invoking uid and its passwd-database home directory."""
    uid = os.getuid()
    if uid == 0 or os.geteuid() == 0:
        raise ValueError("Run Omarchy Air as the desktop user, not root")
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


def install(args=None):
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
        ensure_helper(sourcefd, owner, SIGNING_FINGERPRINT, manifest["version"])
        _verify_directory_path(source_path, sourcefd, owner, final_allow_root=True)
        if args is not None and args.interface:
            _invoke_network("enable", args, manifest["version"])
        if run("pacman", "-Q", "pipewire-zeroconf", check=False, timeout=30).returncode:
            raise ValueError(
                "The helper package is missing its pipewire-zeroconf dependency. "
                "Repair the package dependencies with the system package manager."
            )
        if run(
            "systemctl",
            "is-active",
            "--quiet",
            "avahi-daemon.service",
            check=False,
            timeout=30,
        ).returncode:
            raise ValueError(
                "Avahi is not running. Use install --interface IF --subnet LAN "
                "--avahi for explicit LAN preparation, or follow the README."
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
    helper_error = None
    try:
        validate_helper(version)
        checks["privileged-helper"] = True
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        checks["privileged-helper"] = False
        helper_error = str(error)[:1024]
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
    if service is not None and not isinstance(service, dict):
        raise ValueError("Discovery service returned an invalid status object")
    checks["discovery-ready"] = bool(service and service.get("ready"))
    checks["service-version"] = bool(service and service.get("version") == version)
    sinks = json.loads(
        run("pactl", "-f", "json", "list", "sinks", timeout=30, desktop=True).stdout
    )
    if not isinstance(sinks, list):
        raise ValueError("PipeWire returned an invalid sink list")
    try:
        receivers = [
            {
                "name": sink["name"],
                "description": sink["description"],
                "state": sink["state"],
            }
            for sink in sinks
            if sink["name"].startswith("raop_sink.")
        ]
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("PipeWire returned malformed sink metadata") from error
    checks["receivers-discovered"] = bool(receivers)
    default_sink = run(
        "pactl", "get-default-sink", timeout=30, desktop=True
    ).stdout.strip()
    print(
        json.dumps(
            {
                "checks": checks,
                "service": service,
                "helperError": helper_error,
                "receivers": receivers,
                "defaultSink": default_sink,
                "note": "A discovered or RUNNING sink does not prove audible playback.",
            },
            indent=2,
        )
    )
    return 0 if all(checks.values()) else 1


def _invoke_network(action, args, version):
    validate_helper(version)
    command = ["network", action]
    if action == "enable":
        command.extend(("--interface", args.interface, "--subnet", args.subnet))
        if args.mdns:
            command.append("--mdns")
        if args.avahi:
            command.append("--avahi")
    result = run(
        "sudo",
        "--",
        fixed_executable("env"),
        "-i",
        "PATH=/usr/bin",
        "LC_ALL=C",
        fixed_executable("timeout"),
        "--signal=TERM",
        "--kill-after=1s",
        "150s",
        fixed_executable("omarchyair-helper"),
        *command,
        timeout=180,
        output_limit=1048576,
        interactive=True,
    )
    print(result.stdout, end="")


def configure_network(args):
    owner, _ = _normal_user()
    sourcefd = open_directory(_source_path(), owner, final_allow_root=True)
    try:
        version = _manifest(sourcefd, owner)["version"]
        ensure_helper(sourcefd, owner, SIGNING_FINGERPRINT, version)
    finally:
        os.close(sourcefd)
    _invoke_network(args.action, args, version)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="command", required=True)
    install_parser = actions.add_parser("install")
    for action in ("uninstall", "doctor", "discover"):
        actions.add_parser(action)
    network_parser = actions.add_parser("network", help="Use the packaged root helper")
    network_actions = network_parser.add_subparsers(dest="action", required=True)
    enable_parser = network_actions.add_parser("enable")
    network_actions.add_parser("disable")
    for target in (install_parser, enable_parser):
        target.add_argument("--interface", required=target is enable_parser)
        target.add_argument("--subnet", required=target is enable_parser)
        target.add_argument("--mdns", action="store_true")
        target.add_argument("--avahi", action="store_true")
    args = parser.parse_args()
    if args.command == "install" and (
        bool(args.interface) != bool(args.subnet)
        or ((args.mdns or args.avahi) and not args.interface)
    ):
        parser.error("Network preparation requires both --interface and --subnet")
    if not sys.flags.isolated:
        parser.error(
            "Use /usr/bin/python3 -I omarchyair.py; isolated Python is required"
        )
    interpreter = os.stat(fixed_executable("python3"))
    actual = os.stat("/proc/self/exe")
    if (actual.st_dev, actual.st_ino) != (interpreter.st_dev, interpreter.st_ino):
        parser.error("Use the packaged /usr/bin/python3 interpreter")
    os.umask(0o077)
    if os.getuid() == 0 or os.geteuid() == 0:
        parser.error("Run Omarchy Air as your normal user, never root")
    if args.command == "install":
        install(args)
    elif args.command == "uninstall":
        uninstall()
    elif args.command == "doctor":
        return doctor()
    elif args.command == "network":
        configure_network(args)
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
        print("Omarchy Air: interrupted", file=sys.stderr)
        sys.exit(130)
