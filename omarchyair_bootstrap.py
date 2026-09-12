#!/usr/bin/python3 -I
"""Normal-user bootstrap for the signed, root-owned Omarchy Air helper."""

import json
import os
import re
import stat
import tempfile

from omarchyair_runtime import fixed_executable, open_directory, read_regular, run


__all__ = ("ensure_helper", "validate_helper")

_HELPER_ENTRY = "/usr/bin/omarchyair-helper"
_MODULE_ROOT = "/usr/lib/omarchyair"
_MODULE_FILES = ("omarchyair_helper.py", "omarchyair_runtime.py")
_PUBLIC_KEY = "signing-key.asc"
_KEY_LIMIT = 4096
_PROTOCOL_LIMIT = 4096
_GPG_OUTPUT_LIMIT = 64 * 1024
_POLICY_OUTPUT_LIMIT = 4096
_PACKAGE_OUTPUT_LIMIT = 8 * 1024 * 1024
_PROTOCOL_TIMEOUT = 30
_PREFLIGHT_TIMEOUT = 30
_BOOTSTRAP_TIMEOUT = 900

_FINGERPRINT_RE = re.compile(r"[0-9A-F]{40}")
_VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate protocol field")
        result[key] = value
    return result


class _UnsafeInstallation(ValueError):
    """A path in the fixed helper tree is not safe to inspect or execute."""


def _validate_fingerprint(value):
    if not isinstance(value, str) or _FINGERPRINT_RE.fullmatch(value) is None:
        raise ValueError(
            "The embedded signing fingerprint must be exactly 40 uppercase hexadecimal characters"
        )
    return value


def _validate_version(value):
    if not isinstance(value, str) or _VERSION_RE.fullmatch(value) is None:
        raise ValueError(
            "The helper version must be a numeric semantic version such as 0.3.0"
        )
    return value


def _check_normal_user(owner):
    if not isinstance(owner, int) or isinstance(owner, bool) or owner < 1:
        raise ValueError("Helper bootstrap requires a normal-user owner id")
    if os.geteuid() == 0 or os.getuid() != owner or os.geteuid() != os.getuid():
        raise ValueError("Helper bootstrap must run as the owning normal user")


def _check_directory(fd, path):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        raise _UnsafeInstallation(f"Fixed helper path is not a directory: {path}")
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise _UnsafeInstallation(
            f"Fixed helper directory is not root-owned and nonwritable: {path}"
        )
    return info


def _check_file(fd, path, executable=False):
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
        or info.st_mode & (stat.S_ISUID | stat.S_ISGID)
        or info.st_nlink != 1
        or (executable and not info.st_mode & 0o111)
    ):
        raise _UnsafeInstallation(
            f"Fixed helper file is not root-owned and nonwritable: {path}"
        )
    return info


def _open_parent(path):
    parent, name = os.path.split(path)
    try:
        return open_directory(parent, 0), name
    except (OSError, ValueError) as error:
        raise _UnsafeInstallation(
            f"Cannot safely inspect fixed helper path: {path}"
        ) from error


def _open_fixed_file(path, *, executable=False, allow_missing=False):
    parent, name = _open_parent(path)
    try:
        try:
            fd = os.open(name, _FILE_FLAGS, dir_fd=parent)
        except FileNotFoundError as error:
            if allow_missing:
                return None
            raise _UnsafeInstallation(f"Missing fixed helper file: {path}") from error
        except (OSError, ValueError) as error:
            raise _UnsafeInstallation(
                f"Cannot safely inspect fixed helper file: {path}"
            ) from error
        try:
            _check_file(fd, path, executable=executable)
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)


def _open_fixed_directory(path, *, allow_missing=False):
    parent, name = _open_parent(path)
    try:
        try:
            fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
        except FileNotFoundError as error:
            if allow_missing:
                return None
            raise _UnsafeInstallation(
                f"Missing fixed helper directory: {path}"
            ) from error
        except (OSError, ValueError) as error:
            raise _UnsafeInstallation(
                f"Cannot safely inspect fixed helper directory: {path}"
            ) from error
        try:
            _check_directory(fd, path)
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)


def _inspect_tree():
    """Validate every fixed helper path, returning False only for no install."""
    entry = module_root = None
    try:
        entry = _open_fixed_file(_HELPER_ENTRY, executable=True, allow_missing=True)
        module_root = _open_fixed_directory(_MODULE_ROOT, allow_missing=True)
        if entry is None and module_root is None:
            return False
        if entry is None or module_root is None:
            raise _UnsafeInstallation(
                "Incomplete fixed helper installation; refusing repair"
            )
        for name in _MODULE_FILES:
            path = f"{_MODULE_ROOT}/{name}"
            module = _open_fixed_file(path, allow_missing=True)
            if module is None:
                raise _UnsafeInstallation(
                    f"Incomplete fixed helper installation: {path}"
                )
            os.close(module)
    finally:
        if entry is not None:
            os.close(entry)
        if module_root is not None:
            os.close(module_root)
    return True


def _protocol_version(version):
    try:
        result = run(
            "omarchyair-helper",
            "protocol",
            timeout=_PROTOCOL_TIMEOUT,
            output_limit=_PROTOCOL_LIMIT,
        )
    except Exception as error:
        raise ValueError(f"Installed helper protocol failed: {error}") from error
    try:
        payload = json.loads(result.stdout.strip(), object_pairs_hook=_json_object)
    except (TypeError, ValueError) as error:
        raise ValueError("Installed helper returned invalid protocol JSON") from error
    if not isinstance(payload, dict) or set(payload) != {"api", "version"}:
        raise ValueError("Installed helper returned an unexpected protocol shape")
    api = payload.get("api")
    if type(api) is not int or api != 1:
        raise ValueError("Installed helper protocol API is unsupported")
    reported = payload.get("version")
    if not isinstance(reported, str) or _VERSION_RE.fullmatch(reported) is None:
        raise ValueError("Installed helper returned an invalid protocol version")
    if tuple(map(int, reported.split("."))) > tuple(map(int, version.split("."))):
        raise ValueError(
            f"Installed helper {reported} is newer than required {version}; "
            "refusing a privileged downgrade. Update the plugin checkout."
        )
    if reported != version:
        raise FileNotFoundError(
            f"Installed helper version {reported} does not match required {version}"
        )


def validate_helper(version):
    """Validate the fixed helper tree and protocol, or raise on failure."""
    _validate_version(version)
    if not _inspect_tree():
        raise FileNotFoundError("Omarchy Air helper is not installed")
    _protocol_version(version)


def _check_source_fd(sourcefd, owner):
    try:
        info = os.fstat(sourcefd)
    except OSError as error:
        raise ValueError("Invalid held plugin source directory") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in {owner, 0}
        or info.st_mode & 0o022
    ):
        raise ValueError("Plugin source directory is not owned and nonwritable")


def _gpg_primary_fingerprint(output):
    primary = []
    awaiting = False
    for line in output.splitlines():
        fields = line.split(":")
        if not fields or fields[0] == "":
            continue
        if fields[0] == "pub":
            if awaiting:
                raise ValueError("Signing key fingerprint output is malformed")
            awaiting = True
        elif fields[0] == "fpr" and awaiting:
            if len(fields) <= 9:
                raise ValueError("Signing key fingerprint output is malformed")
            primary.append(fields[9])
            awaiting = False
    if awaiting or len(primary) != 1:
        raise ValueError("Signing key must contain exactly one primary fingerprint")
    if _FINGERPRINT_RE.fullmatch(primary[0]) is None:
        raise ValueError("Signing key primary fingerprint is not canonical")
    return primary[0]


def _verify_public_key(key_data, signing_fingerprint):
    with tempfile.TemporaryDirectory(prefix=".omarchyair-gpg-") as home:
        os.chmod(home, 0o700)
        result = run(
            "gpg",
            "--no-options",
            "--batch",
            "--homedir",
            home,
            "--with-colons",
            "--import-options",
            "show-only",
            "--dry-run",
            "--import",
            timeout=_PREFLIGHT_TIMEOUT,
            output_limit=_GPG_OUTPUT_LIMIT,
            input_data=key_data,
        )
    if _gpg_primary_fingerprint(result.stdout) != signing_fingerprint:
        raise ValueError(
            "Public signing key fingerprint does not match the embedded fingerprint"
        )


def _pacman_conf(name):
    try:
        result = run(
            "pacman-conf",
            name,
            timeout=_PREFLIGHT_TIMEOUT,
            output_limit=_POLICY_OUTPUT_LIMIT,
        )
    except Exception as error:
        raise ValueError(
            f"Could not inspect pacman {name} signature policy; "
            "refusing to install without verified package signatures"
        ) from error
    return result.stdout.strip()


def _remote_signature_policy():
    output = _pacman_conf("RemoteFileSigLevel")
    if not output:
        # An empty RemoteFileSigLevel inherits the effective package policy.
        output = _pacman_conf("SigLevel")
    policy = output.replace(",", " ").split()
    required = {"Required", "PackageRequired"} & set(policy)
    trusted = {"TrustedOnly", "PackageTrustedOnly"} & set(policy)
    weak = {
        "Never",
        "Optional",
        "TrustAll",
        "TrustAllSignatures",
        "PackageNever",
        "PackageOptional",
        "PackageTrustAll",
    } & set(policy)
    if not required or not trusted:
        raise ValueError(
            "pacman RemoteFileSigLevel must require signed, trusted packages; "
            "set Required TrustedOnly in pacman.conf and retry"
        )
    if weak:
        raise ValueError(
            "pacman RemoteFileSigLevel is weaker than Required TrustedOnly; "
            "strengthen pacman.conf and retry without disabling signature checks"
        )


def _require_fixed_tools():
    for name in (
        "gpg",
        "pacman-conf",
        "sudo",
        "env",
        "timeout",
        "pacman-key",
        "pacman",
    ):
        try:
            fixed_executable(name)
        except Exception as error:
            raise ValueError(
                f"Required fixed system executable is unavailable: {name}"
            ) from error


def _foreground_tty():
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise ValueError(
            "Signed helper bootstrap requires a foreground terminal"
        ) from error
    try:
        if not os.isatty(fd) or os.tcgetpgrp(fd) != os.getpgrp():
            raise ValueError("Signed helper bootstrap requires a foreground terminal")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _consent(signing_fingerprint, version):
    fd = _foreground_tty()
    try:
        prompt = (
            f"Omarchy Air will install or upgrade its helper to {version} from:\n"
            f"{_package_url(version)}\n"
            "Required system dependencies (including UFW, Avahi and "
            "pipewire-zeroconf) may also be installed.\n"
            f"Signing key: {signing_fingerprint}\n"
            "This key will be trusted system-wide by pacman for ANY package "
            "signed by it, not only Omarchy Air. Trust is not automatically "
            "removed if installation fails or is interrupted. Continue? [y/N] "
        ).encode("ascii")
        os.write(fd, prompt)
        answer = os.read(fd, 128).strip().lower()
    finally:
        os.close(fd)
    if answer not in (b"y", b"yes"):
        raise ValueError(
            "Signed helper bootstrap cancelled; no package trust was changed"
        )


def _sudo_env(command, *arguments):
    if command not in {"pacman-key", "pacman"}:
        raise ValueError("Unsupported privileged helper command")
    return (
        "sudo",
        "--",
        fixed_executable("env"),
        "-i",
        "PATH=/usr/bin",
        "LC_ALL=C",
        fixed_executable("timeout"),
        "--signal=TERM",
        "--kill-after=1s",
        "600s",
        fixed_executable(command),
        *arguments,
    )


def _run_privileged(command, *arguments, input_data=None):
    return run(
        *_sudo_env(command, *arguments),
        timeout=_BOOTSTRAP_TIMEOUT,
        output_limit=_PACKAGE_OUTPUT_LIMIT,
        interactive=True,
        input_data=input_data,
    )


def _package_url(version):
    return (
        "https://github.com/SantanaJcp/omarchyair/releases/download/"
        f"v{version}/omarchyair-helper-{version}-1-any.pkg.tar.zst"
    )


def ensure_helper(sourcefd, owner, signing_fingerprint, version):
    """Ensure the signed helper is installed and protocol-compatible."""
    _validate_fingerprint(signing_fingerprint)
    _validate_version(version)
    _check_normal_user(owner)

    try:
        validate_helper(version)
    except FileNotFoundError:
        pass
    else:
        return None

    _check_source_fd(sourcefd, owner)
    key_data = read_regular(sourcefd, _PUBLIC_KEY, {owner, 0}, _KEY_LIMIT)
    if not isinstance(key_data, bytes):
        raise ValueError("Public signing key data must be immutable bytes")
    _verify_public_key(key_data, signing_fingerprint)
    _require_fixed_tools()
    _remote_signature_policy()
    _consent(signing_fingerprint, version)

    try:
        _run_privileged("pacman-key", "--add", "-", input_data=key_data)
    except Exception as error:
        raise ValueError(
            f"Could not import the package signing key: {error}"
        ) from error
    try:
        _run_privileged("pacman-key", "--lsign-key", signing_fingerprint)
    except Exception as error:
        raise ValueError(
            "Could not locally trust the package signing key; no automatic key removal was attempted"
        ) from error
    try:
        _run_privileged(
            "pacman",
            "-U",
            "--needed",
            "--noconfirm",
            _package_url(version),
        )
    except Exception as error:
        raise ValueError(
            "Helper package installation failed; the signing key remains trusted in pacman and was not removed"
        ) from error

    try:
        validate_helper(version)
    except (FileNotFoundError, ValueError) as error:
        raise ValueError(
            "Helper package completed but the installed helper failed protocol or safety validation; "
            "the signing key remains trusted in pacman and was not removed"
        ) from error
    return None
