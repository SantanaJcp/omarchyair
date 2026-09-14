"""Real-filesystem safety checks for the descriptor-safe installer helpers."""

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from unittest.mock import patch

import omarchyair as installer


class InstallHost:
    def __init__(self, *, package_present=True, avahi_running=True):
        self.package_present = package_present
        self.avahi_running = avahi_running
        self.calls = []

    def run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        returncode = 0
        if args[:3] == ("pacman", "-Q", "pipewire-zeroconf"):
            returncode = 0 if self.package_present else 1
        elif args[:3] == ("systemctl", "is-active", "--quiet"):
            returncode = 0 if self.avahi_running else 1
        return subprocess.CompletedProcess(args, returncode, "", "")


class InstallerFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.home())
        self.root = Path(self.temporary.name)
        self.source = self.root / "checkout"
        self.plugins = self.root / "config" / "omarchy" / "plugins"
        self.source.mkdir(mode=0o700)
        self.plugins.mkdir(mode=0o700, parents=True)
        for directory in (
            self.root,
            self.source,
            self.root / "config",
            self.root / "config" / "omarchy",
            self.plugins,
        ):
            directory.chmod(0o700)
        for name in installer.FILES:
            (self.source / name).write_bytes(f"payload:{name}\n".encode())
            (self.source / name).chmod(0o600)
        self.owner = os.getuid()

    def tearDown(self):
        self.temporary.cleanup()

    def publish(self):
        sourcefd = installer.open_directory(self.source, self.owner)
        try:
            parentfd = installer.open_directory(self.plugins, self.owner)
            try:
                return installer._publish_files(
                    sourcefd, parentfd, os.fstat(sourcefd), self.owner
                )
            finally:
                os.close(parentfd)
        finally:
            os.close(sourcefd)

    def prepare_install_source(self):
        (self.source / "manifest.json").write_text(
            json.dumps({"id": installer.PLUGIN_ID, "version": "0.3.1"})
        )

    def install_failure(self, host):
        with (
            patch.object(installer, "SOURCE", self.source),
            patch.object(
                installer, "_normal_user", return_value=(self.owner, self.root)
            ),
            patch.object(installer, "ensure_helper", return_value=None),
            patch.object(installer, "run", side_effect=host.run),
        ):
            with self.assertRaises(ValueError) as failure:
                installer.install()
        return failure.exception

    def test_missing_package_stops_before_publication_or_enablement(self):
        self.prepare_install_source()
        host = InstallHost(package_present=False)

        failure = self.install_failure(host)

        self.assertIn("pipewire-zeroconf", str(failure))
        target = self.root / ".config" / "omarchy" / "plugins" / installer.PLUGIN_ID
        self.assertFalse(target.exists())
        self.assertFalse(
            any(args[:3] == ("omarchy", "plugin", "enable") for args, _ in host.calls)
        )
        self.assertFalse(any(args[:2] == ("omarchy", "pkg") for args, _ in host.calls))
        self.assertFalse(any(args and args[0] == "systemctl" for args, _ in host.calls))

    def test_inactive_avahi_stops_before_publication_or_enablement(self):
        self.prepare_install_source()
        host = InstallHost(package_present=True, avahi_running=False)

        failure = self.install_failure(host)

        self.assertIn("Avahi", str(failure))
        target = self.root / ".config" / "omarchy" / "plugins" / installer.PLUGIN_ID
        self.assertFalse(target.exists())
        self.assertFalse(
            any(args[:3] == ("omarchy", "plugin", "enable") for args, _ in host.calls)
        )
        self.assertFalse(any(args[:2] == ("omarchy", "pkg") for args, _ in host.calls))
        self.assertFalse(
            any(
                args[:2] in {("systemctl", "start"), ("systemctl", "enable")}
                for args, _ in host.calls
            )
        )

    def test_existing_target_is_not_overwritten(self):
        target = self.plugins / installer.PLUGIN_ID
        target.mkdir(mode=0o700)
        marker = target / "user-data"
        marker.write_bytes(b"keep me")
        marker.chmod(0o600)

        with self.assertRaises(ValueError):
            self.publish()

        self.assertEqual(marker.read_bytes(), b"keep me")
        self.assertFalse(
            any(
                path.name.startswith(".omarchyair.install.")
                for path in self.plugins.iterdir()
            )
        )

    def test_target_symlink_is_rejected_without_touching_referent(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        marker = outside / "marker"
        marker.write_bytes(b"outside")
        marker.chmod(0o600)
        (self.plugins / installer.PLUGIN_ID).symlink_to(
            outside, target_is_directory=True
        )

        with self.assertRaises(ValueError):
            self.publish()

        self.assertEqual(marker.read_bytes(), b"outside")
        self.assertTrue((self.plugins / installer.PLUGIN_ID).is_symlink())

    def test_writable_ancestor_is_rejected(self):
        unsafe = self.root / "config" / "omarchy"
        unsafe.chmod(0o777)
        try:
            with self.assertRaises(ValueError):
                self.publish()
        finally:
            unsafe.chmod(0o700)

    def test_source_symlink_is_rejected(self):
        (self.source / "Service.qml").unlink()
        (self.source / "Service.qml").symlink_to(self.source / "manifest.json")

        with self.assertRaises((ValueError, OSError)):
            self.publish()

        self.assertFalse((self.plugins / installer.PLUGIN_ID).exists())

    def test_rename_noreplace_preserves_existing_target(self):
        target = self.plugins / installer.PLUGIN_ID
        target.mkdir(mode=0o700)
        marker = target / "marker"
        marker.write_bytes(b"original")
        marker.chmod(0o600)

        parentfd = installer.open_directory(self.plugins, self.owner, create=False)
        stage_name = stagefd = None
        try:
            stage_name, stagefd, stage_info = installer._new_stage(parentfd, self.owner)
            with self.assertRaises(FileExistsError):
                installer._rename_noreplace(
                    parentfd, stage_name, parentfd, installer.PLUGIN_ID
                )
            installer._cleanup_stage(
                stagefd, parentfd, stage_name, stage_info, {}, self.owner
            )
        finally:
            if stagefd is not None:
                os.close(stagefd)
            os.close(parentfd)

        self.assertEqual(marker.read_bytes(), b"original")
        self.assertTrue(target.is_dir())
        self.assertFalse((self.plugins / stage_name).exists())

    def test_cleanup_refuses_replaced_staging_file(self):
        parentfd = installer.open_directory(self.plugins, self.owner, create=False)
        stagefd = None
        try:
            stage_name, stagefd, stage_info = installer._new_stage(parentfd, self.owner)
            # Use the held stage fd so the test exercises the same identity
            # check as an interrupted install, not a pathname cleanup helper.
            fd = os.open(
                "created", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=stagefd
            )
            os.write(fd, b"created")
            os.fsync(fd)
            created_info = os.fstat(fd)
            os.close(fd)
            outside = self.root / "cleanup-outside"
            outside.mkdir(mode=0o700)
            marker = outside / "marker"
            marker.write_bytes(b"untouched")
            marker.chmod(0o600)
            os.unlink("created", dir_fd=stagefd)
            os.symlink(outside, "created", dir_fd=stagefd)

            with self.assertRaises(ValueError):
                installer._cleanup_stage(
                    stagefd,
                    parentfd,
                    stage_name,
                    stage_info,
                    {"created": (created_info.st_dev, created_info.st_ino)},
                    self.owner,
                )
            self.assertEqual(marker.read_bytes(), b"untouched")
            self.assertTrue((self.plugins / stage_name).is_dir())
        finally:
            if stagefd is not None:
                os.close(stagefd)
            os.close(parentfd)

    def test_uninstall_backup_moves_opaque_tree_without_recursive_delete(self):
        self.publish()
        target = self.plugins / installer.PLUGIN_ID
        opaque = target / ".git" / "objects"
        opaque.mkdir(mode=0o700, parents=True)
        opaque_file = opaque / "unrelated"
        opaque_file.write_bytes(b"opaque data")
        opaque_file.chmod(0o600)

        parentfd = installer.open_directory(self.plugins, self.owner, create=False)
        targetfd = None
        try:
            target_info = os.stat(
                installer.PLUGIN_ID, dir_fd=parentfd, follow_symlinks=False
            )
            targetfd = os.open(
                installer.PLUGIN_ID, installer.DIRECTORY_FLAGS, dir_fd=parentfd
            )
            backup = installer._move_to_backup(
                parentfd, targetfd, target_info, self.owner
            )
        finally:
            if targetfd is not None:
                os.close(targetfd)
            os.close(parentfd)

        self.assertFalse(target.exists())
        backup_path = self.plugins / backup
        self.assertTrue(backup_path.is_dir())
        self.assertEqual(
            (backup_path / ".git" / "objects" / "unrelated").read_bytes(),
            b"opaque data",
        )
        self.assertTrue(stat.S_ISDIR(backup_path.stat().st_mode))

    def test_interruption_after_atomic_publish_does_not_empty_live_plugin(self):
        rename = installer._rename_noreplace

        def interrupt_after_rename(*args):
            rename(*args)
            raise KeyboardInterrupt

        with patch.object(installer, "_rename_noreplace", interrupt_after_rename):
            with self.assertRaises(KeyboardInterrupt):
                self.publish()
        target = self.plugins / installer.PLUGIN_ID
        for name in installer.FILES:
            self.assertEqual(
                (target / name).read_bytes(), (self.source / name).read_bytes()
            )

    def test_group_writable_payload_helper_is_rejected_before_external_execution(
        self,
    ):
        (self.source / "manifest.json").write_text(
            json.dumps(
                {
                    "id": installer.PLUGIN_ID,
                    "version": "0.3.1",
                }
            )
        )
        (self.source / "omarchyair.py").chmod(0o660)
        with (
            patch.object(installer, "SOURCE", self.source),
            patch.object(
                installer, "_normal_user", return_value=(self.owner, self.root)
            ),
            patch.object(
                installer,
                "run",
                side_effect=AssertionError("Unsafe external execution"),
            ),
        ):
            with self.assertRaises(ValueError):
                installer.install()


if __name__ == "__main__":
    unittest.main()
