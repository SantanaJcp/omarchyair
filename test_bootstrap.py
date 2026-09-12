"""Reject untrusted signing inputs and package policy before authorizing root work."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import omarchyair_bootstrap as bootstrap


class BootstrapTrustTests(unittest.TestCase):
    def setUp(self):
        self.source = Path(__file__).resolve().parent
        self.sourcefd = os.open(self.source, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.sourcefd)
        self.key = (self.source / "signing-key.asc").read_bytes()

    def test_wrong_signer_cannot_authorize_bootstrap_even_with_consent(self):
        with (
            patch.object(bootstrap, "validate_helper", side_effect=FileNotFoundError),
            patch.object(bootstrap, "_consent", return_value=None),
            patch.object(
                bootstrap,
                "_run_privileged",
                side_effect=AssertionError("Unexpected privileged mutation"),
            ),
            self.assertRaisesRegex(ValueError, "fingerprint"),
        ):
            bootstrap.ensure_helper(self.sourcefd, os.getuid(), "0" * 40, "0.3.0")

    def test_key_bundle_cannot_import_more_than_the_authorized_signer(self):
        with self.assertRaisesRegex(ValueError, "exactly one primary"):
            bootstrap._verify_public_key(
                self.key + self.key,
                "D1E431E8B1F91F6A6C28A0A2B78190C1F45FCB18",
            )

    def test_remote_unsigned_packages_are_refused(self):
        result = subprocess.CompletedProcess(
            (), 0, "PackageOptional\nPackageTrustedOnly\n", ""
        )
        with patch.object(bootstrap, "run", return_value=result):
            with self.assertRaises(ValueError):
                bootstrap._remote_signature_policy()

    def test_signed_but_untrusted_packages_are_refused(self):
        result = subprocess.CompletedProcess(
            (), 0, "PackageRequired\nPackageTrustAll\n", ""
        )
        with patch.object(bootstrap, "run", return_value=result):
            with self.assertRaises(ValueError):
                bootstrap._remote_signature_policy()

    def test_user_owned_helper_tree_is_not_repaired_or_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            entry = Path(directory) / "omarchyair-helper"
            entry.write_text("#!/usr/bin/python3 -I\nraise SystemExit(0)\n")
            entry.chmod(0o755)
            with (
                patch.object(bootstrap, "_HELPER_ENTRY", str(entry)),
                patch.object(bootstrap, "_consent", return_value=None),
                patch.object(
                    bootstrap,
                    "_run_privileged",
                    side_effect=AssertionError("Unexpected privileged mutation"),
                ),
                self.assertRaises(bootstrap._UnsafeInstallation),
            ):
                bootstrap.ensure_helper(
                    self.sourcefd,
                    os.getuid(),
                    "D1E431E8B1F91F6A6C28A0A2B78190C1F45FCB18",
                    "0.3.0",
                )

    def test_version_mismatch_distinguishes_upgrade_from_downgrade(self):
        result = subprocess.CompletedProcess((), 0, '{"api":1,"version":"0.10.0"}', "")
        with (
            patch.object(bootstrap, "_inspect_tree", return_value=True),
            patch.object(bootstrap, "run", return_value=result),
        ):
            with self.assertRaises(ValueError):
                bootstrap.validate_helper("0.9.0")
            with self.assertRaises(FileNotFoundError):
                bootstrap.validate_helper("0.11.0")


if __name__ == "__main__":
    unittest.main()
