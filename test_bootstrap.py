"""Reject substituted package bytes and untrusted signatures before installation."""

import hashlib
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

    def test_replaced_release_payload_cannot_authorize_root_work(self):
        with (
            patch.object(bootstrap, "validate_helper", side_effect=FileNotFoundError),
            patch.object(bootstrap, "_consent", return_value=None),
            patch.object(bootstrap, "_download_asset", return_value=b"replacement"),
            patch.object(
                bootstrap,
                "_run_privileged",
                side_effect=SystemExit("Replacement reached privileged execution"),
            ),
            self.assertRaises(ValueError),
        ):
            bootstrap.ensure_helper(
                self.sourcefd,
                os.getuid(),
                "D1E431E8B1F91F6A6C28A0A2B78190C1F45FCB18",
                next(iter(bootstrap._RELEASE_DIGESTS)),
            )

    def test_substituted_signature_cannot_reach_a_privileged_parser(self):
        package = b"reviewed-package"
        pins = (
            hashlib.sha256(package).hexdigest(),
            hashlib.sha256(b"reviewed-signature").hexdigest(),
        )
        with (
            patch.object(bootstrap, "validate_helper", side_effect=FileNotFoundError),
            patch.object(bootstrap, "_consent", return_value=None),
            patch.object(bootstrap, "_RELEASE_DIGESTS", {"0.3.1": pins}),
            patch.object(
                bootstrap,
                "_download_asset",
                side_effect=[package, b"replacement-signature"],
            ),
            patch.object(
                bootstrap,
                "_run_privileged",
                side_effect=SystemExit("Unverified signature reached root"),
            ),
            self.assertRaises(ValueError),
        ):
            bootstrap.ensure_helper(
                self.sourcefd,
                os.getuid(),
                "D1E431E8B1F91F6A6C28A0A2B78190C1F45FCB18",
                "0.3.1",
            )

    def test_non_https_download_fails_with_a_controlled_text_error(self):
        with self.assertRaises(ValueError):
            bootstrap._download_asset("file:///dev/null", 1024)

    def test_unpinned_version_cannot_download_a_package(self):
        with (
            patch.object(
                bootstrap,
                "_download_asset",
                side_effect=AssertionError("Unpinned version reached download"),
            ),
            self.assertRaisesRegex(ValueError, "No pinned package"),
        ):
            bootstrap._download_package("99.0.0")

    def test_untrusted_signature_is_rejected_even_when_cryptographically_valid(self):
        fingerprint = "D1E431E8B1F91F6A6C28A0A2B78190C1F45FCB18"
        status = (
            f"[GNUPG:] GOODSIG {fingerprint[-16:]} Project\n"
            f"[GNUPG:] VALIDSIG {fingerprint} 2026-09-13 1 0 4 0 22 8 00 {fingerprint}\n"
            "[GNUPG:] TRUST_UNDEFINED 0 pgp\n"
        )
        with (
            patch.object(
                bootstrap,
                "_run_privileged",
                return_value=subprocess.CompletedProcess((), 0, status, ""),
            ),
            self.assertRaises(ValueError),
        ):
            bootstrap._verify_staged_signature("package", "signature", fingerprint)

    def test_trusted_signature_from_another_primary_key_is_rejected(self):
        fingerprint = "D1E431E8B1F91F6A6C28A0A2B78190C1F45FCB18"
        status = (
            f"[GNUPG:] GOODSIG {'0' * 16} Other\n"
            f"[GNUPG:] VALIDSIG {'0' * 40} 2026-09-13 1 0 4 0 22 8 00 {'0' * 40}\n"
            "[GNUPG:] TRUST_FULLY 0 pgp\n"
        )
        with (
            patch.object(
                bootstrap,
                "_run_privileged",
                return_value=subprocess.CompletedProcess((), 0, status, ""),
            ),
            self.assertRaises(ValueError),
        ):
            bootstrap._verify_staged_signature("package", "signature", fingerprint)

    def test_user_replaceable_staging_parent_is_rejected_before_root_work(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(bootstrap, "_CACHE_ROOT", directory),
            patch.object(
                bootstrap,
                "_run_privileged",
                side_effect=AssertionError("Unprotected staging parent reached root"),
            ),
            self.assertRaises(ValueError),
        ):
            with bootstrap._staged_package("0.3.1", b"package", b"signature"):
                self.fail("User-controlled stage was accepted")

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
