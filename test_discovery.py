"""Supervision contracts with real pipe-connected subprocesses, no audio hardware."""

from contextlib import redirect_stdout
import io
import os
import subprocess
import unittest
from unittest.mock import patch

import omarchyair as air


class DiscoverySupervisionTests(unittest.TestCase):
    def supervise(self, code, expected):
        lease_r, lease_w = os.pipe()
        child = air.ManagedProcess(("python3", "-I", "-u", "-c", code), timeout=3)
        output = io.StringIO()
        try:
            with redirect_stdout(output), self.assertRaisesRegex(ValueError, expected):
                air._supervise_discovery(
                    child, lease_r, startup_timeout=0.5, lease_timeout=1
                )
        finally:
            os.close(lease_r)
            os.close(lease_w)
        return output.getvalue()

    def test_registry_diagnostic_does_not_override_acknowledged_module(self):
        code = (
            "import sys,time; sys.stdin.readline(); "
            'print("Error: unsupported registry interface",file=sys.stderr); '
            'print("1 = @module:7"); time.sleep(10)'
        )
        output = self.supervise(code, "Shell lease expired")
        self.assertEqual(output, '{"ready":true}\n')

    def test_alive_process_without_module_acknowledgement_is_not_ready(self):
        code = (
            "import sys,time; sys.stdin.readline(); "
            'print("Error: Could not load module",file=sys.stderr); time.sleep(10)'
        )
        output = self.supervise(
            code, "acknowledgement timed out: Error: Could not load module"
        )
        self.assertEqual(output, "")

    def test_unterminated_backend_line_is_bounded_before_forwarding(self):
        code = 'import os,time; os.write(2,b"x"*16384); time.sleep(10)'
        output = self.supervise(code, "output line exceeds")
        self.assertEqual(output, "")

    def test_missing_receiver_metadata_is_a_controlled_error(self):
        def response(*command, **kwargs):
            data = '[{"name":"raop_sink.example"}]' if command[0] == "pactl" else "{}"
            return subprocess.CompletedProcess(command, 0, data, "")

        with (
            patch.object(air, "run", side_effect=response),
            patch.object(air, "validate_helper", return_value=None),
            self.assertRaises(ValueError),
        ):
            air.doctor()


if __name__ == "__main__":
    unittest.main()
