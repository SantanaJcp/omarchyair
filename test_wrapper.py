"""Exercise wrapper import side effects and errors without requiring root."""

from pathlib import Path
import subprocess
import tempfile
import unittest


class PackagedWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.package = Path(self.temporary.name)
        self.wrapper = Path(__file__).resolve().parent / "omarchyair-helper"

    def invoke(self, helper):
        (self.package / "omarchyair_helper.py").write_text(helper)
        # The fixture stands in for an already validated package tree. This
        # subprocess keeps sys.path, module caches and signals suite-isolated.
        harness = (
            "import importlib.machinery,sys,types; "
            "wrapper=types.ModuleType('installed_wrapper'); "
            "importlib.machinery.SourceFileLoader('installed_wrapper',sys.argv[1])"
            ".exec_module(wrapper); "
            "wrapper._PACKAGE_ROOT=sys.argv[2]; "
            "wrapper._validate_installation=lambda: None; "
            "raise SystemExit(wrapper.main())"
        )
        return subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-c",
                harness,
                str(self.wrapper),
                str(self.package),
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )

    def test_execution_leaves_no_unowned_bytecode_in_package_directory(self):
        result = self.invoke("def main():\n    return 0\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            {entry.name for entry in self.package.iterdir()}, {"omarchyair_helper.py"}
        )

    def test_command_failure_preserves_the_actual_diagnostic(self):
        operation = self.package / "operation.py"
        operation.write_text(
            "import sys\nsys.stderr.write('policy rejected by firewall\\n')\nsys.exit(3)\n"
        )
        result = self.invoke(
            "import subprocess,sys\ndef main():\n"
            f"    subprocess.run([sys.executable,'-I',{str(operation)!r}], "
            "check=True,capture_output=True,text=True)\n"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("policy rejected by firewall", result.stderr)

    def test_interrupt_has_an_explicit_exit_status_without_traceback(self):
        result = self.invoke(
            "import os,signal\ndef main():\n    os.kill(os.getpid(),signal.SIGINT)\n"
        )
        self.assertEqual(result.returncode, 130)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
