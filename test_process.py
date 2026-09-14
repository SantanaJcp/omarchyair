"""Exercise real subprocesses; no privileged commands or audio changes."""

import hashlib
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import omarchyair_runtime as air


def alive(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return False
    return text.rsplit(")", 1)[1].split()[0] != "Z"


class ProcessBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def assert_stopped(self, pid):
        deadline = time.monotonic() + 3
        while alive(pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(alive(pid), f"Owned process {pid} survived cleanup")

    def wait_pid(self, path):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                return int(path.read_text())
            except (FileNotFoundError, ValueError):
                time.sleep(0.01)
        self.fail("Child did not publish its PID")

    def test_hostile_path_and_python_startup_environment_do_not_execute(self):
        marker = self.directory / "executed"
        (self.directory / "python3").write_text(f"#!/bin/sh\ntouch {marker}\n")
        (self.directory / "python3").chmod(0o755)
        (self.directory / "sitecustomize.py").write_text(
            f'open({str(marker)!r}, "w").close()'
        )
        poisoned = {
            "PATH": str(self.directory),
            "PYTHONPATH": str(self.directory),
            "PYTHONHOME": str(self.directory),
            "BASH_ENV": str(marker),
            "LD_PRELOAD": str(marker),
            "HOME": str(self.directory),
            "OMARCHY_PATH": str(self.directory),
        }
        with patch.dict(os.environ, poisoned):
            result = air.run(
                "python3",
                "-I",
                "-c",
                "import json,os; print(json.dumps(dict(os.environ)))",
            )
        actual = json.loads(result.stdout)
        self.assertFalse(marker.exists())
        for name in ("PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "BASH_ENV"):
            self.assertNotIn(name, actual)
        self.assertNotEqual(actual["HOME"], str(self.directory))
        self.assertNotEqual(actual["PATH"], str(self.directory))
        self.assertNotEqual(actual.get("OMARCHY_PATH"), str(self.directory))

    def test_deadline_kills_term_resistant_child_and_grandchild(self):
        pidfile = self.directory / "grandchild"
        code = (
            "import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            "pid=os.fork(); "
            f'open({str(pidfile)!r},"w").write(str(os.getpid())) if pid == 0 else None; '
            "time.sleep(60)"
        )
        with self.assertRaises(ValueError):
            air.run("python3", "-I", "-c", code, timeout=0.4)
        self.assert_stopped(self.wait_pid(pidfile))

    def test_live_output_budget_kills_producer_without_newlines(self):
        pidfile = self.directory / "producer"
        code = (
            f'import os; open({str(pidfile)!r},"w").write(str(os.getpid())); '
            '\nwhile True: os.write(2,b"x"*4096)'
        )
        started = time.monotonic()
        with self.assertRaisesRegex(ValueError, "output budget"):
            air.run("python3", "-I", "-c", code, timeout=10, output_limit=8192)
        self.assertLess(time.monotonic() - started, 5)
        self.assert_stopped(self.wait_pid(pidfile))

    def test_large_input_is_streamed_while_slow_reader_emits_output(self):
        payload = bytes(range(256)) * 512
        code = (
            "import hashlib,os,time; digest=hashlib.sha256()\n"
            "while True:\n"
            " chunk=os.read(0,1024)\n"
            " if not chunk: break\n"
            " digest.update(chunk)\n"
            ' os.write(1,b"o"*len(chunk))\n'
            " time.sleep(0.002)\n"
            "os.write(2,digest.hexdigest().encode())"
        )
        result = air.run("python3", "-I", "-c", code, input_data=payload, timeout=5)
        self.assertEqual(result.stdout, "o" * len(payload))
        self.assertEqual(result.stderr, hashlib.sha256(payload).hexdigest())

    def test_binary_output_is_preserved_when_text_is_disabled(self):
        stdout = bytes(range(256)) + b"\x00\xff"
        stderr = b"\xff\x00diagnostic\x80"
        code = f"import os; os.write(1,{stdout!r}); os.write(2,{stderr!r})"
        result = air.run("python3", "-I", "-c", code, text=False)
        self.assertEqual(result.stdout, stdout)
        self.assertEqual(result.stderr, stderr)

    def test_stalled_stdin_reader_obeys_deadline(self):
        pidfile = self.directory / "stdin-stall"
        code = (
            f'import os,time; open({str(pidfile)!r},"w").write(str(os.getpid())); '
            "time.sleep(60)"
        )
        started = time.monotonic()
        with self.assertRaisesRegex(ValueError, "deadline"):
            air.run(
                "python3",
                "-I",
                "-c",
                code,
                input_data=b"x" * 1048576,
                timeout=0.4,
            )
        self.assertLess(time.monotonic() - started, 5)
        self.assert_stopped(self.wait_pid(pidfile))

    def test_premature_stdin_close_preserves_failure_and_rejects_success(self):
        payload = b"x" * 1048576
        failing = (
            'import os,sys; os.close(0); print("input refused",file=sys.stderr); '
            "sys.exit(7)"
        )
        with self.assertRaises(subprocess.CalledProcessError) as failure:
            air.run("python3", "-I", "-c", failing, input_data=payload)
        self.assertEqual(failure.exception.returncode, 7)
        self.assertEqual(failure.exception.stderr.strip(), "input refused")

        successful = "import os; os.close(0)"
        with self.assertRaisesRegex(ValueError, "before accepting complete input"):
            air.run("python3", "-I", "-c", successful, input_data=payload)

    def test_successful_leader_does_not_leave_descendants_holding_pipes(self):
        pidfile = self.directory / "descendant"
        code = (
            "import os,signal,time; pid=os.fork(); "
            "\nif pid == 0:\n"
            " signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            f' open({str(pidfile)!r},"w").write(str(os.getpid()))\n'
            " time.sleep(60)\n"
            "else:\n"
            f" while not os.path.exists({str(pidfile)!r}): time.sleep(0.01)\n"
            ' print("complete",flush=True)\n'
        )
        result = air.run("python3", "-I", "-c", code, timeout=5)
        self.assertEqual(result.stdout.strip(), "complete")
        self.assert_stopped(self.wait_pid(pidfile))

    def test_guardian_cleans_group_after_caller_is_killed(self):
        pidfile = self.directory / "orphan"
        child_code = (
            "import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            "pid=os.fork(); "
            f'open({str(pidfile)!r},"w").write(str(os.getpid())) if pid == 0 else None; '
            "time.sleep(60)"
        )
        launcher = (
            "import runpy; "
            f"ns=runpy.run_path({str(Path(air.__file__).absolute())!r}); "
            f'ns["run"]("python3","-I","-c",{child_code!r},timeout=30)'
        )
        parent = subprocess.Popen(
            ["/usr/bin/python3", "-I", "-c", launcher],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            descendant = self.wait_pid(pidfile)
            parent.kill()
            parent.wait(timeout=3)
            self.assert_stopped(descendant)
        finally:
            if parent.poll() is None:
                parent.kill()
                parent.wait(timeout=3)

    def test_nonzero_status_preserves_bounded_diagnostic(self):
        with self.assertRaises(subprocess.CalledProcessError) as failure:
            air.run(
                "python3",
                "-I",
                "-c",
                'import sys; print("operation refused",file=sys.stderr); sys.exit(7)',
            )
        self.assertEqual(failure.exception.returncode, 7)
        self.assertEqual(failure.exception.stderr.strip(), "operation refused")

    def test_interactive_command_owns_controlling_terminal_then_restores_it(self):
        pid, terminal = pty.fork()
        if pid == 0:
            try:
                payload = b"bootstrap-payload-" * 8192
                expected = hashlib.sha256(payload).hexdigest()
                result = air.run(
                    "python3",
                    "-I",
                    "-c",
                    'import hashlib,os,sys; fd=os.open("/dev/tty",os.O_RDWR); '
                    "assert os.tcgetpgrp(fd)==os.getpgrp(); "
                    f"assert hashlib.sha256(sys.stdin.buffer.read()).hexdigest()=={expected!r}; "
                    'print("foreground-auth")',
                    interactive=True,
                    input_data=payload,
                    timeout=5,
                )
                assert result.stdout.strip() == "foreground-auth"
                assert os.tcgetpgrp(0) == os.getpgrp()
                os._exit(0)
            except BaseException as error:
                os.write(2, repr(error).encode()[:1024])
                os._exit(1)
        outcome = None
        diagnostic = bytearray()
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if select.select([terminal], [], [], 0.05)[0]:
                    try:
                        diagnostic.extend(os.read(terminal, 4096))
                    except OSError:
                        pass  # A closed PTY reports EIO.
                finished, status = os.waitpid(pid, os.WNOHANG)
                if finished:
                    outcome = os.waitstatus_to_exitcode(status)
                    break
            self.assertEqual(outcome, 0, diagnostic.decode("utf-8", "replace"))
        finally:
            os.close(terminal)
            if outcome is None:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)


if __name__ == "__main__":
    unittest.main()
