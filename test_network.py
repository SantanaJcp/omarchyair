"""Safety regressions; no root, network, or real firewall changes."""

import argparse
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import omarchyair_helper as network


def rule(action="allow", logging=False, comment="user-owned"):
    return (
        ["ufw", action]
        + (["log"] if logging else [])
        + [
            "in",
            "on",
            "wlan0",
            "from",
            "192.168.1.0/24",
            "to",
            "any",
            "port",
            "6001:6002",
            "proto",
            "udp",
            "comment",
            comment,
        ]
    )


def selectors(value):
    # Native UFW replaces a rule with the same selectors even if its action,
    # logging, or comment differs. Keep this independent of network.rule_key.
    result = value[2:]
    if result[:1] in (["log"], ["log-all"]):
        result = result[1:]
    return result[: result.index("comment")] if "comment" in result else result


class FirewallHost:
    def __init__(self):
        self.rules = []
        self.live_override = None
        self.units = {
            "avahi-daemon.service": {"enabled": "disabled", "active": "inactive"},
            "avahi-daemon.socket": {"enabled": "disabled", "active": "inactive"},
        }
        self.fail_activation = False
        self.calls = []

    def run(self, *args, check=True):
        self.calls.append((args, check))
        stdout = ""
        if args == ("ufw", "status"):
            stdout = "Status: active\n"
        elif args == ("ufw", "show", "added"):
            stdout = "\n".join(shlex.join(item) for item in self.rules)
        elif args[:2] == ("ufw", "allow"):
            self.rules = [
                item for item in self.rules if selectors(item) != selectors(list(args))
            ]
            self.rules.append(list(args))
        elif args[:3] == ("ufw", "--force", "delete"):
            self.rules.remove(["ufw", *args[3:]])
        elif args[0] == "iptables":
            active = self.rules if self.live_override is None else self.live_override
            port_arg = "--dports" if "--dports" in args else "--dport"
            interface, subnet = args[args.index("-i") + 1], args[args.index("-s") + 1]
            port = args[args.index(port_arg) + 1]
            present = any(
                item[1] == "allow"
                and "on" in item
                and "port" in item
                and item[item.index("on") + 1] == interface
                and item[item.index("from") + 1] == subnet
                and item[item.index("port") + 1] == port
                for item in active
            )
            return SimpleNamespace(
                stdout="", stderr="", args=args, returncode=0 if present else 1
            )
        elif args[0] == "systemctl":
            action, unit = args[1], args[-1]
            state = self.units[unit]
            if action == "is-enabled":
                stdout = state["enabled"]
            elif action == "is-active":
                stdout = state["active"]
            elif action in ("enable", "disable"):
                if self.fail_activation and "--now" in args:
                    self.fail_activation = False
                    raise subprocess.CalledProcessError(1, args)
                state["enabled"] = "enabled" if action == "enable" else "disabled"
                if unit == "avahi-daemon.service":
                    self.units["avahi-daemon.socket"]["enabled"] = state["enabled"]
                if "--now" in args:
                    state["active"] = "active"
                    self.units["avahi-daemon.socket"]["active"] = "active"
            elif action in ("start", "stop"):
                state["active"] = "active" if action == "start" else "inactive"
            else:
                raise AssertionError(args)
        else:
            raise AssertionError(args)
        return SimpleNamespace(stdout=stdout, returncode=0)


class NetworkPreservationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(temporary.cleanup)
        self.state_root = Path(temporary.name) / "managed"
        self.state = self.state_root / "network.json"
        self.host = FirewallHost()
        self.args = argparse.Namespace(
            interface="wlan0", subnet="192.168.1.0/24", avahi=False, mdns=False
        )
        for replacement in (
            patch.object(network, "STATE_ROOT", self.state_root),
            patch.object(network, "STATE_OWNER", os.geteuid()),
            patch.object(network, "run", self.host.run),
            patch.object(network, "validate_lan", return_value="192.168.1.0/24"),
        ):
            replacement.start()
            self.addCleanup(replacement.stop)
        output = redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def test_conflicting_deny_is_not_overwritten_or_owned(self):
        self.host.rules = [rule("deny")]
        original = copy.deepcopy(self.host.rules)
        with self.assertRaises(ValueError):
            network.network_enable(self.args)
        network.network_disable()
        self.assertEqual(self.host.rules, original)
        self.assertFalse(self.state.exists())

    def test_existing_logged_allow_survives_enable_and_disable(self):
        self.host.rules = [rule(logging=True)]
        original = copy.deepcopy(self.host.rules)
        network.network_enable(self.args)
        network.network_disable()
        self.assertEqual(self.host.rules, original)

    def test_repeated_enable_reverts_only_owned_rule(self):
        unrelated = ["ufw", "allow", "22/tcp"]
        self.host.rules = [unrelated]
        network.network_enable(self.args)
        network.network_enable(self.args)
        self.assertEqual(len(self.host.rules), 2)
        network.network_disable()
        network.network_disable()
        self.assertEqual(self.host.rules, [unrelated])
        self.assertFalse(self.state.exists())

    def test_edited_owned_policy_is_preserved_for_inspection(self):
        network.network_enable(self.args)
        self.host.rules[0][1] = "deny"
        edited = copy.deepcopy(self.host.rules)
        with self.assertRaises(ValueError):
            network.network_disable()
        self.assertEqual(self.host.rules, edited)
        self.assertTrue(self.state.exists())

    def test_changed_owned_subnet_does_not_discard_reversal_journal(self):
        network.network_enable(self.args)
        owned = self.host.rules[0]
        owned[owned.index("from") + 1] = "192.168.1.5"
        edited = copy.deepcopy(self.host.rules)
        with self.assertRaises(ValueError):
            network.network_disable()
        self.assertEqual(self.host.rules, edited)
        self.assertTrue(self.state.exists())

    def test_avahi_service_socket_enablement_is_restored_independently(self):
        self.args.avahi = True
        self.host.units["avahi-daemon.service"]["enabled"] = "enabled"
        original = copy.deepcopy(self.host.units)
        network.network_enable(self.args)
        network.network_disable()
        self.assertEqual(self.host.units, original)

    def test_interrupted_avahi_activation_can_resume_and_revert(self):
        self.args.avahi = True
        original = copy.deepcopy(self.host.units)
        self.host.fail_activation = True
        with self.assertRaises(subprocess.CalledProcessError):
            network.network_enable(self.args)
        network.network_enable(self.args)
        self.assertEqual(self.host.units["avahi-daemon.service"]["active"], "active")
        network.network_disable()
        self.assertEqual(self.host.units, original)
        self.assertFalse(self.state.exists())

    def _managed_rule(self, port="6001:6002"):
        return [
            "ufw",
            "allow",
            "in",
            "on",
            "wlan0",
            "from",
            "192.168.1.0/24",
            "to",
            "any",
            "port",
            port,
            "proto",
            "udp",
            "comment",
            network.COMMENT,
        ]

    def _write_journal(self, state):
        self.state_root.mkdir(mode=0o700, exist_ok=True)
        self.state_root.chmod(0o700)
        self.state.write_text(json.dumps(state) + "\n")
        self.state.chmod(0o600)

    def _valid_journal(self):
        return {
            "rules": [self._managed_rule()],
            "avahi": None,
            "interface": "wlan0",
            "subnet": "192.168.1.0/24",
        }

    def test_symlink_state_is_rejected_without_firewall_commands(self):
        self.state_root.mkdir(mode=0o700)
        target = self.state_root.parent / "attacker-state"
        target.write_text("{}\n")
        target.chmod(0o600)
        self.state.symlink_to(target)
        with self.assertRaises(ValueError):
            network.network_disable()
        self.assertEqual(self.host.calls, [])

    def test_fifo_state_is_rejected_without_blocking_or_commands(self):
        self.state_root.mkdir(mode=0o700)
        os.mkfifo(self.state, 0o600)
        with self.assertRaises(ValueError):
            network.network_disable()
        self.assertEqual(self.host.calls, [])

    def test_oversized_state_is_rejected_before_rollback(self):
        self.state_root.mkdir(mode=0o700)
        self.state.write_bytes(b"x" * (network.STATE_LIMIT + 1))
        self.state.chmod(0o600)
        with self.assertRaises((ValueError, OSError)):
            network.network_disable()
        self.assertEqual(self.host.calls, [])

    def test_malformed_recorded_selector_and_service_key_are_rejected(self):
        state = self._valid_journal()
        state["rules"] = [self._managed_rule("$(touch /tmp/owned)")]
        self._write_journal(state)
        with self.assertRaises(ValueError):
            network.network_disable()
        self.assertEqual(self.host.calls, [])

        state = self._valid_journal()
        state["avahi"] = {
            "attacker.service": {"enabled": "enabled", "active": "active"},
        }
        self._write_journal(state)
        with self.assertRaises(ValueError):
            network.network_disable()
        self.assertEqual(self.host.calls, [])

    def test_locked_state_directory_refuses_split_brain_operation(self):
        self.state_root.mkdir(mode=0o700)
        with network.NetworkStateStore(self.state_root, os.geteuid()):
            with self.assertRaises(ValueError):
                network.network_disable()
        self.assertEqual(self.host.calls, [])

    def test_substituted_state_directory_is_rejected_before_rule_mutation(self):
        replaced = False
        original_run = self.host.run

        def run(*args, check=True):
            nonlocal replaced
            result = original_run(*args, check=check)
            if args == ("ufw", "status") and not replaced:
                moved = self.state_root.with_name("moved-state")
                self.state_root.rename(moved)
                self.state_root.mkdir(mode=0o700)
                replaced = True
            return result

        with patch.object(network, "run", run):
            with self.assertRaises(ValueError):
                network.network_enable(self.args)
        self.assertEqual(self.host.rules, [])

    def test_interrupted_atomic_write_keeps_previous_journal_and_no_temp_file(self):
        state = self._valid_journal()
        self._write_journal(state)
        original_state = self.state.read_bytes()
        self.host.rules = [self._managed_rule()]
        self.args.mdns = True
        with patch.object(
            network.os, "replace", side_effect=OSError("simulated interruption")
        ):
            with self.assertRaises(OSError):
                network.network_enable(self.args)
        self.assertEqual(self.state.read_bytes(), original_state)
        self.assertFalse(
            any(
                item.name.startswith(".network.json.")
                for item in self.state_root.iterdir()
            )
        )
        self.assertEqual(self.host.rules, [self._managed_rule()])

    def test_old_predictable_temporary_symlink_cannot_redirect_writes(self):
        self.state_root.mkdir(mode=0o700)
        victim = self.state_root.parent / "unrelated-file"
        victim.write_text("must remain untouched")
        self.state.with_suffix(".tmp").symlink_to(victim)
        network.network_enable(self.args)
        network.network_disable()
        self.assertEqual(victim.read_text(), "must remain untouched")
        self.assertEqual(self.host.rules, [])

    def test_readable_but_nonwritable_parent_supports_normal_var_lib_layout(self):
        self.state_root.parent.chmod(0o755)
        network.network_enable(self.args)
        network.network_disable()
        self.assertFalse(self.state.exists())
        self.assertEqual(self.host.rules, [])

    def test_replaced_lock_is_rejected_before_state_publication(self):
        with network.NetworkStateStore(self.state_root, os.geteuid()) as store:
            lock = self.state_root / network.LOCK_FILE
            lock.unlink()
            lock.write_text("")
            lock.chmod(0o600)
            with self.assertRaises(ValueError):
                store.save(self._valid_journal())
        self.assertFalse(self.state.exists())

    def test_reordered_ufw_listing_still_reverts_canonical_owned_rule(self):
        network.network_enable(self.args)
        original_run = self.host.run

        def canonical_listing(*args, check=True):
            if args == ("ufw", "show", "added"):
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "ufw allow in on wlan0 proto udp from 192.168.1.0/24 "
                        "to any port 6001:6002 comment omarchyair-managed"
                    ),
                )
            return original_run(*args, check=check)

        with patch.object(network, "run", canonical_listing):
            network.network_disable()
        self.assertEqual(self.host.rules, [])

    def test_journal_cannot_replace_port_keyword_with_arbitrary_argument(self):
        state = self._valid_journal()
        state["rules"][0][9] = "app"
        self._write_journal(state)
        with self.assertRaises(ValueError):
            network.network_disable()
        self.assertEqual(self.host.calls, [])

    def test_interrupted_delete_retains_journal_until_live_rule_is_gone(self):
        network.network_enable(self.args)
        self.host.live_override = copy.deepcopy(self.host.rules)
        with self.assertRaisesRegex(ValueError, "live UFW policy differ"):
            network.network_disable()
        self.assertEqual(self.host.rules, [])
        self.assertTrue(self.state.exists())
        with self.assertRaises(ValueError):
            network.network_disable()
        self.assertTrue(self.state.exists())
        self.host.live_override = []  # Administrator reconciles the live firewall.
        network.network_disable()
        self.assertFalse(self.state.exists())

    def test_interrupted_add_is_not_falsely_accepted_on_retry(self):
        self.host.live_override = []
        with self.assertRaisesRegex(ValueError, "live UFW policy differ"):
            network.network_enable(self.args)
        self.assertEqual(self.host.rules, [self._managed_rule()])
        self.assertTrue(self.state.exists())
        with self.assertRaises(ValueError):
            network.network_enable(self.args)
        self.host.live_override = None  # Administrator reloads persisted policy.
        network.network_enable(self.args)
        network.network_disable()
        self.assertFalse(self.state.exists())


if __name__ == "__main__":
    unittest.main()
