"""Safety regressions; no root, network, or real firewall changes."""
import argparse
from contextlib import redirect_stdout
import copy
import io
from pathlib import Path
import shlex
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import network


def rule(action='allow', logging=False, comment='user-owned'):
    return ['ufw', action] + (['log'] if logging else []) + [
        'in', 'on', 'wlan0', 'from', '192.168.1.0/24', 'to', 'any',
        'port', '6001:6002', 'proto', 'udp', 'comment', comment]


def selectors(value):
    # Native UFW replaces a rule with the same selectors even if its action,
    # logging, or comment differs. Keep this independent of network.rule_key.
    result = value[2:]
    if result[:1] in (['log'], ['log-all']):
        result = result[1:]
    return result[:result.index('comment')] if 'comment' in result else result


class FirewallHost:
    def __init__(self):
        self.rules = []
        self.units = {
            'avahi-daemon.service': {'enabled': 'disabled', 'active': 'inactive'},
            'avahi-daemon.socket': {'enabled': 'disabled', 'active': 'inactive'},
        }
        self.fail_activation = False

    def run(self, *args, check=True):
        stdout = ''
        if args == ('ufw', 'status'):
            stdout = 'Status: active\n'
        elif args == ('ufw', 'show', 'added'):
            stdout = '\n'.join(shlex.join(item) for item in self.rules)
        elif args[:2] == ('ufw', 'allow'):
            self.rules = [item for item in self.rules if selectors(item) != selectors(list(args))]
            self.rules.append(list(args))
        elif args[:3] == ('ufw', '--force', 'delete'):
            self.rules.remove(['ufw', *args[3:]])
        elif args[0] == 'systemctl':
            action, unit = args[1], args[-1]
            state = self.units[unit]
            if action == 'is-enabled':
                stdout = state['enabled']
            elif action == 'is-active':
                stdout = state['active']
            elif action in ('enable', 'disable'):
                if self.fail_activation and '--now' in args:
                    self.fail_activation = False
                    raise subprocess.CalledProcessError(1, args)
                state['enabled'] = 'enabled' if action == 'enable' else 'disabled'
                if unit == 'avahi-daemon.service':
                    self.units['avahi-daemon.socket']['enabled'] = state['enabled']
                if '--now' in args:
                    state['active'] = 'active'
                    self.units['avahi-daemon.socket']['active'] = 'active'
            elif action in ('start', 'stop'):
                state['active'] = 'active' if action == 'start' else 'inactive'
            else:
                raise AssertionError(args)
        else:
            raise AssertionError(args)
        return SimpleNamespace(stdout=stdout, returncode=0)


class NetworkPreservationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name) / 'managed/network.json'
        self.host = FirewallHost()
        self.args = argparse.Namespace(interface='wlan0', subnet='192.168.1.0/24',
                                       avahi=False, mdns=False)
        for replacement in (
            patch.object(network, 'STATE', self.state),
            patch.object(network, 'run', self.host.run),
            patch.object(network, 'validate_lan', return_value='192.168.1.0/24'),
        ):
            replacement.start()
            self.addCleanup(replacement.stop)
        output = redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def test_conflicting_deny_is_not_overwritten_or_owned(self):
        self.host.rules = [rule('deny')]
        original = copy.deepcopy(self.host.rules)
        with self.assertRaises(ValueError):
            network.enable(self.args)
        network.disable()
        self.assertEqual(self.host.rules, original)
        self.assertFalse(self.state.exists())

    def test_existing_logged_allow_survives_enable_and_disable(self):
        self.host.rules = [rule(logging=True)]
        original = copy.deepcopy(self.host.rules)
        network.enable(self.args)
        network.disable()
        self.assertEqual(self.host.rules, original)

    def test_repeated_enable_reverts_only_owned_rule(self):
        unrelated = ['ufw', 'allow', '22/tcp']
        self.host.rules = [unrelated]
        network.enable(self.args)
        network.enable(self.args)
        self.assertEqual(len(self.host.rules), 2)
        network.disable()
        network.disable()
        self.assertEqual(self.host.rules, [unrelated])
        self.assertFalse(self.state.exists())

    def test_edited_owned_policy_is_preserved_for_inspection(self):
        network.enable(self.args)
        self.host.rules[0][1] = 'deny'
        edited = copy.deepcopy(self.host.rules)
        with self.assertRaises(ValueError):
            network.disable()
        self.assertEqual(self.host.rules, edited)
        self.assertTrue(self.state.exists())

    def test_changed_owned_subnet_does_not_discard_reversal_journal(self):
        network.enable(self.args)
        owned = self.host.rules[0]
        owned[owned.index('from') + 1] = '192.168.1.5'
        edited = copy.deepcopy(self.host.rules)
        with self.assertRaises(ValueError):
            network.disable()
        self.assertEqual(self.host.rules, edited)
        self.assertTrue(self.state.exists())

    def test_avahi_service_socket_enablement_is_restored_independently(self):
        self.args.avahi = True
        self.host.units['avahi-daemon.service']['enabled'] = 'enabled'
        original = copy.deepcopy(self.host.units)
        network.enable(self.args)
        network.disable()
        self.assertEqual(self.host.units, original)

    def test_interrupted_avahi_activation_can_resume_and_revert(self):
        self.args.avahi = True
        original = copy.deepcopy(self.host.units)
        self.host.fail_activation = True
        with self.assertRaises(subprocess.CalledProcessError):
            network.enable(self.args)
        network.enable(self.args)
        self.assertEqual(self.host.units['avahi-daemon.service']['active'], 'active')
        network.disable()
        self.assertEqual(self.host.units, original)
        self.assertFalse(self.state.exists())


if __name__ == '__main__':
    unittest.main()
