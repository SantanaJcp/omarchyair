#!/usr/bin/env python3
"""Explicit, privileged LAN preparation; never invoked by the shell plugin."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

STATE = Path('/var/lib/omarchyair/network.json')
COMMENT = 'omarchyair-managed'


def run(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check)


def save(state):
    STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = STATE.with_suffix('.tmp')
    temporary.write_text(json.dumps(state, indent=2) + '\n')
    temporary.chmod(0o600)
    temporary.replace(STATE)


def rules():
    return [shlex.split(line) for line in run('ufw', 'show', 'added').stdout.splitlines()
            if line.startswith('ufw ')]


def rule_key(rule):
    # Keep source and destination port qualifiers attached to their addresses.
    tokens = rule[1:]
    if 'comment' in tokens:
        tokens = tokens[:tokens.index('comment')]
    fields = {}
    for keyword in ('on', 'proto'):
        if keyword in tokens:
            index = tokens.index(keyword)
            fields[keyword] = tokens[index + 1]
            del tokens[index:index + 2]
    if 'from' not in tokens or 'to' not in tokens:
        return tuple(rule)
    source = tokens.index('from')
    destination = tokens.index('to')
    logging = tuple(token for token in tokens[1:source] if token in ('log', 'log-all'))
    qualifiers = tuple(token for token in tokens[1:source] if token not in ('log', 'log-all'))
    return (tokens[0], logging, qualifiers, fields.get('on'), fields.get('proto'),
            tuple(tokens[source + 1:destination]), tuple(tokens[destination + 1:]))


def validate_lan(interface, subnet):
    network = ipaddress.ip_network(subnet, strict=True)
    private = [ipaddress.ip_network(value) for value in
               ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    if network.version != 4 or not any(network.subnet_of(lan) for lan in private):
        raise ValueError('Use an RFC1918 IPv4 LAN subnet, never the Internet.')
    routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'dev', interface).stdout)
    if not any(route.get('dst') == str(network) and route.get('scope') == 'link'
               for route in routes):
        raise ValueError('Subnet must be a directly connected route on the named interface.')
    return str(network)


def enable(args):
    subnet = validate_lan(args.interface, args.subnet)
    state = json.loads(STATE.read_text()) if STATE.exists() else {
        'rules': [], 'avahi': None, 'interface': args.interface, 'subnet': subnet}
    if (state['interface'], state['subnet']) != (args.interface, subnet):
        raise ValueError('Revert the previous LAN preparation before changing networks.')
    if 'Status: active' not in run('ufw', 'status').stdout:
        raise ValueError('UFW is not active; no network changes were made.')
    if args.avahi and state['avahi'] is None:
        previous = {}
        for unit in ('avahi-daemon.service', 'avahi-daemon.socket'):
            enabled = run('systemctl', 'is-enabled', unit, check=False).stdout.strip()
            active = run('systemctl', 'is-active', unit, check=False).stdout.strip()
            if enabled not in ('enabled', 'disabled') or active not in ('active', 'inactive'):
                raise ValueError('Avahi has a nonstandard state; configure it manually.')
            previous[unit] = {'enabled': enabled, 'active': active}
        state['avahi'] = previous
        save(state)
    if args.avahi:
        run('systemctl', 'enable', '--now', 'avahi-daemon.service')
    ports = ['6001:6002'] + (['5353'] if args.mdns else [])
    for port in ports:
        rule = ['ufw', 'allow', 'in', 'on', args.interface, 'from', subnet,
                'to', 'any', 'port', port, 'proto', 'udp', 'comment', COMMENT]
        existing = rules()
        matching = [item for item in existing if rule_key(item)[2:] == rule_key(rule)[2:]]
        if matching:
            if any(item[1] != 'allow' for item in matching):
                raise ValueError(f'Existing firewall policy conflicts with UDP {port}; refusing to replace it.')
            print(f'Preserving existing UDP {port} rule.')
            continue
        if rule not in state['rules']:
            state['rules'].append(rule)
        # Record intent first: interrupted setup can still be reverted safely.
        save(state)
        print(run(*rule).stdout.strip())
    print('LAN preparation recorded. Revert with: sudo python3 network.py disable')


def disable():
    if not STATE.exists():
        print('No managed network changes to revert.')
        return
    state = json.loads(STATE.read_text())
    recorded_selectors = {rule_key(rule)[2:] for rule in state['rules']}
    for existing in rules():
        if existing[-2:] == ['comment', COMMENT] and rule_key(existing)[2:] not in recorded_selectors:
            raise ValueError('A managed rule has changed selectors; inspect it before reverting.')
    for rule in state['rules'][:]:
        for existing in rules():
            if rule_key(existing)[2:] == rule_key(rule)[2:]:
                if rule_key(existing) != rule_key(rule) or existing[-2:] != ['comment', COMMENT]:
                    raise ValueError('A managed rule was edited; refusing to delete it.')
                print(run('ufw', '--force', 'delete', *existing[1:]).stdout.strip())
        state['rules'].remove(rule)
        save(state)
    previous = state['avahi']
    if previous:
        for unit, before in previous.items():
            if before['active'] == 'inactive':
                run('systemctl', 'stop', unit)
        # Service operations also affect its socket via Also=. Restore the
        # service's enablement first, then explicitly restore the socket.
        for unit, before in previous.items():
            action = 'enable' if before['enabled'] == 'enabled' else 'disable'
            run('systemctl', action, unit)
        for unit, before in previous.items():
            if before['active'] == 'active':
                run('systemctl', 'start', unit)
        state['avahi'] = None
        save(state)
    STATE.unlink()
    STATE.parent.rmdir()
    print('Managed network changes reverted; pre-existing rules retained.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    enable_parser = actions.add_parser('enable')
    enable_parser.add_argument('--interface', required=True)
    enable_parser.add_argument('--subnet', required=True)
    enable_parser.add_argument('--mdns', action='store_true', help='Also allow LAN mDNS when discovery is blocked')
    enable_parser.add_argument('--avahi', action='store_true', help='Enable Avahi, recording its prior state')
    actions.add_parser('disable')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run this network-only helper with sudo (or pkexec).')
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    if args.action == 'enable':
        enable(args)
    else:
        disable()


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f'Omarchy Air: {error}', file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        sys.exit(1)
