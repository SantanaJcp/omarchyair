#!/usr/bin/env python3
"""Install, diagnose, or remove Omarchy Air without rewriting audio configuration."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

PLUGIN_ID = 'community.omarchyair'
SOURCE = Path(__file__).resolve().parent
TARGET = Path.home() / '.config/omarchy/plugins' / PLUGIN_ID
FILES = ('manifest.json', 'Service.qml', 'setup.py', 'network.py', 'README.md', 'LICENSE')


def run(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check, timeout=30)


def catalog():
    return json.loads(run('omarchy', 'plugin', 'list', '--json').stdout)


def install():
    if (TARGET.exists() or TARGET.is_symlink()) and TARGET.resolve() != SOURCE:
        raise ValueError(f'{TARGET} already exists; refusing to overwrite it. Use the installed copy or uninstall first.')
    run('omarchy', 'plugin', 'validate', str(SOURCE))
    if run('pacman', '-Q', 'pipewire-zeroconf', check=False).returncode:
        subprocess.run(['omarchy', 'pkg', 'add', 'pipewire-zeroconf'], check=True)
    if run('systemctl', 'is-active', '--quiet', 'avahi-daemon.service', check=False).returncode:
        raise ValueError('Avahi is not running. Prepare the LAN explicitly with network.py enable --avahi; see README.')
    if TARGET.resolve() != SOURCE:
        TARGET.parent.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix='.omarchyair-', dir=TARGET.parent))
        try:
            for name in FILES:
                shutil.copy2(SOURCE / name, stage / name)
            stage.rename(TARGET)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
    if not any(item['id'] == PLUGIN_ID for item in catalog()):
        run('omarchy-shell', 'shell', 'rescanPlugins')
    deadline = time.monotonic() + 10
    while not any(item['id'] == PLUGIN_ID for item in catalog()):
        if time.monotonic() >= deadline:
            raise ValueError('Shell has not discovered the installed plugin; files retained for diagnosis.')
        time.sleep(0.1)
    run('omarchy', 'plugin', 'enable', PLUGIN_ID)
    deadline = time.monotonic() + 10
    while True:
        probe = run('omarchy-shell', 'omarchyair', 'status', check=False)
        if probe.returncode == 0:
            status = json.loads(probe.stdout)
            if status['running']:
                break
            raise ValueError(f'Discovery process stopped: {status}')
        if time.monotonic() >= deadline:
            raise ValueError('Plugin service did not start; run doctor and inspect shell logs.')
        time.sleep(0.1)
    print('Omarchy Air enabled. Select a receiver in the existing audio panel.')
    print('Discovery is not proof of playback. Run doctor; prepare LAN timing ports only if blocked.')


def uninstall():
    if TARGET.is_symlink():
        raise ValueError('Installed path is a symlink; inspect it before removal.')
    if TARGET.exists():
        manifest = json.loads((TARGET / 'manifest.json').read_text())
        if manifest.get('id') != PLUGIN_ID:
            raise ValueError('Installed manifest does not match; refusing removal.')
        print(run('omarchy', 'plugin', 'remove', PLUGIN_ID, '--yes').stdout.strip())
    else:
        print('Plugin is not installed.')
    print('If you used network.py, also run: sudo python3 network.py disable')
    print('Shared packages are intentionally retained. No PipeWire configuration was changed.')


def doctor():
    checks = {}
    for package in ('pipewire', 'pipewire-zeroconf', 'wireplumber', 'avahi'):
        checks[package] = run('pacman', '-Q', package, check=False).returncode == 0
    checks['avahi-running'] = run('systemctl', 'is-active', '--quiet', 'avahi-daemon.service', check=False).returncode == 0
    status = run('omarchy-shell', 'omarchyair', 'status', check=False)
    service = json.loads(status.stdout) if status.returncode == 0 else None
    checks['discovery-running'] = bool(service and service.get('running'))
    sinks = json.loads(run('pactl', '-f', 'json', 'list', 'sinks').stdout)
    receivers = [{'name': sink['name'], 'description': sink['description'], 'state': sink['state']}
                 for sink in sinks if sink['name'].startswith('raop_sink.')]
    checks['receivers-discovered'] = bool(receivers)
    print(json.dumps({'checks': checks, 'service': service, 'receivers': receivers,
                      'defaultSink': run('pactl', 'get-default-sink').stdout.strip(),
                      'note': 'A discovered or RUNNING sink does not prove audible playback.'}, indent=2))
    return 0 if all(checks.values()) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'uninstall', 'doctor'))
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('Run setup.py as your desktop user, not root. Only network.py needs elevation.')
    if args.action == 'install':
        install()
    elif args.action == 'uninstall':
        uninstall()
    else:
        return doctor()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f'Omarchy Air: {error}', file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        sys.exit(1)
