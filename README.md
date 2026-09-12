# Omarchy Air

Omarchy Air is an open-source AirPlay audio output integration for Omarchy.
Receivers appear in Omarchy's **existing audio output selector**; this is not a
replacement audio panel, Sonos controller, or new AirPlay implementation.
PipeWire provides discovery, authentication, audio transport, and volume
control. Release 0.3.0 keeps that native audio path while moving narrowly
scoped system operations into a separately installed, signed helper.

## Operating model

The checkout and installed plugin are normal-user code. They are never run as
root. The only Python frontend actions are `install`, `uninstall`, `doctor`,
`discover`, and the explicit `network enable`/`network disable` actions.
The frontend may ask root `pacman` to install the fixed, signed
`omarchyair-helper` package and its declared dependencies when the user
explicitly requests an operation that needs them. Once installed, the helper
performs only its fixed network/Avahi operations.

The helper is not a copy of the checkout and does not execute checkout files.
It is a root-owned Arch package installed from a fixed signed release URL.
There is no sudoers or polkit installation, no arbitrary package/command/path
argument, and no unattended "one command with no questions" promise.

## Requirements

- Omarchy with the Quickshell service-plugin API.
- PipeWire, WirePlumber, `pipewire-pulse`, Python 3, and Avahi.
- The `pipewire-zeroconf` package.
- A reachable LAN and an AirPlay receiver that supports PipeWire's RAOP
  sender.
- An active desktop session. Run the Omarchy Air frontend as the desktop user,
  never as root.
- The helper package depends on UFW, so installing it can also install UFW.
  Package installation does not enable the firewall or activate Avahi.

## Install

Review the checkout before executing it:

```sh
git clone https://github.com/SantanaJcp/omarchyair.git
cd omarchyair
```

The signed helper package declares its required system dependencies, including
`pipewire-zeroconf`. Omarchy Air does not require a separate dependency
command before this installation. Do not use `sudo` or `pkexec` to invoke the
repository's `omarchyair.py`, a checked-out file, or an installed plugin file.
The frontend's bootstrap may request sudo for fixed system tools, but it never
elevates checkout or plugin code.

For an ordinary install with no network changes, prepare Avahi manually if it
is not already active (see [Manual diagnostics and fallback](#manual-diagnostics-and-fallback))
and run:

```sh
/usr/bin/python3 -I omarchyair.py install
/usr/bin/python3 -I omarchyair.py doctor
```

The isolated `/usr/bin/python3 -I` invocation is required. Installation
validates the reviewed source, publishes the fixed plugin payload without
overwriting an existing destination, and enables it through native Omarchy
plugin controls. If a destination already exists, it refuses to overwrite it;
use the upgrade sequence below.

### Signed helper bootstrap

Installing a missing or outdated helper requires explicit interactive consent.
The frontend displays the signing fingerprint and its system-wide trust
implications. The release key and fixed package target are:

- fingerprint:
  `D1E431E8B1F91F6A6C28A0A2B78190C1F45FCB18`
- key UID: `Omarchy Air releases <codingsantana@gmail.com>`
- key expiry: 2028-09-11
- fixed package URL:
  `https://github.com/SantanaJcp/omarchyair/releases/download/v0.3.0/omarchyair-helper-0.3.0-1-any.pkg.tar.zst`

The public key is bundled as `signing-key.asc` in the reviewed plugin payload.
After confirmation, the frontend passes that key by standard input to the
fixed root `pacman-key` operation, locally trusts only the displayed
fingerprint, and asks root `pacman` to download and install the signed package
from the fixed HTTPS release URL. It does not accept a key or package path
from the user, copy a local package, or execute a helper from the checkout.
Before using an installed helper, the frontend requires its protocol response
to identify API 1 and helper version 0.3.0. A missing or older helper requires
the signed bootstrap. A newer helper is never downgraded automatically:
update the plugin checkout instead.
The URL is the release artifact selected for 0.3.0; do not replace it with a
mirror or an unverified local file. The package manager must enforce its
effective remote-file signature policy (`require` plus `trusted`); the
bootstrap never bypasses signature checking.

This bootstrap is a real trust decision. The signing key is trusted in the
system pacman keyring, so it authorizes installation of any package signed by
that key, not only this helper package. The helper's narrow API does not
constrain what a future package signed by the key could contain. Review the
release source and verify the fingerprint through a trusted release channel
before answering yes. The first bootstrap requires an interactive answer and
sudo authentication from a foreground terminal with stdin attached; it rejects
redirected stdin and is not suitable for unattended automation.
Native `omarchy plugin add` does not bootstrap this helper or its dependencies.

If the helper is missing, installation stops before plugin publication until
the explicit bootstrap succeeds. The helper package declares its required
system dependencies; Omarchy Air does not install packages from the checkout
or accept arbitrary package names.

Keep Omarchy fully updated through its supported `omarchy update` workflow
before installation. Stale package databases can cause dependency downloads
to fail; do not disable signature verification or perform a partial
`pacman -Sy` upgrade to work around that failure. Trust in the signing key
is retained even if installation fails or is interrupted.

### Integrated LAN setup

One install invocation can request the helper's narrow LAN setup and then
enable the plugin. The interface and subnet are always supplied together:

```sh
/usr/bin/python3 -I omarchyair.py install \
  --interface wlan0 \
  --subnet 192.168.1.0/24 \
  --avahi
```

Add `--mdns` only when mDNS is needed:

```sh
/usr/bin/python3 -I omarchyair.py install \
  --interface wlan0 \
  --subnet 192.168.1.0/24 \
  --mdns \
  --avahi
```

The helper checks that UFW is active and that the subnet is directly routed
through the named interface. It adds only the requested inbound UDP
6001--6002 rule, and UDP 5353 only with `--mdns`; it does not guess an
interface, open a broad port range, change the router, or perform a global
firewall reload. `--mdns` and `--avahi` require the interface/subnet pair.
Without `--avahi`, Avahi must already be active. Existing identical firewall
rules are retained rather than claimed, and the helper records only changes it
owns.

The explicit network action is also available after installation:

```sh
/usr/bin/python3 -I omarchyair.py network enable \
  --interface wlan0 \
  --subnet 192.168.1.0/24 \
  --avahi
```

Use this only as the normal desktop user; the frontend delegates the
privileged operation to the installed signed helper. Never prefix it, or any
other repository command, with `sudo` or `pkexec`.

### Upgrade from an earlier release

Use a separate, reviewed checkout of the 0.3.0 release. First select a local
speaker or headphones in Omarchy's audio panel. Then, from the new checkout,
run this sequence in order:

```sh
/usr/bin/python3 -I omarchyair.py uninstall
omarchy restart shell
/usr/bin/python3 -I omarchyair.py install
/usr/bin/python3 -I omarchyair.py doctor
```

This is the native no-overwrite cutover: local output, new-checkout
`uninstall`, shell restart, `install`, then `doctor`. If LAN preparation is
part of this upgrade, add the reviewed `--interface`/`--subnet` pair and any
deliberate `--mdns`/`--avahi` flags to the `install` command; omitting network
flags leaves existing firewall and Avahi state alone.

`uninstall` disables the native plugin record and atomically moves the
installed tree to a `.community.omarchyair.bak.*` backup; it does not
recursively remove a checkout or replace unrelated files. `install` then
publishes the new tree only at an absent destination.

The shell restart is the cold-cache boundary. It clears compiled QML from the
old plugin instance without restarting PipeWire. Installation and `doctor`
compare the running service identity with the checkout's manifest; an older
cached service is not healthy. If installation reports a cached older service,
restart the shell and retry the install/doctor portion from the reviewed
checkout.

## Manual diagnostics and fallback

The signed helper path above is the supported integrated setup. If the helper
cannot be bootstrapped, or an administrator deliberately chooses not to use
its root operation, a system administrator can prepare the LAN directly. Do
not run any of these commands against a repository or installed plugin path.

Before changing Avahi, inspect and record both units in the administrator's
change notes:

```sh
sudo systemctl is-enabled avahi-daemon.service avahi-daemon.socket
sudo systemctl is-active avahi-daemon.service avahi-daemon.socket
```

If policy allows manual activation, use:

```sh
sudo systemctl enable --now avahi-daemon.service
```

Keep the recorded state for **both** `avahi-daemon.service` and
`avahi-daemon.socket`; do not assume that an existing socket policy was
disabled. The signed helper's `--avahi` option records and restores those
states; manual activation is the administrator's responsibility.

For firewall fallback, first inspect addresses, route, and active UFW.
Substitute the interface, subnet, and receiver address with values from this
LAN; do not use a guessed interface or a broad source range:

```sh
ip -4 addr
ip -4 route
ip -4 route show dev wlan0
ip -4 route get 192.168.1.42
sudo ufw status verbose
sudo ufw status numbered
```

Proceed only when UFW reports `Status: active` and the route to the receiver
uses the intended interface. Record the numbered rules before adding anything
so preexisting entries can be distinguished from new ones.

For `wlan0`, source LAN `192.168.1.0/24`, and receiver `192.168.1.42`, add only
the narrow RAOP timing/control rule:

```sh
sudo ufw allow in on wlan0 from 192.168.1.0/24 to any port 6001:6002 proto udp comment 'omarchyair-manual'
```

Add UDP 5353 only when discovery evidence shows mDNS is blocked and the
administrator confirms that this LAN needs the exception:

```sh
sudo ufw allow in on wlan0 from 192.168.1.0/24 to any port 5353 proto udp comment 'omarchyair-manual'
```

Do not add 5353 preemptively or open a broad port range. Multicast or
access-point isolation can still block discovery outside this host.

The manual rules use `omarchyair-manual`, not the helper's
`omarchyair-managed`; use the reversal instructions below and preserve rules
that predate this fallback.

## Use and discovery

1. Open Omarchy's audio panel and select the receiver by its advertised name.
2. Start audio in a browser or another application. Omarchy's native selector
   sets the default and moves active application streams.
3. Adjust volume in the audio panel, starting at a low volume.
4. Select local speakers or headphones to return to local playback. No reboot
   or PipeWire restart is required by the plugin.

Discovery does not select a receiver automatically. AirPlay output has
buffering latency; this is not a promise of macOS-equivalent video
synchronization, gaming latency, AirPlay 2 multiroom synchronization, or
pairing support.

The service supervises a private `pw-cli` process group. It requires an
explicit module acknowledgement before reporting readiness, probes that
module every five seconds, and renews a fifteen-second shell lease.
Disabling/removing the plugin or losing either lease ends discovery and removes
its sinks. A discovered sink is not proof that a speaker produced audible
sound.

## Safe uninstall and reversal

First select a local output. From the reviewed checkout, remove the plugin as
the normal desktop user:

```sh
/usr/bin/python3 -I omarchyair.py uninstall
omarchy restart shell
```

The plugin uninstall does not change PipeWire configuration, the router, or
shared packages. It also does not automatically reverse helper-managed
firewall or Avahi changes. If those changes should be removed, run this
normal-user frontend action from the reviewed checkout:

```sh
/usr/bin/python3 -I omarchyair.py network disable
```

`network disable` delegates to the installed signed root helper. It removes
only the recorded helper-owned UFW rules and restores Avahi only when the
helper changed it. It preserves preexisting identical rules and stops for
inspection if a managed rule was edited. Never run `sudo python3`,
`sudo ./omarchyair.py`, or `sudo /path/to/omarchyair.py network disable`;
the frontend must remain a normal-user process.

Manual firewall and Avahi changes are reversed manually. **Preserve
preexisting rules and restore the service/socket states recorded before the
change.** Inspect first:

```sh
sudo ufw status numbered
sudo systemctl is-enabled avahi-daemon.service avahi-daemon.socket
sudo systemctl is-active avahi-daemon.service avahi-daemon.socket
```

Delete only numbered UFW rows whose comment is exactly `omarchyair-manual` and
which were added for this setup; delete higher numbers first because UFW
renumbers the remaining rows:

```sh
sudo ufw delete <number-of-the-omarchyair-manual-5353-rule>
sudo ufw delete <number-of-the-omarchyair-manual-6001-6002-rule>
sudo ufw status numbered
```

If a rule is unambiguously the example above, its equivalent text reversal is:

```sh
sudo ufw delete allow in on wlan0 from 192.168.1.0/24 to any port 5353 proto udp
sudo ufw delete allow in on wlan0 from 192.168.1.0/24 to any port 6001:6002 proto udp
```

Do not use the text form when it could match a rule that existed before this
setup; leave that rule in place and use numbered inspection to identify only
the newly added entry.

For each Avahi unit, restore the recorded enablement and activity separately:

```sh
# Replace UNIT with avahi-daemon.service and then avahi-daemon.socket.
# Run exactly the action matching the state recorded before preparation.
sudo systemctl enable UNIT       # if that unit was enabled
sudo systemctl disable UNIT      # if that unit was disabled
sudo systemctl start UNIT        # if that unit was active
sudo systemctl stop UNIT         # if that unit was inactive
```

For example, only when **both** units were disabled and inactive before the
manual preparation, the reversal is:

```sh
sudo systemctl disable --now avahi-daemon.service
sudo systemctl disable --now avahi-daemon.socket
```

Never stop or disable a unit merely because it was convenient during setup;
restore the recorded service and socket state.

## Legacy migration

The hardened 0.2.0 helper used the `omarchyair-managed` comment and a
root-owned `/var/lib/omarchyair/network.json` journal. The packaged 0.3.0
helper retains that schema for inspection and reversal, requiring a
root-owned 0700 directory and a private, single-link regular journal.
Earlier or manually modified state that fails these checks is rejected,
not automatically repaired; inspect it as an administrator before migration.
New administrator-created rules must use the distinct
`omarchyair-manual` comment.

An ordinary plugin upgrade with no network flags leaves existing firewall
rules, Avahi state, and the old journal unchanged. Passing explicit network
flags is the only request to reconcile the specified helper-managed setup.
The old journal is data for the fixed helper, not a shell script: never source
it, execute it, or feed it to a command. It may be retained as historical
reference, and no automatic cleanup is performed.

Do not invoke a helper implementation from a checkout, use an old root helper
path, or elevate the frontend. Use the normal-user `network disable` action
above for a recorded reversal, and use the manual inspection procedure for
rules or Avahi changes that were not recorded by the helper. Preserve rules
and service/socket state that predate the old setup.

## Security boundary

The normal-user frontend runs unsandboxed from a reviewed checkout. It is not a
sandbox against malicious code in that checkout, another process with the same
UID, a compromised desktop or PipeWire installation, or a compromised
receiver. Review the checkout and the release-key fingerprint before
installation.

Only the installed, root-owned helper runs plugin-authored code as root.
The bootstrap also invokes fixed privileged system package tools. A compromised
signing key or malicious signed package could compromise the entire system;
the helper's narrow API is not a sandbox for its author or signing key.
Bootstrap requires explicit consent and sudo authentication, uses a fixed package
URL, and does not grant root access to repository or plugin files. No
marketplace approval or security certification is implied.

Privileged package/key commands run under a root-side 600-second system
`timeout`, with a 900-second caller budget. Network operations have a
150-second root-side limit and a 180-second caller budget. The root-side
timeouts escalate after one second independently of the unprivileged caller.
Ordinary subprocesses retain their 30-second deadlines and 1 MiB output
budgets; bootstrap output is limited to 8 MiB.

## Compatibility and verification

The backend is [PipeWire RAOP
discovery](https://docs.pipewire.org/page_module_raop_discover.html) and its
[RAOP sender](https://docs.pipewire.org/page_module_raop_sink.html). Support
depends on the receiver's advertised transport and authentication profile,
not merely an AirPlay logo. PIN/password-protected receivers and AirPlay
2-only features are not implemented by this plugin. A receiver may be
discovered but reject playback; appearance is not universal compatibility.

Run the focused, non-root regressions without audio hardware:

```sh
/usr/bin/python3 -m unittest -v test_installer test_process test_discovery test_network test_bootstrap test_wrapper
```

These cover filesystem and process boundaries, stdin/TTY separation,
discovery leases, firewall/journal preservation, and signer/package-policy
rejection. They do not prove audible playback or validate a particular LAN.

### Historical hardware report

The following findings are retained from the 2026-09-11 hardware session and
are separate from the 0.3.0 signed-helper release claim:

- PipeWire 1.6.8 was tested with a Sonos SYMFONISK **Table lamp (S20)**.
- The receiver appeared in the actual Omarchy audio panel and was selected
  there.
- Sonos returned RTSP 200 for authentication, SETUP, and RECORD after its
  previously blocked UDP timing packets were allowed.
- Chromium Web Audio and `paplay` both routed to the Sonos sink. The native
  output-switch command moved both live streams back to local speakers.
- Uninstall removed the plugin's sinks and restored the complete prior
  `shell.json` content semantically; network reversal retained existing UFW
  rules.
- Avahi was already enabled/running and was not changed on that machine.
- Audible playback was confirmed from both the browser and another application
  through the SYMFONISK Table lamp receiver.
- The bookshelf model remains hardware-unverified. A MacBook receiver was
  discovered but not playback-tested.

Those observations are not a new hardware test of every 0.3.0 change, and no
universal AirPlay or AirPlay 2 compatibility claim is made.

## Maintainer release build

Build as a normal user from reviewed sources. Advance the manifest, compiled
QML version, helper protocol version string and `PKGBUILD` package version
together for each release. Regenerate and review the source hashes with
`makepkg --geninteg`; do not use skipped checksums. Keep build output outside
the plugin checkout because makepkg's source symlinks are not valid plugin
payload entries.

With the protected signing key configured in your private `GNUPGHOME`:

```sh
mkdir -p "$HOME/.cache/omarchyair-build" "$HOME/.cache/omarchyair-dist"
BUILDDIR="$HOME/.cache/omarchyair-build" \
PKGDEST="$HOME/.cache/omarchyair-dist" \
makepkg --cleanbuild --sign --key D1E431E8B1F91F6A6C28A0A2B78190C1F45FCB18
```

Publish the reviewed version tag, package, detached `.sig`, and public
`signing-key.asc` through this repository's GitHub Release. The frontend pins
that release's version and `pkgrel=1` asset name. Never replace a published
release artifact; publish a new version for corrections. Never commit or
upload the private signing key or its revocation certificate. Keep protected
offline backups; package signing must remain under the maintainer's control.

## License

MIT; see `LICENSE`. PipeWire is MIT-licensed. Avahi and the other installed
system components retain their own open-source licenses; their code is not
bundled here. AirPlay, Sonos, IKEA, and Omarchy names identify
interoperability targets. This project is not affiliated with or endorsed by
those projects or companies.
