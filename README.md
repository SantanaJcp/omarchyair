# Omarchy Air

Open-source AirPlay audio output integration for Omarchy. Receivers appear in
Omarchy's **existing audio output selector**. This is a headless shell service,
not a replacement audio panel, Sonos controller, or new AirPlay implementation.
PipeWire provides discovery, authentication, audio transport, and volume control.

## Requirements

- Omarchy with the Quickshell service-plugin API (`omarchy plugin` commands).
- PipeWire, WirePlumber, `pipewire-pulse`, `pipewire-zeroconf`, Avahi, Python 3.
- UFW with its packaged iptables backend for the optional network helper.
- An AirPlay receiver that supports PipeWire's RAOP sender, on a reachable LAN.
- An active desktop session. Run setup as your normal user, not root.

## Install

Review the checkout before executing it, especially before granting root access:

```sh
git clone https://github.com/SantanaJcp/omarchyair.git
cd omarchyair
/usr/bin/python3 -I omarchyair.py install
/usr/bin/python3 -I omarchyair.py doctor
```

The installer validates the manifest, copies the fixed plugin payload to
`~/.config/omarchy/plugins/community.omarchyair`, and enables it. Existing
installations are never overwritten. Running the installed copy enables it
without copying over itself. Python isolated mode (`-I`) is required.

If `pipewire-zeroconf` is missing, installation requests foreground `sudo`
authentication for the narrow `install-dependency` command. That command runs
`omarchy pkg add pipewire-zeroconf` under a root supervisor with its own deadline;
it accepts no package names or arbitrary commands. No dependency installation or
privilege escalation occurs in the background service. Without an interactive
terminal, install the dependency explicitly through Omarchy first.

Alternatively, use the native plugin manager, then validate dependencies:

```sh
omarchy plugin add https://github.com/SantanaJcp/omarchyair.git --yes
/usr/bin/python3 -I ~/.config/omarchy/plugins/community.omarchyair/omarchyair.py install
```

### Upgrade from an earlier release

Use a separate, reviewed checkout of the new release. Select a local audio
output, then run:

```sh
/usr/bin/python3 -I omarchyair.py uninstall
omarchy restart shell
/usr/bin/python3 -I omarchyair.py install
/usr/bin/python3 -I omarchyair.py doctor
```

The shell can retain compiled QML after a plugin rescan. A shell restart clears
that cache; it does not restart PipeWire. Installation and diagnostics compare
the running service's compiled version with the checkout's manifest and refuse
to report an older cached component as healthy. The manifest and the compiled
`Service.qml` version must both be advanced for each release.

Version 0.2.0 replaces `setup.py` and `network.py` with the single isolated
`omarchyair.py` entry point. Existing valid network journals remain usable.

## Network preparation (only when needed)

Discovery requires Avahi and mDNS. RAOP UDP playback also requires the receiver's
control/timing packets to reach this computer. Do not disable your firewall.
Check the current interface and directly connected subnet with `ip -4 route`.
For example, **substitute your own interface and subnet**:

```sh
sudo /usr/bin/env -i PATH=/usr/bin LC_ALL=C \
  /usr/bin/python3 -I "$PWD/omarchyair.py" network enable \
  --interface wlan0 --subnet 192.168.1.0/24
```

This opens only UDP 6001–6002, only on that interface, only from the specified
RFC1918 IPv4 LAN. It requires an active UFW firewall and verifies that the subnet
is a directly connected route. It does not change the router or speaker firmware.
If discovery is blocked, append `--mdns` to allow LAN UDP 5353. If Avahi is not
running, append `--avahi` to enable its service and record the service/socket's
previous state. Do not add either flag when it is unnecessary.

Owned changes are recorded under `/var/lib/omarchyair/network.json`. Existing
identical rules are preserved, not claimed. The helper refuses a second network
until the previous setup is reverted. Re-run explicitly after changing LANs.
Additional simultaneous RAOP sessions can need higher control/timing ports;
this helper deliberately does not open an entire port range in advance.
IPv6-specific firewall setup is not automated.

The helper checks the live kernel rule as well as UFW's persisted configuration.
If an interrupted UFW operation leaves them inconsistent, it stops and keeps the
reversal journal. Inspect the firewall; run `sudo ufw reload` only if the persisted
policy is what you intend to apply, then retry. The helper never performs a
global firewall reload automatically.

## Use

1. Open Omarchy's audio panel and select the receiver by its advertised name.
2. Start audio in a browser or another application. Omarchy's native selector
   sets the default and moves active application streams.
3. Adjust volume in the audio panel. Start at a low volume.
4. Select your local speakers or headphones to return to local playback. No
   reboot or PipeWire restart is required by the plugin.

Discovery does not select a receiver automatically. AirPlay output has buffering
latency; this is not a promise of macOS-equivalent video synchronization, gaming
latency, AirPlay 2 multiroom synchronization, or pairing support.

```sh
omarchy-shell omarchyair status
/usr/bin/python3 -I omarchyair.py doctor
omarchy plugin disable community.omarchyair
omarchy plugin enable community.omarchyair
```

The service supervises a private `pw-cli` process group. It requires an explicit
module acknowledgement before reporting `ready`, probes that module every five
seconds, and requires a renewable lease from the shell. Disabling/removing the
plugin or losing either lease ends discovery and removes its sinks. Healthy
audio has no arbitrary session-duration limit.

Re-enable the plugin explicitly after a backend failure; no restart loop hides
errors. `status` reports readiness, compiled version, bounded terminal errors and
discovered sinks, **not proof that a speaker played sound**. `doctor` exits 0
only when dependencies, Avahi, current service version, ready discovery and at
least one RAOP sink are present. It is not an auditory test.

## Revert

First select a local output, then from the original repository:

```sh
/usr/bin/python3 -I omarchyair.py uninstall
sudo /usr/bin/env -i PATH=/usr/bin LC_ALL=C \
  /usr/bin/python3 -I "$PWD/omarchyair.py" network disable
```

The first command removes the plugin's enabled record through native shell IPC
and atomically moves its whole directory to a `.community.omarchyair.bak.*`
backup. Git checkouts are also backed up: removal never recursively traverses
or deletes the plugin tree.

The second command removes only recorded firewall rules and restores Avahi
state only if this helper changed it. Edited managed rules stop removal for
inspection. The private network directory and lock file remain to prevent
concurrent operations from acquiring different locks; a completed reversal
removes `network.json`. Shared packages are intentionally retained.

No PipeWire configuration files, bar layout or unrelated settings are replaced.
To reinstall, repeat installation and any needed LAN preparation.

## Security boundaries

- System tools and the Python interpreter use fixed paths, with root ownership
  and non-writable resolution components verified. Subprocess environments are
  built from an allowlist; inherited `PATH`, Python startup variables and loader
  overrides are not forwarded. Home comes from the account database. Desktop
  sockets are checked under the user's private runtime directory.
- Ordinary commands have 30-second deadlines and a combined 1 MiB live output
  budget. Root package installation is limited to 600 seconds and 8 MiB, with a
  660-second foreground authentication/caller budget. Guardians own process
  groups, handle caller death, and escalate termination after a one-second
  grace period. Interactive authentication retains the controlling terminal.
- Discovery has a ten-second startup deadline, five-second probe responses,
  renewable fifteen-second leases, an 8 KiB line limit and a 256 KiB/ten-second
  backend output budget. Raw backend output is not forwarded to shell logging.
- Root journals use verified no-follow directory descriptors, an exclusive
  nonblocking lock, private single-link regular files, a 64 KiB read limit and
  an allowlisted schema. Writes use random exclusive temporaries, `fsync` and
  atomic replacement. Unsafe or substituted paths are refused, not repaired.
- Installation verifies source/destination owners and permissions, copies only
  bounded regular files into exclusive destinations and publishes without
  overwriting an existing path. Cleanup removes only this transaction's files
  while the staging directory is still unpublished.

These controls assume a trusted operating system and a reviewed checkout.
Executing this repository as root grants its code root privileges. This is not
a sandbox against malicious same-user code, a compromised root account, or a
compromised PipeWire/receiver implementation. No security certification or
marketplace approval is implied.

## Compatibility and verification

The backend is [PipeWire RAOP discovery](https://docs.pipewire.org/page_module_raop_discover.html)
and its [RAOP sender](https://docs.pipewire.org/page_module_raop_sink.html).
Support depends on the receiver's advertised transport/authentication profile,
not merely an AirPlay logo. PIN/password-protected receivers and AirPlay 2-only
features are not implemented by this plugin. A receiver may be discovered but
reject playback; do not interpret appearance as universal compatibility.

Verified on 2026-09-11 with PipeWire 1.6.8 and a Sonos SYMFONISK **Table lamp
(S20)**:

- Receiver appeared in the actual Omarchy audio panel and was selected there.
- Sonos returned RTSP 200 for authentication, SETUP, and RECORD after allowing
  its previously blocked UDP timing packets.
- Chromium Web Audio and `paplay` both routed to the Sonos sink. The native
  output-switch command moved both live streams back to local speakers.
- Uninstall removed the plugin's sinks and restored the complete prior
  `shell.json` content semantically; network reversal retained existing UFW rules.
- Avahi was already enabled/running and was not changed on this machine.

The tester confirmed audible playback from both the browser and another
application through the SYMFONISK Table lamp receiver. The bookshelf model
remains hardware-unverified. A MacBook receiver was discovered but not
playback-tested. No universal AirPlay or AirPlay 2 compatibility claim is made.

Run the isolated regressions without root or audio hardware:

```sh
/usr/bin/python3 -m unittest -v test_network test_installer test_process test_discovery
```

They cover firewall-policy preservation, interrupted persisted/live rule
reconciliation, Avahi reversal, hostile filesystem entries, atomic publication
and cleanup, poisoned environments, real process-tree termination, foreground
TTY restoration, and discovery acknowledgement/lease failures. Firewall behavior
uses an isolated host model; process and filesystem boundaries use real OS
operations. These tests do not prove audible playback.

Hardware acceptance additionally requires actual browser and non-browser
playback, listener confirmation, local fallback and install/remove/reinstall
checks. The hardware findings above belong to the stated 2026-09-11 session;
they are not a claim of new hardware coverage for each security change.

For the 0.2.0 security release, all 40 isolated regressions passed. A cold-shell
reinstall loaded the compiled 0.2.0 service; Chrome and `paplay` streams moved to
the Sonos sink and back to local speakers. Disabling the plugin terminated its
supervisor, guardian and `pw-cli`; re-enabling rediscovered the receiver and
passed `doctor`. The privileged `network enable` smoke test exited successfully,
preserved the existing scoped UDP 6001–6002 rule and persisted its journal.
It requested no additional ports or Avahi activation. New-rule creation,
reversal and interrupted-operation cases were exercised in the isolated tests,
not repeated against the live firewall for this release. No new listener
confirmation is implied by these security-release checks.

## License

MIT; see `LICENSE`. PipeWire is MIT-licensed. Avahi and the other installed system
components retain their own open-source licenses; their code is not bundled here.
AirPlay, Sonos, IKEA, and Omarchy names identify interoperability targets. This
project is not affiliated with or endorsed by those projects or companies.
