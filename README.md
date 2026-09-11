# Omarchy Air

Open-source AirPlay audio output integration for Omarchy. Receivers appear in
Omarchy's **existing audio output selector**. This is a headless shell service,
not a replacement audio panel, Sonos controller, or new AirPlay implementation.
PipeWire provides discovery, authentication, audio transport, and volume control.

## Requirements

- Omarchy with the Quickshell service-plugin API (`omarchy plugin` commands).
- PipeWire, WirePlumber, `pipewire-pulse`, `pipewire-zeroconf`, Avahi, Python 3.
- An AirPlay receiver that supports PipeWire's RAOP sender, on a reachable LAN.
- An active desktop session. Run setup as your normal user, not root.

## Install

Clone the repository and run the installer:

```sh
git clone https://github.com/SantanaJcp/omarchyair.git
cd omarchyair
python3 setup.py install
python3 setup.py doctor
```

The installer validates the manifest, installs `pipewire-zeroconf` if missing
through `omarchy pkg add`, copies this plugin to
`~/.config/omarchy/plugins/community.omarchyair`, and enables it. An existing
installation is never overwritten. From an installed checkout, the same command
validates dependencies and enables it without copying over itself.

Alternatively, use Omarchy's native plugin manager:

```sh
omarchy plugin add https://github.com/SantanaJcp/omarchyair.git --yes
python3 ~/.config/omarchy/plugins/community.omarchyair/setup.py install
```

The native plugin manager clones the repository without running its code or
installing dependencies. Review the plugin before running its installer.

## Network preparation (only when needed)

Discovery requires Avahi and mDNS. RAOP UDP playback also requires the receiver's
control/timing packets to reach this computer. Do not disable your firewall.
Check the current interface and directly connected subnet with `ip -4 route`.
For example, **substitute your own interface and subnet**:

```sh
sudo python3 network.py enable --interface wlan0 --subnet 192.168.1.0/24
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
python3 setup.py doctor
omarchy plugin disable community.omarchyair
omarchy plugin enable community.omarchyair
```

The service owns a managed `pw-cli` child. Disabling/removing the plugin or
reloading the shell terminates that child and removes its sinks. Re-enable the
plugin if its process exits after an audio-server failure. No restart loop hides
errors. `status` reports process state and discovered sinks, **not proof that a
speaker played sound**. `doctor` exits 0 only when prerequisites, discovery
process, and at least one RAOP sink are present; it is not an auditory test.

## Revert

First select a local output, then from the original repository:

```sh
python3 setup.py uninstall
sudo python3 network.py disable
```

The first command uses Omarchy's native plugin removal (manual installations
are backed up by Omarchy). The second removes only recorded firewall rules and
restores Avahi state only if this helper changed it. If a managed firewall rule
was edited, removal stops for inspection rather than deleting someone else's
rule. Shared packages are intentionally retained; they may have other users.
No PipeWire configuration files, existing bar layout, or unrelated settings are
replaced. To reinstall, repeat the installation and any needed LAN preparation.

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

Run the focused preservation regressions without root:

```sh
python3 -m unittest -v test_network
```

They cover existing firewall policy preservation, edited managed rules,
idempotent reversal, and Avahi service/socket restoration using an isolated host
model. They do not simulate or prove Sonos audio. Hardware acceptance additionally
requires browser and non-browser playback, listener confirmation, local fallback,
and real install/uninstall/reinstall checks.

## License

MIT; see `LICENSE`. PipeWire is MIT-licensed. Avahi and the other installed system
components retain their own open-source licenses; their code is not bundled here.
AirPlay, Sonos, IKEA, and Omarchy names identify interoperability targets. This
project is not affiliated with or endorsed by those projects or companies.
