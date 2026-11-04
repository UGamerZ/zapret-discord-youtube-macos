# Zapret macOS 0.2.2 — Flowseal packet engine

This replaces the earlier SOCKS adaptation. It uses **all 22 original Flowseal BAT configurations and bol-van's original C packet/desynchronization engine**, with a new macOS PFLOG/BPF backend. The SwiftUI interface follows trankesh's dark compact desktop GUI.

The important difference: it can construct and emit actual TCP/UDP packets, including fake payloads, negative sequence overlaps, bad sequence/acknowledgement numbers, TCP timestamps, repeat counts, and IPv4 IP IDs. It does not substitute socket-level splitting for these operations.

**Experimental transport:** builds and packet replay tests pass. Live administrator-authorized PF/BPF interception, end-to-end recovery, Discord voice and ISP bypass have NOT been verified on this machine. Do not treat replay success as a working-network certification.

## Capture and diagnostic fix in 0.2.2

The old incoming capture filter used the `inbound` BPF qualifier, which system libpcap rejects for Ethernet: `inbound/outbound not supported on Ethernet`. That failure returned without preserving its cause. Direction is now selected with `pcap_setdirection(PCAP_D_IN)`, while the IPv4/IPv6 SYN/ACK filter uses portable packet fields.

Every transport setup step now records a stage, concise reason, actual OS/libpcap/tool detail and error code in status.json and packet.log. The alert displays that structured error and omits routine host/IP list loading. It provides Copy error and Open log actions. Offline regression tests reproduce the old compiler failure, accept the actual replacement filter, check IPv4/IPv6 matching, verify error serialization, and check compact alert text. Live capture direction selection still requires a real administrator-authorized run.

## Startup fix in 0.2.1

The first attempted live launch failed before entering the packet engine: system nohup returned `can't detach from console: No such process`. No packets were processed in that session. This version launches through native fork/setsid/exec with redirected streams, an exec acknowledgement and a PID file. It does not use nohup or require a console. A startup process that exits is reported immediately, and the alert includes the tail of packet.log.

The native launcher has been tested with stdin/stdout/stderr connected to /dev/null, without a terminal and without root. The privileged packet path still needs live validation.

## Run

macOS 13+, Apple Silicon or Intel. Open `dist/Zapret macOS.app`. All executable components are universal and ad hoc signed; this is not a Developer ID signed or notarized release.

1. Choose an original Flowseal config, starting with `general`.
2. Set Game mode while disconnected if needed. Off preserves Flowseal's port-12 sentinel; on uses its default TCP/UDP range 1024–65535.
3. Press Connect and authorize the packet engine with macOS. Unlike the old version, it requires root while running to use PF and BPF.
4. Restart existing browser/Discord connections. Kernel PF states created before connection may bypass the new rules. The app never flushes unrelated system states.
5. Inspect packet counters in Settings, then verify the actual applications on the affected network. Disconnect removes the session's interception rules and releases its PF enable reference.

Closing the window leaves the menu-bar app running. Quit stops interception. A supervisor watches the GUI's process identity and also stops on GUI exit/crash. No LaunchDaemon, kext, NetworkExtension, DNS change, hosts update, SOCKS proxy, or permanent firewall configuration is installed.

**Find a strategy** performs direct HTTP probes, then applies the original packet profiles in turn. It changes PF temporarily and requests administrator authorization. Testing all 22 profiles can take several minutes. HTTP success does not verify video playback, UDP voice, or filtering bypass. Packet activity is aggregate and can include other applications.

## Packet path

```text
Application's real socket
        ↓
PF: log matching outbound TCP/UDP to a private pflog interface, block original
        ↓
New macOS adapter reads complete PFLOG IP packets
        ↓
Original zapret matcher, conntrack, TLS/QUIC parser and desync engine
        ↓
BPF writes Ethernet frames to the original physical uplink
        ↓
Gateway → server; replies arrive normally in the application's original socket
```

Addresses and ports are preserved. No userspace TCP stack, NAT or external relay is introduced. IPv4 header checksums that raw-socket output would normally fill are completed by the adapter. Deliberately wrong TCP/UDP checksums used for fooling are preserved. Pre-TSO TCP superpackets are segmented in software to the physical MTU before Ethernet injection, preserving the TCP byte stream and deliberate checksum corruption. Incoming SYN/ACKs are observed for conntrack feedback; incoming traffic is not blocked or rewritten.

PFLOG is a bounded capture buffer, **not** a kernel packet queue with backpressure. Capture drops and injection failures stop interception, allowing later packets to use the ordinary kernel path. A lost UDP datagram cannot be recovered by removing the rules; applications may need reconnecting.

## Configuration parity

`Resources/flowseal/configs` contains the pinned original BAT files. `scripts/import_flowseal.py` parses only their winws argument region; it never executes batch commands. It preserves argument order, repeated fake payload options, filters, include/exclude lists, `--new` profile chains, numeric settings and fake binary contents. It translates only:

- `%BIN%` and `%LISTS%` into bundled resource paths;
- `%GameFilterTCP%` / `%GameFilterUDP%` into the original disabled sentinel or enabled default range;
- CMD's escaped `^!` into the literal `!` expected by zapret;
- `--wf-tcp` / `--wf-udp` into equivalent macOS capture-port windows.

Every remaining option goes to the original zapret command-line parser and implementation. Unknown flags fail; there is no SOCKS fallback or silent method downgrade. The IPSet selector mirrors disabled (the upstream sentinel), loaded (the supplied original backup ranges), and any (an empty unrestricted list). User-list placeholders are supplied as empty files; the other lists and fake payloads are pinned snapshots, not live updates. UI editing of lists and custom game ranges is not implemented.

Examples verified in byte-level replay:

- `general`: `multisplit`, `seqovl=681`, exact fake TLS prefix, zero IPv4 ID, valid checksums and original TLS stream reconstruction.
- `FAKE TLS AUTO`: both configured fake-TLS entries, each repeated 11 times, bad sequence/ack offsets, SNI mutation and reverse segment order. Collapsing those repeated fake options would change the behavior.
- `ALT`: 32 emitted packets for the tested TLS flow, timestamp fooling and exact fake split patterns.
- Discord UDP: six exact ACTIVE_DISCORD_UDP fake datagrams before the real 74-byte IP-discovery request, with original addresses and ports, for IPv4 and IPv6.

See `VALIDATION.md` for the limits of the checks and `PACKET_RESEARCH.md` for sources.

## Runtime requirements and boundaries

The adapter needs an Ethernet-compatible physical uplink that supports BPF Ethernet injection. Typical Wi-Fi/Ethernet interfaces expose this, but support is checked at runtime. VPN/PPP/tunnel interfaces are refused. If IPv4 and IPv6 have different default uplinks, startup fails instead of silently covering only one. If only one IP family has an internet default route, only that family is intercepted.

The active PF ruleset must already reference Apple's `com.apple/*` wildcard anchor. The engine loads only its own child anchor and never rewrites `/etc/pf.conf`, flushes global states, or disables PF globally. Other firewall rules, socket owners that PF cannot identify, root-owned traffic, unusual offload/MTU behavior and OS changes can affect coverage. Local/private/multicast addresses and the physical interface's local networks are excluded from interception. Flowseal's more specific lists and L7/IP filtering remain in the original engine.

The supplied configs are outbound strategies. Arbitrary new configs needing inbound suppression/rewriting are not supported by this backend. This is not a claim of universal winws compatibility. DNS resolution is unchanged, so DNS poisoning can still prevent connections.

The interface and default gateway are checked while running. A route/uplink change, missing own PF rules, packet-worker failure, capture overflow or injection failure stops the session. Reconnect after changing networks. System sleep/wake and kernel PF behavior need live testing on each supported macOS release.

## Session and recovery

Root-owned runtime state is in `/var/run/zapret-macos-UID/`: `packet.log`, `status.json`, `rules.conf`, lock, control socket and the session's PF reference token. The stop socket accepts only a fixed stop request from the initiating UID or root; it is not an arbitrary privileged command interface.

The root supervisor clears the own anchor before stopping the worker. The worker also attempts cleanup if its supervisor disappears. A new Connect first recovers a stale own anchor and PF reference, refusing to interfere with a running session. If cleanup needs retry, the GUI shows a recovery action. Killing both root processes simultaneously can still leave stale rules until recovery or reboot; no background launch service is installed to recover after every possible failure.

If the GUI cannot perform recovery, the bundled helper supports:

```sh
sudo '/path/to/Zapret macOS.app/Contents/Resources/zapret-packet' --mac-recover YOUR_NUMERIC_UID
```

Use `id -u` for your numeric UID. Recovery clears only `com.apple/zapretmac-UID` and its saved PF reference. A crashed session may leave an unused private pflog interface; recovery does not destroy a possibly reused stale interface. Runtime files disappear on reboot. The earlier 0.1 SOCKS journal is detected separately and must be restored before packet-mode connection.

## Build and test

Requires Apple Command Line Tools, Swift 5.9+, clang and Python 3 (provided by the current Command Line Tools installation). System libpcap and zlib are used; no dependency downloads are needed.

```sh
./scripts/build.sh
./scripts/test.sh
```

The build imports the original configs, builds the original engine plus macOS backend for arm64 and x86_64, builds a universal SwiftUI executable, assembles the bundle and ad hoc signs it. Tests do not request root, edit PF, create live packet captures or send network packets. They exercise the actual engine offline with PCAP input/output, not an independently implemented approximation of the algorithms.

Open Package.swift to edit the GUI; use the script to assemble its packet engine and resources. `swift run` alone does not produce a complete application bundle.

Independent, unofficial project. See THIRD_PARTY.md and bundled licenses.
