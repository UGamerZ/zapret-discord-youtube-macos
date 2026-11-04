# Packet-method research and design

Investigated 2026-11-05. Source snapshots are recorded in THIRD_PARTY.md.

## Why the first SOCKS implementation was insufficient

Flowseal's `general.bat` specifies a fake TLS prefix *outside* the valid TCP stream window: seq minus 681, then a 1-byte genuine segment, with a second genuine segment beginning at seq plus 1. A TCP socket cannot choose the sequence number of its writes. UDP profiles also emit repeated QUIC/Discord/STUN payloads from the application's real tuple. `tpws` cannot reproduce those wire operations.

Authoritative method definitions are the original [Flowseal configs](https://github.com/Flowseal/zapret-discord-youtube) and [zapret desync implementation](https://github.com/bol-van/zapret/blob/master/nfq/desync.c), not similar-sounding proxy features. This port therefore retains that C implementation and its parser, host/IP filters, QUIC classifier/decryptor, conntrack and binary payloads.

## macOS interception

Upstream's [BSD/macOS notes](https://github.com/bol-van/zapret/blob/master/docs/bsd.en.md#macos) explain why compiling `dvtws` does not provide a usable divert queue on macOS. Apple's [NetworkExtension explanation](https://developer.apple.com/videos/play/wwdc2025/234/) says filter providers return verdicts rather than modifying traffic. A packet tunnel is a different forwarding architecture and does not by itself supply WinDivert semantics.

Apple publishes the underlying [PFLOG implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_pflog.c) and [BPF implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/bpf.c). PF can log a matching packet and block its original; a BPF writer can supply replacement link-layer frames. This is the architecture used here. It relies on lower-level OS facilities rather than a stable Apple application-level packet editing API, and runtime compatibility needs live testing.

The [naladwepo macOS port](https://github.com/naladwepo/zapret-for-mac), inspected at 763790eb671b7bc5d89399b8af46ebed70a39f0d, supplied a useful independent example of PFLOG/BPF transport, including the need to align the logged header length to a BPF word boundary. Its Go packet engine and daemon are not bundled or executed here. This project's macOS adapter, supervisor and SwiftUI integration were implemented locally, using the original bol-van packet algorithms instead of that port's reimplementation.

## Important differences from a real divert queue

PFLOG can overflow. It does not hold an original packet pending a userspace verdict. The original has already been blocked; losing its capture cannot be undone. The backend checks capture-drop statistics and stops on overflow rather than claiming reliable processing. It also stops on BPF write failure, uplink drift or disappearance of its anchor.

Live traffic may also contain hardware-checksum/offload representations. The backend fixes checksums on captured originals before processing. On output it fills the IPv4 header checksum that upstream expects the raw-socket kernel path to calculate, and deliberately does not repair L4 checksums after desync because that would undo `badsum` fooling.

Only the supplied outbound Flowseal configurations are in scope. Incoming SYN/ACK observation is feedback, not an inbound divert queue. Methods requiring inbound suppression need additional work and must not be described as supported merely because the upstream parser accepts their names.
