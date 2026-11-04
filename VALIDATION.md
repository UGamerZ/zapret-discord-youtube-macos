# Validation — macOS packet backend 0.2.2

2026-11-05, Apple Silicon build host, Swift 6.3.3 and Apple Command Line Tools.

Reported live attempt on 2026-11-05: packet.log contained `nohup: can't detach from console: No such process`; status was stopped with zero packets. The engine had not started. Version 0.2.1 replaces that launch path, adds exec acknowledgement/PID monitoring, and displays log details on startup failure.

The next reported attempt reached transport setup but lost its failure detail. The old `inbound and ...` Ethernet filter was reproduced with system libpcap: `inbound/outbound not supported on Ethernet`. Version 0.2.2 removes that qualifier, selects incoming direction using the API, preserves all setup errors in structured fields and avoids loading-message dumps in the alert.

Checks performed without changing the user's network preferences or PF configuration:

- Real libpcap regression: old Ethernet qualifier rejected; replacement filter compiles and matches SYN/ACK but rejects SYN, ACK and RST, for IPv4 and IPv6. Structured stage/detail/code survive JSON serialization with quotes, backslashes and control characters. Swift formatter excludes routine loading output and bounds alert length.
- Native-launcher regression tests pass without a controlling console, with all inherited streams redirected to /dev/null. Child stdin is EOF; stdout/stderr and PID are correctly recorded. Failed exec returns its concrete error immediately. Symlink log paths are refused.
- Original nfq/desync C engine plus new macOS adapter compiled for arm64 and x86_64.
- All 22 pinned Flowseal BAT argument profiles parsed and accepted by the actual zapret CLI, with game capture filters disabled and enabled (44 configurations).
- Seven Swift core checks: legacy proxy-state parsing/recovery serialization, malformed-output rejection, disabled proxy handling, authentication/ownership, hostile-string shell quoting, and exact-profile/game-range expansion, and concise structured startup diagnostics.
- PCAP replay executes the actual original C engine. `general` checked for both IPv4 and IPv6: seq offset -681, exact 681-byte fake prefix, real segment offsets, original tuple, IPv4 ID zero, IPv4/TCP checksums, and reconstruction of the unmodified TLS request.
- Discord discovery checked for IPv4 and IPv6: six exact bundled ACTIVE_DISCORD_UDP fake payloads followed by the unchanged original request, valid checksums and preserved tuple.
- FAKE TLS AUTO: both repeated fake-TLS options preserved (22 fake emissions), badseq sequence and acknowledgement offsets, SNI modification and reverse segment order.
- ALT: 32 packets, timestamp fooling and fake split pattern checked.
- QUIC IPv4/IPv6: exact six fake payloads and original datagram, with disabled and loaded IPSet gates checked separately.
- Software TSO IPv4/IPv6: oversized TCP input segmented below physical MTU with correct sequence numbers, checksums and full stream reconstruction.
- All 22 profiles produced replacement packets for a matching TLS flow in replay.
- The generated PF rule grammar passed system pfctl -n parsing without applying rules.
- Revised GUI launched and inspected: all 22 original configs, method summaries, game mode, and all three IPSet modes are present.
- Universal app bundle assembled and ad hoc codesign verified.

These are offline packet tests, not proof of a live working bypass. Live PF loading, private pflog capture, Ethernet injection on this particular Wi-Fi adapter, hardware offload/MTU behavior, supervisor recovery after real crashes, OS administrator authorization, Intel runtime execution, ISP-specific filtering and Discord voice were not validated. No claim is made that live UDP voice bypass has succeeded.

Reproduce:

```sh
./scripts/build.sh
./scripts/test.sh
```

To validate the actual transport, launch the app, authorize Connect, restart the affected application's connections, verify captured/emitted/suppressed counters, test real YouTube/Discord use, then verify Disconnect and recovery. This requires interactive administrator authorization and temporary changes to the Mac's packet filtering.
