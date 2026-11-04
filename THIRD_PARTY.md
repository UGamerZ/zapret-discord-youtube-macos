# Source provenance — packet version 0.2.2

Retrieved 2026-11-05. Pinned snapshots; no automatic downloads or updates.

| Project | Commit | Used here | License |
| --- | --- | --- | --- |
| https://github.com/bol-van/zapret | 73ee2aa04e6e94922e7dc07554a1c3a456dc3201 | Original nfq C engine, parsers, conntrack, packet construction, crypto and desync operations; patched only at platform entry/emission boundaries | MIT plus embedded crypto notices; ThirdParty/ZAPRET-LICENSE.txt and ThirdParty/CRYPTO-LICENSE.txt |
| https://github.com/Flowseal/zapret-discord-youtube | 2401b7a13837139b0265632464ba563dddbf80d8 | All 22 original general BAT configs, binary fake payloads, include/exclude lists and full IPSet backup | MIT; ThirdParty/FLOWSEAL-LICENSE.txt |
| https://github.com/trankesh/zapret-youtube-discord-gui | cb05f0f5645658ccf987cea94a2a5e045b370895 | UI layout reference, application icon, unchanged PT Root UI font | MIT for GUI; SIL OFL 1.1 for font |

Original engine adaptations in ThirdParty/nfq:

- `nfqws.c`: include the adapter interface, rename main so the macOS wrapper can consume its own transport options, and invoke the new transport instead of the unusable BSD divert loop.
- `darkmagic.c`: retain original packet construction and helpers; rename unused BSD raw-output functions and route the public rawsend API to the new BPF/PCAP emitter.
- No desync algorithms, matching rules, built-in fake payloads, QUIC code or crypto were rewritten.

`PacketEngine/mac_capture.c` supplies the Ethernet SYN/ACK filter and `mac_diagnostics.c` supplies structured setup error reporting. `PacketEngine/mac_launch.c` supplies the console-independent native launcher. `PacketEngine/mac_packet.c` is the local macOS transport, supervisor, stop/recovery interface and offline replay driver. `scripts/import_flowseal.py` imports the original config arguments. `Sources` is the local SwiftUI application and core data/command code. The unneeded upstream windows directory and its platform binary libraries are omitted from the source distribution. Windows binaries are not used by the app.

The separate https://github.com/naladwepo/zapret-for-mac repository was read as a transport-design reference at commit 763790eb671b7bc5d89399b8af46ebed70a39f0d. Its Go engine/daemon are not included. See PACKET_RESEARCH.md for primary OS references and the PFLOG header-alignment detail informed by that project.

PT Root UI: Copyright © 2018 ParaType Inc., ParaType Ltd. Unchanged font, SIL OFL 1.1; ThirdParty/FONT-OFL.txt. No system-wide font installation.
