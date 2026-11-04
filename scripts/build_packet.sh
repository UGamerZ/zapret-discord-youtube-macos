#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .build/packet
for ARCH in arm64 x86_64; do
    clang -std=gnu99 -O2 -flto -Wno-address-of-packed-member -DZAPRET_MAC_PACKET \
        -target "${ARCH}-apple-macos13.0" -IPacketEngine -IThirdParty/nfq \
        PacketEngine/mac_packet.c PacketEngine/mac_launch.c PacketEngine/mac_capture.c PacketEngine/mac_diagnostics.c ThirdParty/nfq/*.c ThirdParty/nfq/crypto/*.c \
        -lz -lpcap -o ".build/packet/zapret-packet-${ARCH}"
done
lipo -create .build/packet/zapret-packet-arm64 .build/packet/zapret-packet-x86_64 -output .build/packet/zapret-packet
