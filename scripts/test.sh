#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
export CLANG_MODULE_CACHE_PATH="$PWD/.build/ModuleCache"
export SWIFTPM_MODULECACHE_OVERRIDE="$PWD/.build/ModuleCache"
swift run --disable-sandbox ZapretCoreChecks
python3 scripts/test_capture.py
python3 scripts/test_launch.py
python3 scripts/test_packet.py
