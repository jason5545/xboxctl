#!/bin/sh
# Builds nano-ble.app (ad-hoc signed) next to this script:
#   tools/nano-ble-bridge/build.sh && xboxctl nano-probe --ble tools/nano-ble-bridge/nano-ble.app
set -e
cd "$(dirname "$0")"
mkdir -p nano-ble.app/Contents/MacOS
cp Info.plist nano-ble.app/Contents/Info.plist
swiftc -O main.swift -o nano-ble.app/Contents/MacOS/nano-ble
codesign -s - --force nano-ble.app
