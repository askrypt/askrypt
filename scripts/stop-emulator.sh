#!/usr/bin/env bash
# Stop running Askrypt Android emulator(s).
#
# By default kills every running emulator via `adb emu kill` (clean shutdown).
# Pass a specific serial to target just one.
#
# Usage:
#   scripts/stop-emulator.sh                 # stop all running emulators
#   scripts/stop-emulator.sh emulator-5554   # stop a specific one
set -euo pipefail

export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
ADB="$ANDROID_HOME/platform-tools/adb"

if [[ ! -x "$ADB" ]]; then
  echo "error: adb not found at $ADB" >&2
  exit 1
fi

# Collect target serials: the argument if given, else all attached emulators.
if [[ $# -gt 0 ]]; then
  targets=("$@")
else
  mapfile -t targets < <("$ADB" devices | awk '/^emulator-[0-9]+\t/ {print $1}')
fi

if [[ ${#targets[@]} -eq 0 ]]; then
  echo "No running emulators found."
  exit 0
fi

for serial in "${targets[@]}"; do
  echo "Stopping $serial..."
  "$ADB" -s "$serial" emu kill || echo "  (could not signal $serial; it may already be down)"
done

# Give them a moment, then report what's left.
sleep 2
remaining="$("$ADB" devices | awk '/^emulator-[0-9]+\t/ {print $1}')"
if [[ -n "$remaining" ]]; then
  echo "Still running: $remaining"
else
  echo "All emulators stopped."
fi
