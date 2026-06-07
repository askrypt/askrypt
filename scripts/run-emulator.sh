#!/usr/bin/env bash
# Launch the Askrypt Android emulator.
#
# The system image (~4 GB) and the AVD live on the roomy data disk
# (/media/ruslan/data/android) because the home/root partition is nearly full.
# This script wires up the env vars that point the SDK tools at those locations,
# then boots the AVD with KVM hardware acceleration.
#
# Usage:
#   scripts/run-emulator.sh                 # boot the default AVD (windowed)
#   scripts/run-emulator.sh -no-window      # headless (e.g. for CI / flutter test)
#   AVD=other_avd scripts/run-emulator.sh   # boot a different AVD
#
# Any extra arguments are passed straight through to the `emulator` binary.
set -euo pipefail

export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
# AVDs (incl. the growable userdata.img) live off the full root partition.
export ANDROID_AVD_HOME="${ANDROID_AVD_HOME:-/media/ruslan/data/android/avd}"

AVD="${AVD:-askrypt_api36}"
EMULATOR="$ANDROID_HOME/emulator/emulator"

if [[ ! -x "$EMULATOR" ]]; then
  echo "error: emulator not found at $EMULATOR" >&2
  exit 1
fi

if ! "$EMULATOR" -list-avds | grep -qx "$AVD"; then
  echo "error: AVD '$AVD' not found. Available:" >&2
  "$EMULATOR" -list-avds >&2
  exit 1
fi

if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  echo "warning: /dev/kvm is not accessible — the emulator will be slow." >&2
fi

echo "Booting AVD '$AVD' (KVM accelerated)..."
exec "$EMULATOR" -avd "$AVD" \
  -accel on \
  -gpu host \
  -no-snapshot \
  -no-boot-anim \
  "$@"
