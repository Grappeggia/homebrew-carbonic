#!/bin/bash
# Usage: runtime-launch.sh INSTALLED_APP OUT_DIR
# Launches a copy of the installed app for 25 s on this runner and records
# evidence. The copy has quarantine removed only because a headless runner
# cannot perform the user's Open Anyway approval; the installed app keeps it.
set -euo pipefail
APP=$1
OUT=$2
RUN="$(dirname "$OUT")/runtime-copy/Carbonic.app"
rm -rf "$(dirname "$RUN")"
mkdir -p "$(dirname "$RUN")"
ditto "$APP" "$RUN"
xattr -dr com.apple.quarantine "$RUN"
uname -m > "$OUT/runtime-host-arch.txt"
sysctl -n sysctl.proc_translated > "$OUT/runtime-translated.txt" 2>/dev/null || echo 0 > "$OUT/runtime-translated.txt"
system_profiler SPDisplaysDataType > "$OUT/runtime-displays.txt" 2>&1 || true
"$RUN/Contents/MacOS/Carbonic" > "$OUT/runtime.log" 2>&1 &
PID=$!
cleanup() { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; }
trap cleanup EXIT
sleep 25
kill -0 "$PID"
ps -o pid=,etime=,command= -p "$PID" > "$OUT/runtime-process.txt"
screencapture -x "$OUT/runtime.png"
test -s "$OUT/runtime.png"
if grep -q "Could not acquire Metal device" "$OUT/runtime.log"; then
  echo unavailable > "$OUT/runtime-metal.txt"
else
  echo available > "$OUT/runtime-metal.txt"
fi
printf 'PASS process alive after 25 s on %s (metal %s)\n' "$(cat "$OUT/runtime-host-arch.txt")" "$(cat "$OUT/runtime-metal.txt")" > "$OUT/runtime-result.txt"
