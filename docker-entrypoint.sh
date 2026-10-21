#!/bin/sh
# Starts the relay, or several processes on one machine, as the unprivileged
# relay user. The data directory is handed to that user first: a platform
# volume is usually owned by root. Nothing here runs as root after that.
#
# One process (the default): runs the relay with this environment.
#
# Several (RELAY_SUPERVISE="name:binary name:binary ..."): runs each binary
# with this environment plus every variable prefixed NAME_ with the prefix
# removed. So PUBLIC_RELAY_MODE=public reaches the process named "public" as
# RELAY_MODE=public. If any process exits, all are stopped and this exits, so
# the platform restarts the machine rather than leaving half of it running.
set -eu
data="${RELAY_DATA_ROOT:-${RELAY_DATA_DIR:-/data}}"
as_relay=""
if [ "$(id -u)" = "0" ]; then
  mkdir -p "$data"
  chown -R relay:relay "$data"
  chmod 700 "$data"
  as_relay="su-exec relay"
fi

if [ -z "${RELAY_SUPERVISE:-}" ]; then
  exec $as_relay /usr/local/bin/relay "$@"
fi

pids=""
stop_all() {
  for p in $pids; do kill "$p" 2>/dev/null || true; done
  wait || true
}
trap 'stop_all; exit 0' TERM INT

for spec in $RELAY_SUPERVISE; do
  name="${spec%%:*}"
  bin="${spec#*:}"
  prefix="$(echo "$name" | tr '[:lower:]-' '[:upper:]_')_"
  (
    env | sed -n "s/^${prefix}//p" | while IFS= read -r kv; do printf '%s\n' "$kv"; done > "/tmp/env.$name"
    while IFS= read -r kv; do export "$kv"; done < "/tmp/env.$name"
    rm -f "/tmp/env.$name"
    exec $as_relay "/usr/local/bin/$bin"
  ) &
  pids="$pids $!"
  echo "started $name ($bin) as pid $!"
done

while :; do
  for p in $pids; do
    if ! kill -0 "$p" 2>/dev/null; then
      echo "process $p exited; stopping the others"
      stop_all
      exit 1
    fi
  done
  sleep 2
done
