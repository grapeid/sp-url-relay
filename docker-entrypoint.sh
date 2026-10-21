#!/bin/sh
# Give the data directory to the relay user, then run the relay as that user.
# The relay never runs as root.
set -eu
dir="${RELAY_DATA_DIR:-/data}"
if [ "$(id -u)" = "0" ]; then
  mkdir -p "$dir"
  chown -R relay:relay "$dir"
  chmod 700 "$dir"
  exec su-exec relay /usr/local/bin/relay "$@"
fi
exec /usr/local/bin/relay "$@"
