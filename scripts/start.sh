#!/bin/bash
set -e

echo "=== Tunneling Hub Server ==="

bash scripts/install.sh

if [ ! -f bin/relay ]; then
    echo "Building M35 relay server..."
    CGO_ENABLED=0 go build -o bin/relay ./cmd/relay
else
    echo "Relay server binary found (pre-built)."
fi

echo "Starting M35 url-relay on port 5000..."
RELAY_APEX="${RELAY_APEX:-relay.grapeid.org}" SQLITE_PATH="${SQLITE_PATH:-./data/relay.db}" ./bin/relay &
API_PID=$!
sleep 1

echo "Starting Chisel server on port 8080..."
./bin/chisel server --auth user:secret-token --port 8080 --reverse &
CHISEL_PID=$!

echo ""
echo "=== All services started ==="
echo "  API server:    port 5000 (public, handles routing)"
echo "  Chisel server: port 8080 (tunnel endpoint)"
echo ""
echo "API endpoints (on port 5000):"
echo "  GET  /check-name?name=alice"
echo "  POST /claim-name  {\"name\": \"alice\"}"
echo "  GET  /status"
echo ""

cleanup() {
    echo "Shutting down services..."
    kill $API_PID $CHISEL_PID 2>/dev/null
    wait
}
trap cleanup EXIT INT TERM

wait -n
echo "A process exited unexpectedly. Shutting down..."
cleanup
