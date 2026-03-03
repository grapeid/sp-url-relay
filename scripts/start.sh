#!/bin/bash
set -e

echo "=== Tunneling Hub Server ==="

bash scripts/install.sh

if [ ! -f bin/api ]; then
    echo "Building API server..."
    CGO_ENABLED=0 go build -o bin/api ./cmd/api
else
    echo "API server binary found (pre-built)."
fi

echo "Starting API server on port 5000..."
./bin/api &
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
