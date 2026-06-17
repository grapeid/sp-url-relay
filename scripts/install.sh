#!/bin/bash
set -e

# GHSA-38jh-8h67-m7mj: AUTH env ignored before v1.10.0 — use --auth in start.sh.
CHISEL_VERSION="1.10.1"
BIN_DIR="./bin"

mkdir -p "$BIN_DIR"

if [ ! -f "$BIN_DIR/chisel" ]; then
    echo "Downloading chisel v${CHISEL_VERSION}..."
    curl -sL "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_amd64.gz" -o /tmp/chisel.gz
    gunzip -f /tmp/chisel.gz
    mv /tmp/chisel "$BIN_DIR/chisel"
    chmod +x "$BIN_DIR/chisel"
    echo "Chisel installed."
else
    echo "Chisel already installed."
fi

echo "All dependencies installed."
