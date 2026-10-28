#!/usr/bin/env bash
set -e

echo "[ENTRYPOINT] Starting Streamion with Cloudflare WARP SOCKS5 Proxy"

export HOST="${HOST:-0.0.0.0}"
export PORT="${PORT:-7860}"
export SOCKS_PORT="${SOCKS_PORT:-1080}"
export WIREGUARD_INTERFACE_DNS="${WIREGUARD_INTERFACE_DNS:-1.1.1.1}"

if [[ -z "${WIREGUARD_INTERFACE_PRIVATE_KEY}" ]]; then
    echo "[ENTRYPOINT] Generating Cloudflare Warp configuration..."
    
    WARP_OUTPUT=$(warp || true)
    
    if [[ -n "$WARP_OUTPUT" ]]; then
        export WIREGUARD_INTERFACE_PRIVATE_KEY=$(echo "$WARP_OUTPUT" | grep "PrivateKey" | awk '{print $3}')
        export WIREGUARD_INTERFACE_ADDRESS=$(echo "$WARP_OUTPUT" | grep "Address" | awk '{print $3}')
        export WIREGUARD_PEER_PUBLIC_KEY=$(echo "$WARP_OUTPUT" | grep "PublicKey" | awk '{print $3}')
        export WIREGUARD_PEER_ENDPOINT=$(echo "$WARP_OUTPUT" | grep "Endpoint" | awk '{print $3}')
        echo "[ENTRYPOINT] Warp config generated successfully"
    else
        echo "[WARN] warp CLI command failed or returned empty, server will auto-generate WARP directly"
    fi
else
    echo "[ENTRYPOINT] Using provided WireGuard configuration"
fi

echo "[ENTRYPOINT] Starting SOCKS5 proxy server on port ${SOCKS_PORT}..."
server &
SERVER_PID=$!

echo "[ENTRYPOINT] Waiting for WireGuard tunnel to stabilize..."
sleep 4

echo "[ENTRYPOINT] Testing tunnel connectivity..."
TRACE=$(curl -s --max-time 10 --socks5 127.0.0.1:${SOCKS_PORT} https://cloudflare.com/cdn-cgi/trace 2>&1 || true)
if echo "$TRACE" | grep -q "ip="; then
    echo "[ENTRYPOINT] Tunnel OK — proxy IP info:"
    echo "$TRACE" | grep -E "ip=|loc=|warp="
else
    echo "[WARN] Tunnel test inconclusive, response was:"
    echo "$TRACE"
fi

echo "[ENTRYPOINT] Setting proxy environment..."
export ALL_PROXY="socks5://127.0.0.1:${SOCKS_PORT}"
export HTTPS_PROXY="socks5://127.0.0.1:${SOCKS_PORT}"
export HTTP_PROXY="socks5://127.0.0.1:${SOCKS_PORT}"

echo "[ENTRYPOINT] Starting Streamion on ${HOST}:${PORT}..."
exec deno task dev
