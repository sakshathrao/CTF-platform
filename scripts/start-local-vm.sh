#!/usr/bin/env bash
#
# CTF Platform — Local VM Runner with Loopback-Only Port Forwarding
#
# Binds to 127.0.0.1 only:
#   - SSH: 127.0.0.1:2222 -> Guest port 22
#   - FTP Control: 127.0.0.1:2121 -> Guest port 21
#   - FTP Passive Data: 127.0.0.1:2122 -> Guest port 2122
#
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${PROJECT_ROOT}/public/images/customBzImage"

if [ ! -f "$IMAGE" ]; then
    echo "Error: Kernel image not found at $IMAGE" >&2
    exit 1
fi

QEMU_BIN="$(command -v qemu-system-i386 || command -v qemu-system-x86_64 || true)"
if [ -z "$QEMU_BIN" ]; then
    echo "Error: QEMU binary not found in PATH" >&2
    exit 1
fi

echo "Starting local CTF VM with loopback-only port forwarding..."
echo "  SSH:         127.0.0.1:2222 (Forwarded to guest:22)"
echo "  FTP Control: 127.0.0.1:2121 (Forwarded to guest:21)"
echo "  FTP Passive: 127.0.0.1:2122 (Forwarded to guest:2122)"
echo "  LAN Access:  Strictly blocked (127.0.0.1 binding only)"
echo ""

exec "$QEMU_BIN" \
    -kernel "$IMAGE" \
    -m 64M \
    -nographic \
    -append "console=ttyS0 quiet" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:2121-:21,hostfwd=tcp:127.0.0.1:2122-:2122" \
    -device "virtio-net-pci,netdev=net0"
