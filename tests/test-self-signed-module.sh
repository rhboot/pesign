#!/bin/bash
# Test self-signed module-only signing certificate setup
# Based on Red Hat documentation

set -e

TEST_NAME="self-signed-module"
WORK_DIR=$(mktemp -d)
trap "rm -rf $WORK_DIR" EXIT

echo "  Setting up self-signed module-only certificate..."

# Create certificate database
mkdir -m 0700 -p "$WORK_DIR/certdb"
echo "" | certutil -d "$WORK_DIR/certdb" -N --empty-password

# Generate self-signed module certificate
./src/efikeygen --dbdir "$WORK_DIR/certdb" \
    --self-sign \
    --module \
    --common-name 'CN=Test Module Signing Key' \
    --nickname 'Test Module Key'

# Verify certificate was created
if ! certutil -d "$WORK_DIR/certdb" -L -n 'Test Module Key' > /dev/null 2>&1; then
    echo "  ERROR: Certificate not created"
    exit 1
fi

# Export certificate
certutil -d "$WORK_DIR/certdb" \
    -n 'Test Module Key' \
    -Lr \
    > "$WORK_DIR/module_cert.cer"

# Verify certificate file exists and is not empty
if [ ! -s "$WORK_DIR/module_cert.cer" ]; then
    echo "  ERROR: Certificate export failed"
    exit 1
fi

echo "  ✓ Self-signed module certificate created successfully"

# Verify trust flags are set (should be u,u,u for user cert)
TRUST=$(certutil -d "$WORK_DIR/certdb" -L | grep "Test Module Key" | awk '{print $NF}')
if [ -z "$TRUST" ]; then
    echo "  ✗ No trust flags found"
    exit 1
else
    echo "  ✓ Trust flags: $TRUST"
fi

# Get test data directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DATA="$SCRIPT_DIR/data"

# Use real kernel and module files
KERNEL="$TEST_DATA/vmlinuz-6.19.10-200.fc43.x86_64"
MODULE="$TEST_DATA/vfat.ko"

# Test signing a kernel (should this work with module cert?)
echo "  Testing kernel signing with module certificate..."
if ./src/pesign --certdir "$WORK_DIR/certdb" \
        --certificate 'Test Module Key' \
        --in "$KERNEL" \
        --sign \
        --out "$WORK_DIR/kernel-signed" 2>"$WORK_DIR/kernel-error.log"; then
    echo "  ⚠ Module cert signed kernel (exit 0)"
    ./src/pesign --show-signature --in "$WORK_DIR/kernel-signed" 2>/dev/null | head -5
else
    echo "  ✓ Module cert rejected for kernel signing (exit $?)"
    [ -s "$WORK_DIR/kernel-error.log" ] && cat "$WORK_DIR/kernel-error.log"
fi

# Test signing a module (should work)
echo "  Testing module signing with module certificate..."
if ./src/pesign --certdir "$WORK_DIR/certdb" \
        --certificate 'Test Module Key' \
        --in "$MODULE" \
        --sign \
        --out "$WORK_DIR/module-signed.ko" 2>"$WORK_DIR/module-error.log"; then
    echo "  ✓ Module cert signed module (exit 0)"
    ./src/pesign --show-signature --in "$WORK_DIR/module-signed.ko" 2>/dev/null | head -5
else
    echo "  ✗ Module cert failed to sign module (exit $?)"
    [ -s "$WORK_DIR/module-error.log" ] && cat "$WORK_DIR/module-error.log"
    exit 1
fi

exit 0
