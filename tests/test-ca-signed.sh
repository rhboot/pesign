#!/bin/bash
# Test CA and signing certificate setup
# Based on AlmaLinux documentation

set -e

TEST_NAME="ca-signed"
WORK_DIR=$(mktemp -d)
trap "rm -rf $WORK_DIR" EXIT

echo "  Setting up CA and signing certificates..."

# Create certificate database
mkdir -m 0700 -p "$WORK_DIR/ca"
echo "" | certutil -d "$WORK_DIR/ca" -N --empty-password

# Generate CA certificate
./src/efikeygen -d "$WORK_DIR/ca" \
    --ca --self-sign \
    --not-valid-after=$(date +%s --date='+10 years') \
    --nickname='Test Secure Boot CA' \
    --common-name='CN=Test Secure Boot CA,O=Test Organization,E=test@example.com'

# Verify CA was created
if ! certutil -d "$WORK_DIR/ca" -L -n 'Test Secure Boot CA' > /dev/null 2>&1; then
    echo "  ERROR: CA certificate not created"
    exit 1
fi

# Generate signing certificate signed by CA (marked as --kernel)
./src/efikeygen -d "$WORK_DIR/ca" \
    --kernel \
    --not-valid-after=$(date +%s --date='+10 years') \
    --signer='Test Secure Boot CA' \
    --nickname='Test Secure Boot Signing' \
    --common-name='CN=Test Secure Boot Signing,O=Test Organization,E=test@example.com'

# Verify signing certificate was created
if ! certutil -d "$WORK_DIR/ca" -L -n 'Test Secure Boot Signing' > /dev/null 2>&1; then
    echo "  ERROR: Signing certificate not created"
    exit 1
fi

# Export certificates
certutil -d "$WORK_DIR/ca" -L -n "Test Secure Boot CA" -r > "$WORK_DIR/test-secureboot-ca.cer"
certutil -d "$WORK_DIR/ca" -L -n "Test Secure Boot Signing" -r > "$WORK_DIR/test-secureboot.cer"

# Verify certificate files exist and are not empty
if [ ! -s "$WORK_DIR/test-secureboot-ca.cer" ]; then
    echo "  ERROR: CA certificate export failed"
    exit 1
fi

if [ ! -s "$WORK_DIR/test-secureboot.cer" ]; then
    echo "  ERROR: Signing certificate export failed"
    exit 1
fi

echo "  ✓ CA and signing certificates created successfully"

# Get test data directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DATA="$SCRIPT_DIR/data"

# Use real kernel and module files
KERNEL="$TEST_DATA/vmlinuz-6.19.10-200.fc43.x86_64"
MODULE="$TEST_DATA/vfat.ko"

# Test signing a kernel (should work - cert was created with --kernel)
echo "  Testing kernel signing with CA-signed certificate..."
if ./src/pesign --certdir "$WORK_DIR/ca" \
        --certificate 'Test Secure Boot Signing' \
        --in "$KERNEL" \
        --sign \
        --out "$WORK_DIR/kernel-signed" 2>"$WORK_DIR/kernel-error.log"; then
    echo "  ✓ CA-signed cert signed kernel (exit 0)"
    ./src/pesign --show-signature --in "$WORK_DIR/kernel-signed" 2>/dev/null | head -5
else
    echo "  ✗ CA-signed cert failed to sign kernel (exit $?)"
    [ -s "$WORK_DIR/kernel-error.log" ] && cat "$WORK_DIR/kernel-error.log"
    exit 1
fi

# Test signing a module (kernel certs can sign modules)
echo "  Testing module signing with CA-signed certificate..."
if ./src/pesign --certdir "$WORK_DIR/ca" \
        --certificate 'Test Secure Boot Signing' \
        --in "$MODULE" \
        --sign \
        --out "$WORK_DIR/module-signed.ko" 2>"$WORK_DIR/module-error.log"; then
    echo "  ✓ CA-signed cert signed module (exit 0)"
    ./src/pesign --show-signature --in "$WORK_DIR/module-signed.ko" 2>/dev/null | head -5
else
    echo "  ✗ CA-signed cert failed to sign module (exit $?)"
    [ -s "$WORK_DIR/module-error.log" ] && cat "$WORK_DIR/module-error.log"
    exit 1
fi

exit 0
