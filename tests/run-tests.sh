#!/bin/bash
# Main test runner for pesign functional tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

FAILED_TESTS=()
PASSED_TESTS=()

echo "======================================"
echo "Running pesign functional tests"
echo "======================================"
echo

run_test() {
    local test_script="$1"
    local test_name=$(basename "$test_script" .sh)

    echo -e "${YELLOW}Running: ${test_name}${NC}"

    if bash "$test_script"; then
        echo -e "${GREEN}✓ PASSED: ${test_name}${NC}"
        PASSED_TESTS+=("$test_name")
    else
        echo -e "${RED}✗ FAILED: ${test_name}${NC}"
        FAILED_TESTS+=("$test_name")
    fi
    echo
}

# Run all test scripts
for test in "$SCRIPT_DIR"/test-*.sh; do
    if [ -f "$test" ]; then
        run_test "$test"
    fi
done

# Summary
echo "======================================"
echo "Test Summary"
echo "======================================"
echo -e "${GREEN}Passed: ${#PASSED_TESTS[@]}${NC}"
echo -e "${RED}Failed: ${#FAILED_TESTS[@]}${NC}"

if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
    echo
    echo "Failed tests:"
    for test in "${FAILED_TESTS[@]}"; do
        echo -e "  ${RED}✗${NC} $test"
    done
    exit 1
fi

echo
echo -e "${GREEN}All tests passed!${NC}"
exit 0
