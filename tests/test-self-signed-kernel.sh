#!/bin/bash
#
# Copyright Gordon Messmer <gmessmer@redhat.com>
#
# Distributed under terms of the GPLv3 license.
#

set -eu
set -o pipefail
export PS4='# ${BASH_SOURCE}:${LINENO} - [${SHLVL},${BASH_SUBSHELL},$?] '

KERNEL="tests/data/vmlinuz-6.19.10-200.fc43.x86_64"
MODULE="tests/data/vfat.ko"

setup()
{
    mkdir tests/test_key_db
    cd tests/test_key_db
    export NSS_DEFAULT_DB_TYPE=sql
    certutil -d . -N --empty-password
    cd -
}

cleanup() {
    rm -fr tests/test_key_db >&/dev/null || :
}

# Verify that a certificate exists in the database and has trust flags set.
verify_cert() {
    local nickname="${1}" && shift

    echo -n "testing that certificate '${nickname}' was created: "
    if ! certutil -d tests/test_key_db -L -n "${nickname}" >/dev/null 2>&1 ; then
        echo "failure! ret:$?"
        exit 1
    fi
    local trust
    trust=$(certutil -d tests/test_key_db -L | grep "${nickname}" | awk '{print $NF}')
    if [ -z "${trust}" ] ; then
        echo "failure! no trust flags"
        exit 1
    fi
    echo "success! (trust:${trust})"
}

# Sign a file and check the result against the expected outcome.
test_signing() {
    local nickname="${1}" && shift
    local infile="${1}" && shift
    local what="${1}" && shift
    local expected_result="${1}" && shift

    echo -n "testing ${what} signing with '${nickname}': "
    case "${expected_result}" in
        "pass")
            if ! ./src/pesign --certdir tests/test_key_db \
                    --certificate "${nickname}" \
                    --sign --in "${infile}" \
                    --out "tests/test_key_db/${what}-signed" ; then
                echo "failure! ret:$?"
                exit 1
            fi
            echo "success!"
            ;;
        "fail")
            if ./src/pesign --certdir tests/test_key_db \
                    --certificate "${nickname}" \
                    --sign --in "${infile}" \
                    --out "tests/test_key_db/${what}-signed" ; then
                echo "failure! ret:$?"
                exit 1
            fi
            echo "success!"
            ;;
    esac
}

main() {
    trap cleanup INT QUIT SEGV ABRT ERR
    cleanup
    setup

    while [ $# -ne 0 ]; do
        case " $1 " in
            " --disable-pqc ")
                shift
                ;;
            *)
                echo "unknown argument ${1}" >/dev/stderr
                exit 1
                ;;
        esac
    done

    # Generate a self-signed certificate for signing kernels.
    ./src/efikeygen -d tests/test_key_db \
        --self-sign --kernel \
        --common-name 'CN=Test Kernel Signing Key' \
        --nickname 'Test Kernel Key'
    verify_cert 'Test Kernel Key'

    # A kernel-signing certificate can sign both kernels and modules.
    test_signing 'Test Kernel Key' "${KERNEL}" kernel pass
    test_signing 'Test Kernel Key' "${MODULE}" module pass

    cleanup
}

main "${@}"

# vim:fenc=utf-8:tw=75
