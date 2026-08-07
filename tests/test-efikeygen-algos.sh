#!/bin/bash
#
# Copyright Peter Jones <pjones@redhat.com>
#
# Distributed under terms of the GPLv3 license.
#

set -eu
set -o pipefail
export PS4='# ${BASH_SOURCE}:${LINENO} - [${SHLVL},${BASH_SUBSHELL},$?] '

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

test_one_algo() {
    local cryptalg
    local hashalg
    local sigstr
    local sizestr
    local expected_result

    cryptalg="${1}" && shift
    hashalg="${1}" && shift
    sigstr="${1}" && shift
    sizestr="${1}" && shift
    expected_result="${1}" && shift

    local cryptarg=""
    local hasharg=""
    if [ "${cryptalg}" != default ] ; then
        cryptarg="-a ${cryptalg}"
    fi
    if [ "${hashalg}" != default ] ; then
        hasharg="-h ${hashalg}"
    fi
    local name="${cryptalg}-${hashalg}"

    echo -n "testing ${cryptalg} generation with ${hashalg} hash: "

    # shellcheck disable=SC2086
    # echo
    # echo ./src/efikeygen -d tests/test_key_db/ -k -S -c "CN=${name}" -n "${name}" ${cryptarg} ${hasharg}
    case "${expected_result}" in
        "pass")
            # shellcheck disable=SC2086
            if ! ./src/efikeygen -d tests/test_key_db/ -k -S -c "CN=${name}" -n "${name}" ${cryptarg} ${hasharg} ; then
                echo "failure! ret:$?"
                exit 1
            fi
            # "certutil -L" doesn't include the RSA key size, which is very
            # obnoxious.
            certutil -d tests/test_key_db/ -L -n "${name}" -r > "tests/test_key_db/${name}.cer"
            openssl x509 -inform der -in "tests/test_key_db/${name}.cer" -noout -text | grep -q "${sizestr}"
            openssl x509 -inform der -in "tests/test_key_db/${name}.cer" -noout -text | grep -q "${sigstr}"
            echo "success!"
            ;;
        "fail")
            # shellcheck disable=SC2086
            if ./src/efikeygen -d tests/test_key_db/ -k -S -c "CN=${name}" -n "${name}" ${cryptarg} ${hasharg} ; then
                echo "failure! ret:$?"
                exit 1
            fi
            echo "success!"
        esac
}

main() {
    trap cleanup INT QUIT SEGV ABRT ERR

    cleanup
    setup

    test_one_algo rsa2048 default "2048 bit" sha256WithRSAEncryption pass
    test_one_algo rsa3072 default "3072 bit" sha256WithRSAEncryption pass
    test_one_algo rsa4096 default "4096 bit" sha256WithRSAEncryption pass
    test_one_algo ml-dsa-87 default ML-DSA-87 ML-DSA-87 pass

    cleanup
}

main "${@}"

# vim:fenc=utf-8:tw=75
