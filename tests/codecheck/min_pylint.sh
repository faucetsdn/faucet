#!/bin/bash

set -euo pipefail

MINRATING=9.44

SCRIPTPATH=$(readlink -f "$0")
TESTDIR=$(dirname "${SCRIPTPATH}")
BASEDIR=$(readlink -f "${TESTDIR}/../..")
PYTHONPATH=${BASEDIR}:${BASEDIR}/clib

lintfile=$(mktemp /tmp/pylintXXXXXX)

# TODO: --fail-under can't be used because it takes only integers.
for file in "$@" ; do
    PYTHONPATH=${PYTHONPATH} pylint --exit-zero --rcfile=/dev/null --extension-pkg-whitelist=netifaces,pytricia -d import-error ${file} > "${lintfile}"
    rating=$(grep -ohE "rated at [0-9\.\-]+" "${lintfile}" | sed "s/rated at //g")
    echo "pylint rating ${file}: ${rating}"
    failing=$(bc <<< "${rating} < ${MINRATING}")
    if [ "$failing" -ne 0 ]; then
        cat "${lintfile}"
        echo "pylint rating ${file}: ${rating} is below minimum ${MINRATING}"
        exit 1
    fi
done

rm "${lintfile}"
