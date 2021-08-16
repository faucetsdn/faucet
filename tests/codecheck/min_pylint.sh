#!/bin/bash

set -euo pipefail

MINRATING=9.50

SCRIPTPATH=$(readlink -f "$0")
TESTDIR=$(dirname "${SCRIPTPATH}")
BASEDIR=$(readlink -f "${TESTDIR}/../..")

export PYLINTRC=$(readlink -f "$BASEDIR/.pylintrc")

for file in "$@" ; do
    echo ""
    echo "------------------------------------------------------------------"
    echo "pylint report for ${file}"
    pylint --fail-under=${MINRATING} ${file} || \
        (echo "pylint rating for ${file} is below minimum of ${MINRATING}" && exit 1)
done
