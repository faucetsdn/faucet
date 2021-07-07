#!/bin/bash

set -euo pipefail

MINRATING=9.50

for file in "$@" ; do
    echo ""
    echo "------------------------------------------------------------------"
    echo "pylint report for ${file}"
    pylint --fail-under=${MINRATING} -d import-error ${file} || \
        (echo "pylint rating for ${file} is below minimum of ${MINRATING}" && exit 1)
done
