#!/bin/bash

set -euo pipefail

SCRIPTPATH=$(readlink -f "$0")
TESTDIR=$(dirname "${SCRIPTPATH}")
BASEDIR=$(readlink -f "${TESTDIR}/../..")

config=$(readlink -f "$BASEDIR/.flake8")
srcfiles=$("${TESTDIR}/src_files.sh" "$@" | shuf)

flake8 -j 2 --config "${config}" ${srcfiles}
