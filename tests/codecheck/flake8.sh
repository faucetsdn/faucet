#!/bin/bash

set -euo pipefail

SCRIPTPATH=$(readlink -f "$0")
TESTDIR=$(dirname "${SCRIPTPATH}")
BASEDIR=$(readlink -f "${TESTDIR}/../..")

config=$(readlink -f "$BASEDIR/.codecheck")
srcfiles=$("${TESTDIR}/src_files.sh" "$@" | shuf)

flake8 -j 2 --config "${config}" ${srcfiles}
