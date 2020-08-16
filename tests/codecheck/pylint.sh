#!/bin/bash

set -euo pipefail

SCRIPTPATH=$(readlink -f "$0")
TESTDIR=$(dirname "${SCRIPTPATH}")

srcfiles="${TESTDIR}/src_files.sh $*"
${srcfiles} | shuf | parallel --timeout 300 --delay 1 --halt now,fail=1 -j 4 ./min_pylint.sh
