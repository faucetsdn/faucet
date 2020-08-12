#!/bin/bash

set -euo pipefail

SCRIPTPATH=$(readlink -f "$0")
TESTDIR=$(dirname "${SCRIPTPATH}")

srcfiles="${TESTDIR}/src_files.sh $*"
${srcfiles} | shuf | parallel --delay 1 --bar --halt now,fail=1 -j 2 ./min_pylint.sh
