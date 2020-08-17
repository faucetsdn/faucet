#!/bin/bash

set -euo pipefail

MINCOVERAGE=92

SCRIPTPATH=$(readlink -f "$0")
TESTDIR=$(dirname "${SCRIPTPATH}")
BASEDIR=$(readlink -f "${TESTDIR}/..")
PYTHONPATH=${BASEDIR}:${BASEDIR}/clib

unit_test_files=(${TESTDIR}/unit/*/test_*.py)

test_cmd="PYTHONPATH=${PYTHONPATH} coverage run --parallel-mode --source ${BASEDIR}/faucet/ -m unittest --verbose"

coverage erase
printf '%s\n' "${unit_test_files[@]}" | shuf | parallel --verbose --timeout 600 --delay 1 --halt now,fail=1 -j 4 "${test_cmd}"
coverage combine
coverage xml
coverage report -m --fail-under=${MINCOVERAGE}
