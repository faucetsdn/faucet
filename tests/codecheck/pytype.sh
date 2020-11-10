#!/bin/bash

set -euo pipefail

if [[ "$(which pytype)" == "" ]] ; then
  echo pytype not installed - skipping
  exit
fi

SCRIPTPATH=$(readlink -f "$0")
TESTDIR=$(dirname "${SCRIPTPATH}")
BASEDIR=$(readlink -f "${TESTDIR}/../..")

tmpdir=$(mktemp -d /tmp/pytypeXXXXXX)
config="${BASEDIR}/setup.cfg"
srcfiles=$("${TESTDIR}/src_files.sh" "$@" | shuf)

pytype -j 2 --config "${config}" -o "${tmpdir}" "${srcfiles}"

rm -rf "${tmpdir}"
