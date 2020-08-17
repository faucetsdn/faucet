#!/bin/bash

set -euo pipefail

SCRIPTPATH=$(readlink -f "$0")
TESTDIR=$(dirname "${SCRIPTPATH}")
BASEDIR=$(readlink -f "${TESTDIR}/../..")

tmpfile=$(mktemp /tmp/srcfilesXXXXXX)

if [[ "$*" == "" ]] ; then
  for dir in clib faucet tests ; do
      find "${BASEDIR}/${dir}/" -type f -name '[a-z]*.py'
  done | xargs realpath > "${tmpfile}"
else
  cd "${BASEDIR}"
  readlink -f "$@" > "${tmpfile}"
fi

sort < "${tmpfile}"

rm "${tmpfile}"
