#!/bin/bash

set -euo pipefail

SCRIPTPATH=$(readlink -f "$0")
TESTDIR=$(dirname "${SCRIPTPATH}")
BASEDIR=$(readlink -f "${TESTDIR}/../..")

if [[ "$*" == "" ]] ; then
  files=()

  readarray -t root_files \
    <<< "$(find "${BASEDIR}" -maxdepth 1 -type f ! -size 0 -name '*.py' -exec realpath {} \;)"

  files=("${files[@]}" "${root_files[@]}")

  for dir in adapters clib docs faucet tests ; do
    readarray -t sub_files \
      <<< "$(find "${BASEDIR}/${dir}/" -type f ! -size 0 -name '*.py' -exec realpath {} \;)"

    files=("${files[@]}" "${sub_files[@]}")
  done

  for file in "${files[@]}"; do
    echo "${file}"
  done | sort
else
  cd "${BASEDIR}"
  readlink -f "$@" | sort
fi
