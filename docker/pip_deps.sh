#!/bin/bash

set -euo pipefail

SCRIPTPATH=$(readlink -f "$0")
SCRIPTDIR=$(dirname "${SCRIPTPATH}")
BASEDIR=$(readlink -f "${SCRIPTDIR}/..")

reqs="test-requirements.txt fuzz-requirements.txt adapters/vendors/rabbitmq/requirements.txt"
pip_args=""

for opt in "$@"; do
  case "${opt}" in
    --pip-args=*)
      pip_args+=" ${opt#*=}"
      ;;
    --extra-requirements=*)
      reqs+=" ${opt#*=}"
      ;;
  esac
done

PIPARGS="install -q --upgrade ${pip_args}"

# Install pip pre-dependencies.
"${BASEDIR}/docker/retrycmd.sh" "pip3 ${PIPARGS} wheel cython setuptools"

for req in ${reqs}; do
  "${BASEDIR}/docker/retrycmd.sh" "pip3 ${PIPARGS} -r ${BASEDIR}/${req}"
done

# Topo unit test needs mininet in user python environment
if ! python -c 'import mininet.net' 2> /dev/null; then
  TMPDIR=$(mktemp -d) && pushd "${TMPDIR}"
  git clone https://github.com/mininet/mininet
  cd mininet
  pip3 install -q .
  popd && rm -rf "${TMPDIR}"
fi
