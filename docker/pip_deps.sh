#!/bin/bash

set -e

if [ "$PIP_REQUIREMENTS" == "" ] ; then
	PIP_REQUIREMENTS="test-requirements.txt fuzz-requirements.txt docs/requirements.txt adapters/vendors/rabbitmq/requirements.txt"
fi
echo PIP_REQUREMENTS: $PIP_REQUIREMENTS

FAUCETHOME=`dirname $0`/..
FAUCETHOME=`readlink -f $FAUCETHOME`
PIPARGS="install -q --upgrade $*"

# Install pip pre-dependencies.
$FAUCETHOME/docker/retrycmd.sh "pip3 $PIPARGS wheel cython setuptools"

for r in $PIP_REQUIREMENTS; do
  $FAUCETHOME/docker/retrycmd.sh "pip3 $PIPARGS -r $FAUCETHOME/$r"
done

# Topo unit test needs mininet in user python environment
if ! python -c 'import mininet.net' 2> /dev/null; then
  TMPDIR=$(mktemp -d) && pushd $TMPDIR
  git clone https://github.com/mininet/mininet
  cd mininet
  pip3 install -q .
  popd && rm -rf $TMPDIR
fi
