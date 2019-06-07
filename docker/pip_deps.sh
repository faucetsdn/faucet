#!/bin/bash

set -e

FAUCETHOME=`dirname $0`/..
FAUCETHOME=`readlink -f $FAUCETHOME`
PIPARGS="install -q --upgrade $*"

for r in test-requirements.txt fuzz-requirements.txt docs/requirements.txt adapters/vendors/rabbitmq/requirements.txt ; do
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
