#!/bin/bash

FAUCETHOME=`dirname $0`/..
FAUCETHOME=`readlink -f $FAUCETHOME`
PIPARGS="install -q --upgrade $*"

for r in test-requirements.txt requirements.txt docs/requirements.txt fuzz-requirements.txt ; do
  $FAUCETHOME/docker/retrycmd.sh "pip3 $PIPARGS -r $FAUCETHOME/$r" || exit 1
done
