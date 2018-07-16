#!/bin/bash

FAUCETHOME=`dirname $0`/..
PIPARGS=$*

$FAUCETHOME/docker/retrycmd.sh "pip install -q --upgrade $PIPARGS -r $FAUCETHOME/py2-test-requirements.txt" || exit 1

for r in test-requirements.txt requirements.txt docs/requirements.txt fuzz-requirements.txt ; do
  $FAUCETHOME/docker/retrycmd.sh "pip3 install -q --upgrade $PIPARGS -r $FAUCETHOME/$r" || exit 1
done
