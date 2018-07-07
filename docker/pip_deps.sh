#!/bin/bash

FAUCETHOME=`dirname $0`/..
PIPARGS=$*

for p in pip pip3 ; do
  for r in test-requirements.txt requirements.txt docs/requirements.txt fuzz-requirements.txt ; do
    $FAUCETHOME/docker/retrycmd.sh "$p install -q --upgrade $PIPARGS -r $FAUCETHOME/$r" || exit 1
  done
done
