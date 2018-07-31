#!/bin/bash

FAUCETHOME=`dirname $0`"/../.."
PYTHONPATH=$FAUCETHOME:$FAUCETHOME/faucet:$FAUCETHOME/clib
PARARGS="parallel --delay 1 --bar"
PYTYPEARGS="pytype --pythonpath $PYTHONPATH -d pyi-error,import-error -V3.5"
PYTYPE=`which pytype`
PYHEADER=`head -1 $PYTYPE`
SRCFILES="$FAUCETHOME/tests/codecheck/src_files.sh"
echo "Using $PYTYPE (header $PYHEADER)"

$SRCFILES | shuf | $PARARGS $PYTYPEARGS || exit 1
