#!/bin/bash

# TODO: until 3.6 safe, force 3.5
PYV="3.5"
FAUCETHOME=`dirname $0`"/../.."
PYTHONPATH=$FAUCETHOME:$FAUCETHOME/faucet:$FAUCETHOME/clib
PARARGS="parallel --delay 1 --bar"
PYTYPE=`which pytype`
PYTYPEARGS="python$PYV  $PYTYPE --pythonpath $PYTHONPATH -d pyi-error,import-error -V$PYV"
PYHEADER=`head -1 $PYTYPE`
SRCFILES="$FAUCETHOME/tests/codecheck/src_files.sh"
echo "Using $PYTYPE (header $PYHEADER)"

$SRCFILES | shuf | $PARARGS $PYTYPEARGS || exit 1
