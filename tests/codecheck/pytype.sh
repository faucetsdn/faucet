#!/bin/bash

# TODO: run separately until https://github.com/google/pytype/issues/133 is fixed.
# TODO: until 3.6 safe, force 3.5
PYV="3.5"
FAUCETHOME=`dirname $0`"/../.."
CONFIG="$FAUCETHOME/setup.cfg"
PARARGS="parallel --delay 1 --bar"
PYTYPE=`which pytype`
PYTYPEARGS="python$PYV  $PYTYPE --config $CONFIG"
PYHEADER=`head -1 $PYTYPE`
SRCFILES="$FAUCETHOME/tests/codecheck/src_files.sh"
echo "Using $PYTYPE (header $PYHEADER)"

$SRCFILES | shuf | $PARARGS $PYTYPEARGS || exit 1
