#!/bin/bash

# TODO: run separately until https://github.com/google/pytype/issues/133 is fixed.
# TODO: until 3.6 safe, force 3.5
PYV="3.5"
FAUCETHOME=`dirname $0`"/../.."
TMPDIR=`mktemp -d -p /var/tmp`
CONFIG="$FAUCETHOME/setup.cfg"
PARARGS="parallel --delay 1 --bar --halt now,fail=1"
PYTYPE=`which pytype`
PYTYPEARGS="python$PYV $PYTYPE --config $CONFIG -o $TMPDIR"
PYHEADER=`head -1 $PYTYPE`
SRCFILES="$FAUCETHOME/tests/codecheck/src_files.sh"
echo "Using $PYTYPE (header $PYHEADER)"

$SRCFILES | shuf | $PARARGS $PYTYPEARGS || exit 1
rm -rf $TMPDIR
