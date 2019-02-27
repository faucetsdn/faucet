#!/bin/bash

FAUCETHOME=`dirname $0`"/../.."
TMPDIR=`mktemp -d -p /var/tmp`
CONFIG="$FAUCETHOME/setup.cfg"
PARARGS="parallel --delay 1 --bar --halt now,fail=1 -j 2"
PYTYPE=`which pytype`
PYTYPEARGS="python3 $PYTYPE --config $CONFIG -o $TMPDIR/{/} {}"
PYHEADER=`head -1 $PYTYPE`
SRCFILES="$FAUCETHOME/tests/codecheck/src_files.sh $*"
echo "Using $PYTYPE (header $PYHEADER)"

$SRCFILES | shuf | $PARARGS $PYTYPEARGS || exit 1
rm -rf $TMPDIR
