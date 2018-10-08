#!/bin/bash

PYV="3.5"
FAUCETHOME=`dirname $0`"/../.."
TMPDIR=`mktemp -d -p /var/tmp`
CONFIG="$FAUCETHOME/setup.cfg"
PARARGS="parallel --delay 1 --bar --halt now,fail=1 -j 2"
PYTYPE=`which pytype`
PYTYPEARGS="python$PYV $PYTYPE --config $CONFIG -o $TMPDIR/{/} {}"
PYHEADER=`head -1 $PYTYPE`
SRCFILES=`$FAUCETHOME/tests/codecheck/src_files.sh`
if [[ "$*" != "" ]] ; then
  SRCFILES="$*"
fi
echo "Using $PYTYPE (header $PYHEADER)"

echo $SRCFILES | tr " " "\n" | shuf | $PARARGS $PYTYPEARGS || exit 1
rm -rf $TMPDIR
