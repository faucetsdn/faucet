#!/bin/bash

FAUCETHOME=`dirname $0`"/../.."
TMPDIR=`mktemp -d -p /var/tmp`
CONFIG="$FAUCETHOME/setup.cfg"
PYTYPE=`which pytype`
PYHEADER=`head -1 $PYTYPE`
SRCFILES="$FAUCETHOME/tests/codecheck/src_files.sh $*"
echo
echo "Using $PYTYPE (header $PYHEADER)"

python3 $PYTYPE -j 2 --config $CONFIG -o $TMPDIR/{/} `$SRCFILES | shuf` || exit 1
rm -rf $TMPDIR
