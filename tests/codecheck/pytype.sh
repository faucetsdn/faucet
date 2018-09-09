#!/bin/bash

# TODO: until 3.6 safe, force 3.5
PYV="3.5"
FAUCETHOME=`dirname $0`"/../.."
PYTHONPATH=$FAUCETHOME:$FAUCETHOME/faucet:$FAUCETHOME/clib
PARARGS="parallel --delay 1 --bar"
SRCFILES="$FAUCETHOME/tests/codecheck/src_files.sh"

TMPD=`mktemp -d`
test -d $TMPD || exit
function cleanup {
  rm -r "$TMPD"
}
trap cleanup EXIT

PYTYPEARGS="pytype -V$PYV -o $TMPD --pythonpath $PYTHONPATH -d pyi-error,import-error"
$PYTYPEARGS `$SRCFILES` || exit 1
