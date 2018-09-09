#!/bin/bash

# TODO: until 3.6 safe, force 3.5
PYV="3.5"
FAUCETHOME=`dirname $0`"/../.."
PYTHONPATH=$FAUCETHOME:$FAUCETHOME/faucet:$FAUCETHOME/clib
SRCFILES="$FAUCETHOME/tests/codecheck/src_files.sh"

TMPD=`mktemp -d`
test -d $TMPD || exit
function cleanup {
  rm -r "$TMPD"
}
trap cleanup EXIT

PYTYPEARGS="pytype -V$PYV -o $TMPD --pythonpath $PYTHONPATH -d pyi-error,import-error -v2"

declare -A SRCDIRS
for f in `$SRCFILES` ; do
   d=`dirname $f`
   SRCDIRS[$d]="$f ${SRCDIRS[$d]}"
done

for d in "${!SRCDIRS[@]}" ; do
   srcfiles=${SRCDIRS[$d]}
   $PYTYPEARGS $srcfiles || exit 1
done
