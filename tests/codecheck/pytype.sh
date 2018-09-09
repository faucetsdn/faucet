#!/bin/bash

# TODO: pytype is very memory intensive - run per separate directory to limit resources.
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

PYTYPEARGS="pytype -V$PYV -o $TMPD --pythonpath $PYTHONPATH -d pyi-error,import-error"

declare -A SRCDIRS
for f in `$SRCFILES` ; do
   d=`dirname $f`
   if [ "SRCDIRS[$d]]" ] ; then
       SRCDIRS[$d]="$f\n${SRCDIRS[$d]}"
   else
       SRCDIRS[$d]=$f
   fi
done

PARARGS="parallel --delay 1 --bar"
for d in "${!SRCDIRS[@]}" ; do
   srcfiles=${SRCDIRS[$d]}
   echo -e $d: $srcfiles
   echo -e $srcfiles | $PARARGS $PYTYPEARGS || exit 1
done
