#!/bin/bash

FAUCETHOME=`dirname $0`"/.."
# TODO: increase job count - pytype is a memory hog
PARGS='--delay 1 -j 1 --bar pytype -Z -d pyi-error,import-error'

PY2=""
PY3=""
for i in `$FAUCETHOME/tests/src_files.sh` ; do
  if grep -qn "import mininet" $i ; then
    PY2+="$i\n"
  else
    PY3+="$i\n"
  fi
done

echo -e $PY2 | parallel $PARGS -V2.7 || exit 1
echo -e $PY3 | parallel $PARGS -V3.5 || exit 1
