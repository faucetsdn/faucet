#!/bin/bash

FAUCETHOME=`dirname $0`"/.."
# TODO: pytype is a memory hog, use -Z for now
PYTYPEARGS='pytype -Z -d pyi-error,import-error'
PARARGS='parallel --delay 1 --bar'

PY2=""
PY3=""
for i in `$FAUCETHOME/tests/src_files.sh` ; do
  if grep -qn "import mininet" $i ; then
    PY2+="$i\n"
  else
    PY3+="$i\n"
  fi
done

echo -e $PY2 | $PARARGS $PYTYPEARGS -V2.7 || exit 1
echo -e $PY3 | $PARARGS $PYTYPEARGS -V3.5 || exit 1
