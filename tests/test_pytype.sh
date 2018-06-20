#!/bin/bash

FAUCETHOME=`dirname $0`"/.."
PYTYPEARGS="pytype -d pyi-error,import-error"

PY2=""
PY3=""
# TODO: skip mininet files to reduce pytype resources
for i in `$FAUCETHOME/tests/src_files.sh|shuf|grep -v mininet` ; do
  # mininet requires python2
  if grep -qn "import mininet" $i ; then
    PY2+="$i "
  else
    PY3+="$i "
  fi
done

for i in $PY2 ; do
  echo $i
  $PYTYPEARGS -V2.7 $i
done

for i in $PY3 ; do
  echo $i
  $PYTYPEARGS -V3.5 $i
done
