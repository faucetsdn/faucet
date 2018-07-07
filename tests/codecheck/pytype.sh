#!/bin/bash

FAUCETHOME=`dirname $0`"/../.."
PARARGS="parallel --delay 1 --bar"
PYTYPEARGS="pytype -d pyi-error,import-error"
PYTYPE=`which pytype`
PYHEADER=`head -1 $PYTYPE`

echo "Using $PYTYPE (header $PYHEADER)"

PY2=""
PY3=""
for i in `$FAUCETHOME/tests/codecheck/src_files.sh|shuf` ; do
  # mininet requires python2
  if grep -qn "import mininet" $i ; then
    PY2+="$i\n"
  else
    PY3+="$i\n"
  fi
done

echo -ne $PY2 | $PARARGS $PYTYPEARGS -V2.7 || exit 1
echo -ne $PY3 | $PARARGS $PYTYPEARGS -V3.5 || exit 1
