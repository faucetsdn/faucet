#!/bin/sh

set -e

APK="apk -q"
BUILDDEPS="gcc python3-dev musl-dev parallel yaml-dev"
TESTDEPS="bitstring pytest wheel virtualenv"
PIP3="pip3 -q --no-cache-dir install --upgrade"
FROOT=/faucet-src

dir=`dirname $0`

# Clean up
rm -r "$FROOT/docs"

$APK add -U git $BUILDDEPS && \
  $dir/retrycmd.sh "$PIP3 pip" && \
  $dir/retrycmd.sh "$PIP3 setuptools $TESTDEPS" && \
  $dir/retrycmd.sh "$PIP3 -r $FROOT/requirements.txt" && \
  $PIP3 $FROOT

if [ "$(uname -m)" == "x86_64" ]; then
  echo $FROOT/tests/unit/faucet/test_*.py $FROOT/tests/unit/gauge/test_*.py | xargs realpath | shuf | parallel --delay 1 --bar --halt now,fail=1 -j 2 python3 -m pytest
else
  echo "Skipping tests on $(uname -m) platform"
fi

pip3 uninstall -y $TESTDEPS || exit 1
for i in $BUILDDEPS ; do
  $APK del $i || exit 1
done

# Smoke test
faucet -V || exit 1

find / -name \*pyc -delete || exit 1
