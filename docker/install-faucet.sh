#!/bin/sh

set -e

APK="apk -q"
BUILDDEPS="gcc python3-dev musl-dev"
TESTDEPS="bitstring pytest setuptools wheel virtualenv"
PIP3="pip3 -q --no-cache-dir install --upgrade"
FROOT=/faucet-src

dir=`dirname $0`

# Clean up
rm -r "$FROOT/docs"

$APK add -U git yaml-dev $BUILDDEPS && \
  $dir/retrycmd.sh "$PIP3 pip" && \
  $dir/retrycmd.sh "$PIP3 $TESTDEPS" && \
  $dir/retrycmd.sh "$PIP3 -r $FROOT/requirements.txt" && \
  $PIP3 $FROOT

if [ "$ARCH" == "armhf" ]; then
  echo "Skipping tests on $ARCH platform"
else
  python3 -m pytest $FROOT/tests/unit/faucet/test_*.py
  python3 -m pytest $FROOT/tests/unit/gauge/test_*.py
fi

for i in $BUILDDEPS ; do
  $APK del $i
done

find / -name \*pyc -delete
