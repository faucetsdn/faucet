#!/bin/bash

set -e

TMPDIR=$(mktemp -d)
FAUCETHOME=`dirname $0`/..
FAUCETHOME=`readlink -f $FAUCETHOME`
PIPARGS="install -q --upgrade $*"
# python3.5 is part of Debian oldstable, which is supported by https://wiki.debian.org/LTS.
# We will need to skip certain unsupported pip packages
PYTHON35PIPSKIP="(pytype)"

# Install pip pre-dependencies.
$FAUCETHOME/docker/retrycmd.sh "pip3 $PIPARGS wheel cython setuptools pybind11"

REQ="requirements.txt test-requirements.txt fuzz-requirements.txt docs/requirements.txt adapters/vendors/rabbitmq/requirements.txt"
REQDIR=$TMPDIR/requirements
mkdir $REQDIR
pushd $FAUCETHOME
cp -a --parents $REQ $REQDIR
popd
pythonminor=$(python3 -c "import sys;print(sys.version_info.minor)")
echo python3 minor version is $pythonminor
if [[ "$pythonminor" == "5" ]] ; then
  for r in $REQ ; do
    echo filtering $FAUCETHOME/$r for python3.5
    grep -vE "$PYTHON35PIPSKIP" $FAUCETHOME/$r > $REQDIR/$r
  done
fi
for r in $REQ ; do
  echo pip installing from $REQDIR/$r
  $FAUCETHOME/docker/retrycmd.sh "pip3 $PIPARGS -r $REQDIR/$r"
done

# Topo unit test needs mininet in user python environment
if ! python -c 'import mininet.net' 2> /dev/null; then
  pushd $TMPDIR
  git clone https://github.com/mininet/mininet
  cd mininet
  pip3 install -q .
  popd
fi

rm -rf $TMPDIR
