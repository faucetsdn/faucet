#!/bin/bash


echo TRAVIS_COMMIT_RANGE: $TRAVIS_COMMIT_RANGE
echo TRAVIS_COMMIT: $TRAVIS_COMMIT
FILES_CHANGED=`git diff --name-only $TRAVIS_COMMIT_RANGE`
PY_FILES_CHANGED=`git diff --name-only $TRAVIS_COMMIT_RANGE|grep -E ".py$"`

if [[ "$FILES_CHANGED" != "" ]] ; then
  echo files changed: $FILES_CHANGED
else
  echo no files changed.
fi

if [ "${MATRIX_SHARD}" == "sanity" ] ; then
  FAUCET_TESTS="-u FaucetSanityTest"
  ./tests/run_unit_tests.sh || exit 1
  codecov || true
else
  ALLTESTFILES="tests/integration/mininet_tests.py clib/clib_mininet_tests.py"
  ALLTESTS=`grep -E -o "^class (Faucet[a-zA-Z0-9]+Test)" ${ALLTESTFILES}|cut -f2 -d" "|sort`
  declare -A sharded

  function shard {
    work=$1
    workers=$2
    i=0
    for shard in $work ; do
      i=$(expr $i % $workers)
      sharded[$i]="${sharded[$i]} $shard"
      i=$(expr $i + 1)
    done
  }

  shard "$ALLTESTS" ${MATRIX_SHARDS}
  FAUCET_TESTS="-di ${sharded[${MATRIX_SHARD}]}"
fi

PY3V=`python3 --version`
if [[ "$PY3V" != "Python 3.6"* ]] ; then
  echo not running docker tests for $PY3V
  exit 0
fi

if [[ "$PY_FILES_CHANGED" == "" ]] ; then
  echo no python source changed, not running docker tests.
  exit 0
fi

docker pull faucet/test-base
docker build -t ${FAUCET_TEST_IMG} -f Dockerfile.tests . || exit 1
docker rmi faucet/test-base
docker images

echo Shard $MATRIX_SHARD: $FAUCETTESTS
sudo docker run --privileged --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  -v $HOME/.cache/pip:/var/tmp/pip-cache \
  -e FAUCET_TESTS="${FAUCET_TESTS}" \
  -e PY_FILES_CHANGED="${PY_FILES_CHANGED}" \
  -t ${FAUCET_TEST_IMG} || exit 1
exit 0
