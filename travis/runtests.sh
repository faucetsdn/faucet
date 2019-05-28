#!/bin/bash


# See https://docs.travis-ci.com/user/environment-variables/#convenience-variables
echo TRAVIS_BRANCH: $TRAVIS_BRANCH
echo TRAVIS_COMMIT: $TRAVIS_COMMIT

# If PY_FILES_CHANGED is empty, run all codecheck tests (otherwise only on changed files).
FILES_CHANGED=""
PY_FILES_CHANGED=""
RQ_FILES_CHANGED=""

# TRAVIS_COMMIT_RANGE will be empty in a new branch.
if [[ "$TRAVIS_COMMIT_RANGE" != "" ]] ; then
  echo TRAVIS_COMMIT_RANGE: $TRAVIS_COMMIT_RANGE
  GIT_DIFF_CMD="git diff --name-only $TRAVIS_COMMIT_RANGE"
  FILES_CHANGED=`$GIT_DIFF_CMD`
  if [ $? -ne 0 ] ; then echo $GIT_DIFF_CMD returned $? ; fi
  PY_FILES_CHANGED=`$GIT_DIFF_CMD | grep -E ".py$"`
  RQ_FILES_CHANGED=`$GIT_DIFF_CMD | grep -E "requirements.*txt$"`
  if [[ "$FILES_CHANGED" != "" ]] ; then
    echo files changed: $FILES_CHANGED
  else
    echo no files changed.
  fi
fi

if [ "${MATRIX_SHARD}" == "unittest" ] ; then
  ./docker/pip_deps.sh
  pip3 install ./
  pip3 show faucet
  ./tests/run_unit_tests.sh || exit 1

  if [ "${CODECOV_UPLOAD}" == "true" ] ; then
    codecov || true
  fi

  if [ "${BUILD_DOCS}" == "true" ] ; then
    cd ./docs
    make html || exit 1
    rm -rf _build
    cd ..
  fi

  exit 0
elif [ "${MATRIX_SHARD}" == "sanity" ] ; then
  FAUCET_TESTS="-u FaucetSanityTest"
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
  FAUCET_TESTS="-din ${sharded[${MATRIX_SHARD}]}"
fi

if [[ "$FILES_CHANGED" != "" ]] ; then
  if [[ "$PY_FILES_CHANGED" == "" && "$RQ_FILES_CHANGED" == "" ]] ; then
    echo Not running docker tests because only non-python/requirements changes: $FILES_CHANGED
    exit 0
  else
    echo python/requirements changes: $PY_FILES_CHANGED $RQ_FILES_CHANGED
  fi
fi

docker pull faucet/test-base
docker build -t ${FAUCET_TEST_IMG} -f Dockerfile.tests . || exit 1
docker rmi faucet/test-base
docker images

SHARDARGS="--privileged --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --ulimit core=99999999999:99999999999 \
  -v /var/local/lib/docker:/var/lib/docker \
  -v $HOME/.cache/pip:/var/tmp/pip-cache"
echo Shard $MATRIX_SHARD: $FAUCETTESTS: $SHARDARGS

ulimit -c unlimited && sudo echo '/var/tmp/core.%h.%e.%t' > /proc/sys/kernel/core_pattern
sudo modprobe openvswitch
sudo modprobe ebtables

if [ "${MATRIX_SHARD}" == "sanity" ] ; then
  # Simulate hardware test switch
  # TODO: run a standalone DP and also a stacked DP test to test hardware linkages.
  sudo docker run $SHARDARGS -e FAUCET_TESTS="-ni FaucetSanityTest FaucetStackStringOfDPUntaggedTest" -e HWTESTS="1" -t ${FAUCET_TEST_IMG} || exit 1
fi

sudo docker run $SHARDARGS -e PY_FILES_CHANGED="${PY_FILES_CHANGED}" -e FAUCET_TESTS="${FAUCET_TESTS}" -t ${FAUCET_TEST_IMG} || exit 1

if ls -1 /var/tmp/core* >/dev/null 2>&1 ; then
  echo coredumps found after tests run.
  exit 1
  # TODO: automatically run gdb?
fi

exit 0
