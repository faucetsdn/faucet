#!/bin/bash

# See https://docs.travis-ci.com/user/environment-variables/#convenience-variables
echo "TRAVIS_BRANCH: ${TRAVIS_BRANCH}"
echo "TRAVIS_COMMIT: ${TRAVIS_COMMIT}"
echo "TRAVIS_PULL_REQUEST: ${TRAVIS_PULL_REQUEST}"

# If FILES_CHANGED is set to all, run codecheck tests on all files,
# otherwise only run on changed files listed in PY_FILES_CHANGED
FILES_CHANGED="all"
PY_FILES_CHANGED=""
RQ_FILES_CHANGED=""

if [ ! -z "${TRAVIS_COMMIT_RANGE}" ]; then
  # This isn't a new branch

  echo "TRAVIS_COMMIT_RANGE: ${TRAVIS_COMMIT_RANGE}"

  if [ "${TRAVIS_PULL_REQUEST}" == "false" ]; then
    # This isn't a PR build

    # We need the individual commits to detect force pushes
    COMMIT1="$(echo "${TRAVIS_COMMIT_RANGE}" | cut -f 1 -d '.')"
    COMMIT2="$(echo "${TRAVIS_COMMIT_RANGE}" | cut -f 4 -d '.')"

    if [ "$(git cat-file -t "${COMMIT1}" 2>/dev/null)" == "commit" ] && [ "$(git cat-file -t "${COMMIT2}" 2>/dev/null)" == "commit" ]; then
      # Both commits exist, this isn't a rewrite of history
      COMMIT_RANGE="${TRAVIS_COMMIT_RANGE}"
    fi
  else
    # This is a PR build
    COMMIT_RANGE="${TRAVIS_BRANCH}...HEAD"
  fi

  if [ ! -z "${COMMIT_RANGE}" ]; then
    GIT_DIFF_CMD="git diff --diff-filter=ACMRT --name-only ${COMMIT_RANGE} --"
    FILES_CHANGED=$(${GIT_DIFF_CMD} | tr '\n' ' ')
    PY_FILES_CHANGED=$(${GIT_DIFF_CMD} | grep -E ".py$" | tr '\n' ' ')
    RQ_FILES_CHANGED=$(${GIT_DIFF_CMD} | grep -E "requirements(.*)txt$" | tr '\n' ' ')
  fi
fi

if [ "${FILES_CHANGED}" != "all" ]; then
  echo "These files have changed between ${COMMIT_RANGE}: ${FILES_CHANGED}"
  [ ! -z "${PY_FILES_CHANGED}" ] && echo "Python code changes: ${PY_FILES_CHANGED}"
  [ ! -z "${RQ_FILES_CHANGED}" ] && echo "Python requirements changes: ${RQ_FILES_CHANGED}"
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
    (
    cd ./docs || exit 1
    make html || exit 1
    rm -rf _build
    )
  fi

  if [ "${PYLINT}" == "true" ] ; then
    if [ "${FILES_CHANGED}" == "all" ] || [ ! -z "${PY_FILES_CHANGED}" ]; then
      (
      cd ./tests/codecheck || exit 1
      ./pylint.sh ${PY_FILES_CHANGED} || exit 1
      )
    fi
  fi

  if [ "${PYTYPE}" == "true" ] ; then
    if [ "${FILES_CHANGED}" == "all" ] || [ ! -z "${PY_FILES_CHANGED}" ] || [ ! -z "${RQ_FILES_CHANGED}" ]; then
      (
      cd ./tests/codecheck || exit 1
      if [ ! -z "${RQ_FILES_CHANGED}" ]; then
        # When requirements change, run pytype on everything
        ./pytype.sh || exit 1
      else
        ./pytype.sh ${PY_FILES_CHANGED} || exit 1
      fi
      )
    fi
  fi

  exit 0
elif [ "${MATRIX_SHARD}" == "sanity" ] ; then
  FAUCET_TESTS="-u FaucetSanityTest"
elif [ "${MATRIX_SHARD}" == "generative-unit" ]; then
  FAUCET_TESTS="--generative_unit"
elif [ "${MATRIX_SHARD}" == "generative-integration" ]; then
  FAUCET_TESTS="--generative_integration"
else
  ALLTESTFILES="tests/integration/mininet_tests.py tests/integration/mininet_multidp_tests.py clib/clib_mininet_tests.py"
  ALLTESTS=$(grep -E -o "^class (Faucet[a-zA-Z0-9]+Test)" ${ALLTESTFILES} | cut -f2 -d" " | sort)
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

if [ "${FILES_CHANGED}" != "all" ]; then
  if [ -z "${PY_FILES_CHANGED}" ] && [ -z "${RQ_FILES_CHANGED}" ]; then
    echo "Not running docker tests because no code changes detected"
    exit 0
  fi
fi

docker build --pull -t ${FAUCET_TEST_IMG} -f Dockerfile.tests . || exit 1

SHARDARGS="--privileged --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --ulimit core=99999999999:99999999999 \
  -v /var/local/lib/docker:/var/lib/docker \
  -v $HOME/.cache/pip:/var/tmp/pip-cache"

echo "MATRIX_SHARD: ${MATRIX_SHARD}"
echo "FAUCET_TESTS: ${FAUCET_TESTS}"
echo "SHARDARGS: ${SHARDARGS}"

ulimit -c unlimited
echo '/var/tmp/core.%h.%e.%t' | sudo tee /proc/sys/kernel/core_pattern
sudo modprobe openvswitch
sudo modprobe ebtables

if [ "${MATRIX_SHARD}" == "sanity" ] ; then
  # Simulate hardware test switch
  # TODO: run a standalone DP and also a stacked DP test to test hardware linkages.
  sudo docker run $SHARDARGS -e FAUCET_TESTS="-ni FaucetSanityTest FaucetStackStringOfDPUntaggedTest" -e HWTESTS="1" -t ${FAUCET_TEST_IMG} || exit 1
else
  sudo docker run $SHARDARGS -e FAUCET_TESTS="${FAUCET_TESTS}" -t ${FAUCET_TEST_IMG} || exit 1
fi

if ls -1 /var/tmp/core* >/dev/null 2>&1 ; then
  echo "coredumps found after tests run."
  exit 1
  # TODO: automatically run gdb?
fi

exit 0
