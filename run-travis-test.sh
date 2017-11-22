#!/bin/bash

docker build -t ${FAUCET_TEST_IMG} -f Dockerfile.tests . || exit 1
docker images

# If sanity shard, just the sanity test and lint/type/dependency checks.
if [ "${MATRIX_SHARD}" == "sanity" ] ; then
  touch ~/.pylintrc
  cd ./tests
  PYTHONPATH=~/faucet ./test_min_pylint.sh || exit 1
  PYTHONPATH=~/faucet python3 -m pytest ./test_*.py --cov faucet --doctest-modules -v --cov-report term-missing || exit 1
  coveralls || true
  cd ..
  RUNTESTS="FaucetSanityTest"
# If not the sanity shard, run sharded tests but skip lint/type/dependency checks.
else
  ALLTESTS=`grep -E -o "^class (Faucet[a-zA-Z0-9]+Test)" tests/faucet_mininet_test_unit.py|cut -f2 -d" "|sort`
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
  RUNTESTS="-n ${sharded[${MATRIX_SHARD}]}"
fi

echo running tests ${RUNTESTS}
travis_wait sudo docker run --privileged -t -e FAUCET_TESTS="-d ${RUNTESTS}" ${FAUCET_TEST_IMG}
