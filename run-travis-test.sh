#!/bin/bash

docker pull faucet/faucet-testbase
docker build -t ${FAUCET_TEST_IMG} -f Dockerfile.tests . || exit 1
docker rmi faucet/faucet-testbase
docker images

# If sanity shard, just the sanity test and lint/type/dependency checks.
if [ "${MATRIX_SHARD}" == "sanity" ] ; then
  touch ~/.pylintrc
  cd ./docs
  pip3 install -r requirements.txt
  make html || exit 1
  rm -rf _build

  cd ../tests
  PYTHONPATH=~/faucet ./test_min_pylint.sh || exit 1
  PYTHONPATH=~/faucet ./test_coverage.sh || exit 1
  codecov || true
  cd ..
  RUNTESTS="FaucetSanityTest"
# If not the sanity shard, run sharded tests but skip lint/type/dependency checks.
else
  ALLTESTS=`grep -E -o "^class (Faucet[a-zA-Z0-9]+Test)" tests/faucet_mininet_test_unit.py|cut -f2 -d" "|sort`
  ALLTESTS+=" "`grep -E -o "^class (Faucet[a-zA-Z0-9]+Test)" clib/clib_mininet_test_unit.py|cut -f2 -d" "|sort`
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

sudo docker run --privileged --sysctl net.ipv6.conf.all.disable_ipv6=0 -t -e FAUCET_TESTS="-d ${RUNTESTS}" ${FAUCET_TEST_IMG}
