#!/bin/bash

docker pull faucet/test-base
docker build -t ${FAUCET_TEST_IMG} -f Dockerfile.tests . || exit 1
docker rmi faucet/test-base
docker images

ALLTESTS=""
for i in tests/faucet_mininet_test_unit.py clib/clib_mininet_test_unit.py ; do
  ALLTESTS=`grep -E -o "^class (Faucet[a-zA-Z0-9]+Test)" $i|cut -f2 -d" "|sort`" "
done

if [ "${MATRIX_SHARD}" == "sanity" ] ; then
  RUNTESTS="FaucetSanityTest"
else:
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
  RUNTESTS="-i ${sharded[${MATRIX_SHARD}]}"
fi

sudo docker run --privileged --sysctl net.ipv6.conf.all.disable_ipv6=0 -t -e FAUCET_TESTS="-d ${RUNTESTS}" ${FAUCET_TEST_IMG}
