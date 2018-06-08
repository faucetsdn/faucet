#!/bin/bash

docker pull faucet/test-base
docker build -t ${FAUCET_TEST_IMG} -f Dockerfile.tests . || exit 1
docker rmi faucet/test-base
docker images

if [ "${MATRIX_SHARD}" = "sanity" ] ; then
  FAUCET_TESTS="FaucetSanityTest"
else
  ALLTESTFILES="tests/faucet_mininet_test_unit.py clib/clib_mininet_test_unit.py"
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
  FAUCET_TESTS="-i ${sharded[${MATRIX_SHARD}]}"
fi

echo $MATRIX_SHARD: $FAUCETTESTS
sudo docker run --privileged --sysctl net.ipv6.conf.all.disable_ipv6=0 -e FAUCET_TESTS="${FAUCET_TESTS}" -t ${FAUCET_TEST_IMG}
}
