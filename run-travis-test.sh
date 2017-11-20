#!/bin/bash

touch ~/.pylintrc
cd ./tests
PYTHONPATH=~/faucet ./test_min_pylint.sh
PYTHONPATH=~/faucet python3 -m pytest ./test_*.py --cov faucet --doctest-modules -v --cov-report term-missing
coveralls || true
cd ..

docker build -t ${FAUCET_TEST_IMG} -f Dockerfile.tests .
docker images

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
RUNTESTS="${sharded[${MATRIX_SHARD}]}"

sudo docker run --privileged -t -e FAUCET_TESTS="-d ${RUNTESTS}" ${FAUCET_TEST_IMG} 
