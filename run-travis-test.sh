#!/bin/bash

touch ~/.pylintrc
cd ./tests
PYTHONPATH=~/faucet ./test_min_pylint.sh
PYTHONPATH=~/faucet python3 -m pytest ./test_*.py --cov faucet --doctest-modules -v --cov-report term-missing
coveralls || true
cd ..

docker build -t ${FAUCET_TEST_IMG} -f Dockerfile.tests .
docker images

ALLTESTS=`grep -E -o "^class (Faucet[a-zA-Z0-9]+Test)" tests/faucet_mininet_test_unit.py|cut -f2 -d" "`
SINGLETESTS=`echo "$ALLTESTS" | grep -o -E "\b(FaucetSingle.+Test)\b"`
PARALLELTESTS=`echo "$ALLTESTS" | grep -v -E "\b(FaucetSingle.+Test)\b"`

echo single process tests: ${SINGLETESTS}
echo parallelizable tests: ${PARALLELTESTS}

case ${TRAVIS_MATRIX} in
  SINGLE)
    RUNTESTS=${SINGLETESTS}
    ;;
  PARALLEL)
    RUNTESTS=${PARALLELTESTS}
    ;;
  *)
    RUNTESTS=''
    ;;
esac

sudo docker run --privileged -t -e FAUCET_TESTS="-d ${RUNTESTS}" ${FAUCET_TEST_IMG} 
