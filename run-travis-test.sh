#!/bin/bash

# TODO: run different tests based on matrix.
touch ~/.pylintrc
cd ~/tests
PYTHONPATH=~/faucet ./test_min_pylint.sh
PYTHONPATH=~/faucet python3 -m pytest ./test_*.py --cov faucet --doctest-modules -v --cov-report term-missing
coveralls || true
cd ~/
docker build -t ${FAUCET_TEST_IMG} -f Dockerfile.tests .
docker images
sudo docker run --privileged -t -e FAUCET_TESTS="-d" ${FAUCET_TEST_IMG}
