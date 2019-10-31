#!/bin/bash -e
#
# Utility script for running tests locally. Spins up the appropriate
# docker container, and drops into a command line.
#
# Run everything
#FAUCET_TESTS=
#
# Run (all) integration tests.
FAUCET_TESTS="-i -n"
#
# Run a specific test, keeping results.
#FAUCET_TESTS="-i -n -k FaucetUntaggedLLDPTest"

CMD=bash

ROOT=$(realpath $(dirname $0)/..)
cd $ROOT

sudo docker build --pull -t faucet/tests -f Dockerfile.tests  .

echo
echo "environment set:"
echo "  FAUCET_TESTS=\"$FAUCET_TESTS\""
echo "try:"
echo "  docker/runtests.sh"
echo

mkdir -p test_results

sudo docker run -ti --privileged \
     -v $PWD:/faucet-src \
     -v $PWD/test_results:/var/tmp \
     -e FAUCET_TESTS="$FAUCET_TESTS" \
     --sysctl net.ipv6.conf.all.disable_ipv6=0 \
     faucet/tests $CMD
