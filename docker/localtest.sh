#!/bin/bash -e
#
# Utility script for running tests locally. Spins up the appropriate
# docker container, and drops into a command line.
#
# Run everything
#FAUCET_TESTS=
#
# Run (all) integration tests.
: ${FAUCET_TESTS="-i -n"}
#
# Run a specific test, keeping results.
#FAUCET_TESTS="-i -n -k FaucetUntaggedLLDPTest"

ROOT=$(realpath $(dirname $0)/..)
cd $ROOT

: ${CMD:=bash}
: ${TEST_RESULTS:=$ROOT/test_results}
: ${PIP_CACHE:=/tmp/faucet-pip-cache}

IMAGE_TAG=faucet/tests
: ${CONTAINER_NAME=local-test}

sudo modprobe openvswitch
sudo modprobe ebtables

if which apparmor_status >&/dev/null ; then
    if sudo apparmor_status --enabled ; then
        sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.tcpdump || :
    fi
fi

image_exists=$(sudo docker image ls -q $IMAGE_TAG)
if [ -z "$image_exists" -o -n "$FORCE_BUILD" ]; then
    sudo docker build \
      --pull \
      -t $IMAGE_TAG \
      -f Dockerfile.tests  .
fi

echo
if [ -n "$FAUCET_TESTS" ]; then
    echo "environment set:"
    echo "  FAUCET_TESTS=\"$FAUCET_TESTS\""
fi
echo "try:"
echo "  docker/runtests.sh"
echo

mkdir -p $PIP_CACHE $TEST_RESULTS
sudo chown root:root $PIP_CACHE

sudo docker run \
     --rm -ti \
     ${CONTAINER_NAME:+--name=$CONTAINER_NAME} \
     --privileged \
     --sysctl net.ipv6.conf.all.disable_ipv6=0 \
     -v $ROOT:/faucet-src \
     -v $TEST_RESULTS:/var/tmp \
     -v $PIP_CACHE:/var/tmp/pip-cache \
     -e DOCKER_HOST=unix:///var/local/run/docker.sock \
     ${FAUCET_TESTS:+-e FAUCET_TESTS="$FAUCET_TESTS"} \
     $IMAGE_TAG $CMD
