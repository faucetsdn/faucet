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

IMAGE_TAG=faucet/tests

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
echo "environment set:"
echo "  FAUCET_TESTS=\"$FAUCET_TESTS\""
echo "try:"
echo "  docker/runtests.sh"
echo

mkdir -p test_results
mkdir -p /tmp/faucet-pip-cache

sudo docker run \
     --rm -ti \
     --privileged \
     --sysctl net.ipv6.conf.all.disable_ipv6=0 \
     -v $PWD:/faucet-src \
     -v $PWD/test_results:/var/tmp \
     -v /tmp/faucet-pip-cache:/var/tmp/pip-cache \
     -e FAUCET_TESTS="$FAUCET_TESTS" \
     $IMAGE_TAG $CMD
