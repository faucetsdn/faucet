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

: ${CMD:=bash}

ROOT=$(realpath $(dirname $0)/..)
cd $ROOT

sudo modprobe openvswitch
sudo modprobe ebtables

if which apparmor_status >&/dev/null ; then
    if sudo apparmor_status --enabled ; then
        sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.tcpdump || true
    fi
fi

sudo tests/sysctls_for_tests.sh || true

[ -n "$SKIP_BUILD" ] || sudo docker build --pull -t faucet/tests -f Dockerfile.tests  .

echo
echo "environment set:"
echo "  FAUCET_TESTS=\"$FAUCET_TESTS\""
echo "try:"
echo "  docker/runtests.sh"
echo

mkdir -p test_results

sudo docker run -ti \
     --privileged \
     --sysctl net.ipv6.conf.all.disable_ipv6=0 \
     -v /tmp/faucet-pip-cache:/var/tmp/pip-cache \
     -v /var/local/lib/docker:/var/lib/docker \
     -v $PWD:/faucet-src \
     -v $PWD/test_results:/var/tmp \
     -e FAUCET_TESTS="$FAUCET_TESTS" \
     faucet/tests $CMD
