#!/bin/bash

UNITTESTS=1
DEPCHECK=1
MINCOVERAGE=85

# allow user to skip parts of docker test
# this wrapper script only cares about -n, -u, -i, others passed to test suite.
while getopts "cdijknsux" o $FAUCET_TESTS; do
  case "${o}" in
        i)
            # run only integration tests
            UNITTESTS=0
            DEPCHECK=0
            ;;
        n)
            # skip code check
            DEPCHECK=0
            ;;
        u)
            # skip unit tests
            UNITTESTS=0
            ;;
        *)
            ;;
    esac
done

cd /faucet-src

if [ -d /var/tmp/pip-cache ] ; then
  echo Using pip cache
  cp -r /var/tmp/pip-cache /var/tmp/pip-cache-local || exit 1
fi
./docker/pip_deps.sh "--cache-dir=/var/tmp/pip-cache-local" || exit 1
./docker/workarounds.sh || exit 1

echo "========== checking IPv4/v6 localhost is up ====="
ping6 -c 1 ::1 || exit 1
ping -c 1 127.0.0.1 || exit 1

echo "========== Starting OVS ========================="
export OVS_LOGDIR=/usr/local/var/log/openvswitch
/usr/local/share/openvswitch/scripts/ovs-ctl start || exit 1
ovs-vsctl show || exit 1
ovs-vsctl --no-wait set Open_vSwitch . other_config:max-idle=50000
# Needed to support double tagging.
ovs-vsctl --no-wait set Open_vSwitch . other_config:vlan-limit=2

cd /faucet-src/tests

./sysctls_for_tests.sh

# TODO: need to force UTF-8 as POSIX causes python3/pytype errors.
locale-gen en_US.UTF-8 || exit 1

if [ "$UNITTESTS" == 1 ] ; then
    echo "========== Running faucet unit tests =========="
    cd /faucet-src/tests
    LANG=en_US.UTF-8 LANGUAGE=en_US.en LC_ALL=en_US.UTF-8 ./run_unit_tests.sh || exit 1
fi

if [ "$DEPCHECK" == 1 ] ; then
    echo "========== Building documentation =========="
    cd /faucet-src/docs
    make html || exit 1
    rm -rf _build

    cd /faucet-src/tests/codecheck
    echo "============ Running pytype analyzer ============"
    LANG=en_US.UTF-8 LANGUAGE=en_US.en LC_ALL=en_US.UTF-8 ./pytype.sh || exit 1

    echo "============ Running pylint analyzer ============"
    PYTHONPATH=../.. ./pylint.sh || exit 1
fi

echo "========== Starting docker container =========="
service docker start

echo "========== Running faucet system tests =========="
test_failures=
export FAUCET_DIR=/faucet-src/faucet
export PYTHONPATH=/faucet-src:/faucet-src/faucet:/faucet-src/clib

cd /faucet-src/tests/integration
./mininet_main.py -c
LANG=en_US.UTF-8 LANGUAGE=en_US.en LC_ALL=en_US.UTF-8 http_proxy="" ./mininet_main.py $FAUCET_TESTS || test_failures+=" mininet_main"

cd /faucet-src/clib
LANG=en_US.UTF-8 LANGUAGE=en_US.en LC_ALL=en_US.UTF-8 http_proxy="" ./clib_mininet_test.py $FAUCET_TESTS || test_failures+=" clib_mininet_test"

if [ -n "$test_failures" ]; then
    echo Test failures: $test_failures
    exit 1
fi

echo Done with faucet system tests.
