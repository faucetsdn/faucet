#!/bin/bash

UNITTESTS=1
DEPCHECK=1
MINCOVERAGE=85

set -e  # quit on error

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
  cp -r /var/tmp/pip-cache /var/tmp/pip-cache-local
fi
./docker/pip_deps.sh "--cache-dir=/var/tmp/pip-cache-local"
./docker/workarounds.sh

echo "========== checking IPv4/v6 localhost is up ====="
ping6 -c 1 ::1
ping -c 1 127.0.0.1

echo "========== Starting OVS ========================="
export OVS_LOGDIR=/usr/local/var/log/openvswitch
/usr/local/share/openvswitch/scripts/ovs-ctl start
ovs-vsctl show
ovs-vsctl --no-wait set Open_vSwitch . other_config:max-idle=50000
# Needed to support double tagging.
ovs-vsctl --no-wait set Open_vSwitch . other_config:vlan-limit=2

cd /faucet-src/tests

./sysctls_for_tests.sh || true

# TODO: need to force UTF-8 as POSIX causes python3/pytype errors.
locale-gen en_US.UTF-8
export LANG=en_US.UTF-8
export LANGUAGE=en_US.en
export LC_ALL=en_US.UTF-8

export PYTHONPATH=/faucet-src:/faucet-src/faucet:/faucet-src/clib

if [ "$UNITTESTS" == 1 ] ; then
    echo "========== Running faucet unit tests =========="
    cd /faucet-src/tests
    time ./run_unit_tests.sh
fi


if [ "$DEPCHECK" == 1 ] ; then
    echo "========== Building documentation =========="
    cd /faucet-src/docs
    time make html
    rm -rf _build

    cd /faucet-src/tests/codecheck
    echo "============ Running pylint analyzer ============"
    time ./pylint.sh $PY_FILES_CHANGED
    echo "============ Running pytype analyzer ============"
    time ./pytype.sh $PY_FILES_CHANGED
fi

echo "========== Starting docker container =========="
service docker start || true

echo "========== Running faucet system tests =========="
test_failures=
export FAUCET_DIR=/faucet-src/faucet
export http_proxy=

cd /faucet-src/tests/integration
./mininet_main.py -c
time ./mininet_main.py $FAUCET_TESTS || test_failures+=" mininet_main"

cd /faucet-src/clib
time ./clib_mininet_test.py $FAUCET_TESTS || test_failures+=" clib_mininet_test"

if [ -n "$test_failures" ]; then
    echo Test failures: $test_failures
    exit 1
fi

echo Done with faucet system tests.
