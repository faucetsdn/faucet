#!/bin/bash

UNITTESTS=1
DEPCHECK=1
MINCOVERAGE=85

cd /faucet-src

if [ -d /var/tmp/pip-cache ] ; then
  cp -r /var/tmp/pip-cache /var/tmp/pip-cache-local || exit 1
fi
./docker/pip_deps.sh "--cache-dir=/var/tmp/pip-cache-local" || exit 1

# if -n passed, don't check dependencies/lint/type/documentation.
# wrapper script only cares about -n, others passed to test suite.
while getopts "cdjknsxi" o $FAUCET_TESTS; do
  case "${o}" in
        n)
            DEPCHECK=0
            ;;
        i)
            UNITTESTS=0
            DEPCHECK=0
            ;;
        *)
            ;;
    esac
done

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

if [ "$UNITTESTS" == 1 ] ; then
    echo "========== Running faucet unit tests =========="
    cd /faucet-src/tests
    PYTHONPATH=.. ./test_coverage.sh || exit 1
    # TODO: enable under travis
    # codecov || true
fi

if [ "$DEPCHECK" == 1 ] ; then
    echo "========== Building documentation =========="
    cd /faucet-src/docs
    make html || exit 1
    rm -rf _build

    cd /faucet-src/tests
    echo "============ Running pytype analyzer ============"
    # TODO: need to force UTF-8 as POSIX causes pytype errors
    locale-gen en_US.UTF-8 || exit 1
    LANG=en_US.UTF-8 LANGUAGE=en_US.en LC_ALL=en_US.UTF-8 ./test_pytype.sh || exit 1

    echo "============ Running pylint analyzer ============"
    PYTHONPATH=.. ./test_min_pylint.sh || exit 1
fi

echo "========== Starting docker container =========="
service docker start

echo "========== Running faucet system tests =========="
test_failures=
export PYTHONPATH=/faucet-src

cd /faucet-src/tests
python2 ./faucet_mininet_test.py -c
http_proxy="" python2 ./faucet_mininet_test.py $FAUCET_TESTS || test_failures+=" faucet_mininet_test"

cd /faucet-src/clib
http_proxy="" python2 ./clib_mininet_test.py $FAUCET_TESTS || test_failures+=" clib_mininet_test"

if [ -n "$test_failures" ]; then
    echo Test failures: $test_failures
    exit 1
fi

echo Done with faucet system tests.
