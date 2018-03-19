#!/bin/bash

DEPCHECK=1
MINCOVERAGE=75

TMPDIR=$(mktemp -d /tmp/$(basename $0).XXXXXX)

# if -n passed, don't check dependencies/lint/type/documentation.
# wrapper script only cares about -n, others passed to test suite.
while getopts "cdknsx" o $FAUCET_TESTS; do
  case "${o}" in
        n)
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

if [ "$DEPCHECK" == 1 ] ; then
    echo "========== Building documentation =========="
    cd /faucet-src/docs
    make html || exit 1
    rm -rf _build

    echo "============ Running pytype analyzer ============"
    cd /faucet-src/tests
    # TODO: pytype doesn't completely understand py3 yet.
    ls -1 ../faucet/*py | parallel pytype -d pyi-error,import-error || exit 1

fi

echo "========== Running faucet unit tests =========="
python3 -m pytest ./test_*.py --cov faucet --doctest-modules -v --cov-report term-missing | tee $TMPDIR/coverage.txt || exit 1
COVERAGE=`grep TOTAL $TMPDIR/coverage.txt |grep -Eo '\b[0-9]+\%'|sed 's/\%//g'`
echo coverage: $COVERAGE percent
if [ "$COVERAGE" -lt "$MINCOVERAGE" ] ; then
    echo coverage below minimum MINCOVERAGE percent
    exit 1
fi

rm -rf "$TMPDIR"

echo "========== Running faucet system tests =========="
python2 ./faucet_mininet_test.py -c
http_proxy="" python2 ./faucet_mininet_test.py $FAUCET_TESTS || exit 1
