#!/bin/bash
echo "========== Running gNMI tests ==================="
# Just a placeholder that runs a gNMI client and displays help.
$GOPATH/bin/cli --help

echo "========== Starting OVS ========================="
service openvswitch-switch start

cd /faucet-src/tests

echo "============ Running pytype analyzer ============"
# TODO: pytype doesn't completely understand py3 yet.
ls -1 ../faucet/*py | parallel --bar pytype -d import-error || exit 1

while /bin/true; do
  wait -n || {
    code="$?"
    ([[ $code = "127" ]] && exit 0 || exit "$code")
    break
  }
done

echo "========== Running faucet config tests =========="
python3 ./test_config.py || exit 1
python3 ./test_check_config.py || exit 1

echo "========== Running faucet unit tests ============"
python3 ./test_valve.py || exit 1

echo "========== Running faucet system tests =========="
python2 ./faucet_mininet_test.py -c
time ./faucet_mininet_test.py $FAUCET_TESTS || exit 1
