#!/bin/bash

set -euo pipefail

INTEGRATIONTESTS=1
UNITTESTS=1
DEPCHECK=1
GEN_UNIT=0
GEN_TOLERANCE=0
SKIP_PIP=0
HELP=0
HWTESTS=${HWTESTS:-0}
PY_FILES_CHANGED=${PY_FILES_CHANGED:-""}


if [ -z "${FAUCET_TESTS:-}" ]; then
  # If FAUCET_TESTS env var isn't set read arguments from argv
  FAUCET_TESTS="$*"
fi

PARAMS=""

# Parse options, some are used by this script, some are
# passed onto mininet_main.py & clib_mininet_main.py
for opt in ${FAUCET_TESTS}; do
  case "${opt}" in
    --help)
      HELP=1
      ;;
    --check)
      INTEGRATIONTESTS=0
      UNITTESTS=0
      DEPCHECK=1
      ;;
    --integration)
      INTEGRATIONTESTS=1
      UNITTESTS=0
      DEPCHECK=0
      PARAMS+=" -i"		# Is this still needed ?
      ;;
    --unit)
      INTEGRATIONTESTS=0
      UNITTESTS=1
      DEPCHECK=0
      ;;
    --nocheck)
      DEPCHECK=0
      PARAMS+=" -n"		# Is this still needed ?
      ;;
    --nointegration)
      INTEGRATIONTESTS=0
      ;;
    --nounit)
      UNITTESTS=0
      ;;
    --generative_unit)
      GEN_UNIT=1
      UNITTESTS=0
      DEPCHECK=0
      INTEGRATIONTESTS=0
      PARAMS+=" ${opt}"
      ;;
    --generative_tolerance)
      GEN_TOLERANCE=1
      UNITTESTS=0
      DEPCHECK=0
      INTEGRATIONTESTS=0
      PARAMS+=" ${opt}"
      ;;
    --*)
      PARAMS+=" ${opt}"
      ;;
    -*)
      for (( i=1; i<${#opt}; i++ )); do
        case "${opt:$i:1}" in
          i)
            # run only integration tests
            UNITTESTS=0
            DEPCHECK=0
            PARAMS+=" -${opt:$i:1}"
            ;;
          n)
            # skip code check
            DEPCHECK=0
            PARAMS+=" -${opt:$i:1}"
            ;;
          u)
            # skip unit tests
            UNITTESTS=0
            ;;
          z)
            # Skip pip installer
            echo "Option set to assume environment is set up."
            SKIP_PIP=1
            ;;
          *)
            PARAMS+=" -${opt:$i:1}"
            ;;
        esac
      done
      ;;
    *)
      PARAMS+=" ${opt}"
      ;;
  esac
done

# Remove leading space
FAUCET_TESTS="${PARAMS#"${PARAMS%%[![:space:]]*}"}"

cd /faucet-src

if [ "$SKIP_PIP" == 0 ] ; then
    pip_deps_args=()
  if [ -d /var/tmp/pip-cache ] ; then
    echo "Using pip cache"
    pip_deps_args+=("--pip-args=--cache-dir=/var/tmp/pip-cache")
  fi
  if [ "$DEPCHECK" == 1 ] ; then
    pip_deps_args+=("--extra-requirements=codecheck-requirements.txt")
  fi
  ./docker/pip_deps.sh "${pip_deps_args[@]}"
else
  echo "Skipping pip install script"
fi

export PYTHONPATH=/faucet-src:/faucet-src/faucet:/faucet-src/clib

if [ "$HELP" == 1 ] ; then
  cd /faucet-src/tests/integration
  ./mininet_main.py --help
  exit 0
fi

if [ "$UNITTESTS" == 1 ] ; then
  echo "========== Running faucet unit tests =========="
  cd /faucet-src/tests
  time ./run_unit_tests.sh
elif [ "$GEN_UNIT" == 1 ] ; then
  echo "========== Running faucet generative unit tests =========="
  cd /faucet-src/tests/generative/unit/
  time ./test_topology.py
else
  echo "========== Skipping unit tests =========="
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
else
  echo "========== Skipping code checks =========="
fi

if [ $INTEGRATIONTESTS -eq 0 -a $GEN_TOLERANCE -eq 0 ] ; then
  echo "========== Skipping integration tests =========="
  echo Done with faucet system tests.
  exit 0
fi

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

/faucet-src/tests/sysctls_for_tests.sh || true

echo "========== Starting docker container =========="
mkdir -p /var/local/run/
if ! grep -q "unix:///var/local/run/docker.sock" /etc/default/docker; then
cat << EOF >> /etc/default/docker
DOCKER_OPTS="-H unix:///var/local/run/docker.sock"
EOF
fi
export DOCKER_HOST="unix:///var/local/run/docker.sock"
service docker start || true

echo "========== Running faucet system tests =========="
test_failures=
export FAUCET_DIR=/faucet-src/faucet
export http_proxy=

if [ "$INTEGRATIONTESTS" == 1 ] ; then
  echo "========== Running faucet integration tests =========="
  cd /faucet-src/tests/integration
  ./mininet_main.py -c
elif [ "$GEN_TOLERANCE" == 1 ] ; then
  echo "========== Running faucet generative integration fault-tolerance tests =========="
  cd /faucet-src/tests/generative/integration/
  ./fault_tolerance_main.py -c
fi

if [ "$HWTESTS" == 1 ] ; then
  echo "========== Simulating hardware test switch =========="
  ovs-vsctl add-br hwbr &&
    ovs-vsctl set-controller hwbr tcp:127.0.0.1:6653 tcp:127.0.0.1:6654 &&
    ovs-vsctl set-fail-mode hwbr secure &&
    ovs-vsctl set Open_vSwitch . other_config:vlan-limit=2
  DPID='0x'`sudo ovs-vsctl get bridge hwbr datapath-id|sed 's/"//g'`
  DP_PORTS=""
  N=$'\n'
  # TODO: randomize OF port range (offset from 1 for basic test)
  for p in `seq 2 5` ; do
    HWP="hwp$p"
    PHWP="p$HWP"
    ip link add dev $HWP type veth peer name $PHWP &&
      ifconfig $PHWP up &&
      ovs-vsctl add-port hwbr $PHWP -- set interface $PHWP ofport_request=$p
    for i in $HWP $PHWP ; do
      echo 1 > /proc/sys/net/ipv6/conf/$i/disable_ipv6
      ip -4 addr flush dev $i
      ip -6 addr flush dev $i
    done
    DP_PORTS="  ${p}: ${HWP}${N}${DP_PORTS}"
  done
  cat > /tmp/hw_switch_config.yaml << EOL
hw_switch: True
hardware: 'Open vSwitch TFM'
of_port: 6653
gauge_of_port: 6654
cpn_intf: lo
dp_ports:
${DP_PORTS}
dpid: ${DPID}
EOL
  mkdir -p /etc/faucet
  cp /tmp/hw_switch_config.yaml /etc/faucet
  cat /etc/faucet/hw_switch_config.yaml
  ovs-vsctl show
  ovs-ofctl dump-ports hwbr
fi

if [ "$INTEGRATIONTESTS" == 1 ]; then
  time ./mininet_main.py $FAUCET_TESTS || test_failures+=" mininet_main"
  cd /faucet-src/clib
  time ./clib_mininet_test.py $FAUCET_TESTS || test_failures+=" clib_mininet_test"
elif [ "$GEN_TOLERANCE" == 1 ] ; then
  time ./fault_tolerance_main.py $FAUCET_TESTS || test_failures+=" tolerance_main"
fi

if [ -n "${test_failures}" ]; then
    echo "Test failures: ${test_failures}"
    exit 1
fi

echo Done with faucet system tests.
