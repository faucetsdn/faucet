#!/bin/sh
 ./run_integration_tests.sh -s `grep -oh "Faucet.*Zodiac[a-zA-Z0-9]\+" integration/mininet_tests.py | tr '\n' ' '`
