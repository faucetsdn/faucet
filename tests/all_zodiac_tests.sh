#!/bin/sh
 ./all_tests.sh -s `grep -oh "Faucet.*Zodiac[a-zA-Z0-9]\+" faucet_mininet_test.py |tr '\n' ' '`
