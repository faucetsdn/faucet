#!/bin/bash

FAUCETHOME=`dirname $0`"/.."
# TODO: remove workaround for mininet_test.py
$FAUCETHOME/tests/src_files.sh | grep -v mininet_test.py | parallel --delay 1 -j 2 --bar pytype -V3.5 -d pyi-error,import-error || exit 1
exit 0
