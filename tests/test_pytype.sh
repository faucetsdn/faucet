#!/bin/bash

FAUCETHOME=`dirname $0`"/.."
$FAUCETHOME/tests/src_files.sh | parallel --delay 1 -j 2 --bar pytype -V3.5 -d pyi-error,import-error || exit 1
exit 0
