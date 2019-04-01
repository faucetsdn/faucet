#!/bin/bash

FAUCETHOME=`dirname $0`"/../.."
SRCFILES="$FAUCETHOME/tests/codecheck/src_files.sh $*"
$SRCFILES | shuf | parallel --delay 1 --bar --halt now,fail=1 -j 2 ./min_pylint.sh || exit 1
exit 0
