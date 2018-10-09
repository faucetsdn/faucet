#!/bin/bash

FAUCETHOME=`dirname $0`"/../.."
SRCFILES="$FAUCETHOME/tests/codecheck/src_files.sh $*"
$SRCFILES | shuf | parallel --bar ./min_pylint.sh || exit 1
exit 0
