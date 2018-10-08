#!/bin/bash

FAUCETHOME=`dirname $0`"/../.."
SRCFILES=`$FAUCETHOME/tests/codecheck/src_files.sh`
if [[ "$*" != "" ]] ; then
  SRCFILES="$*"
fi
echo $SRCFILES | tr " " "\n" | shuf | parallel --bar ./min_pylint.sh || exit 1
exit 0
