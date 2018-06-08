#!/bin/bash

FAUCETHOME=`dirname $0`"/.."
echo `$FAUCETHOME/tests/src_files.sh` | parallel -d " " --bar ./min_pylint.sh || exit 1
exit 0
