#!/bin/bash

FAUCETHOME=`dirname $0`"/.."
echo `$FAUCETHOME/tests/src_files.sh` | parallel --delim " " --delay 1 --bar pytype -d pyi-error,import-error || exit 1
exit 0
