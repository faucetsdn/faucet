#!/bin/bash

FAUCETHOME=`dirname $0`"/.."
SRC_FILES=$FAUCETHOME/*/[a-z]*.py
ls -1 $SRC_FILES | parallel --bar pytype -d pyi-error,import-error || exit 1
exit 0
