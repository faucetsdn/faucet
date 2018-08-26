#!/bin/bash

FAUCETHOME=`dirname $0`"/../.."
# TODO: test_packaging.py causes pytype to die.
for i in clib faucet tests ; do find $FAUCETHOME/$i/ -type f -name [a-z]*.py ; done | xargs realpath | sort |grep -v test_packaging.py
