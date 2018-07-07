#!/bin/bash

FAUCETHOME=`dirname $0`"/../.."
for i in clib faucet tests ; do find $FAUCETHOME/$i/ -type f -name [a-z]*.py ; done | xargs realpath | sort
