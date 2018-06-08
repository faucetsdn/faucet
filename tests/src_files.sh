#!/bin/bash

FAUCETHOME=`dirname $0`"/.."
for i in clib faucet tests ; do ls -1 $FAUCETHOME/$i/[a-z]*.py ; done | xargs realpath | sort
