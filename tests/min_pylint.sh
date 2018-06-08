#!/bin/bash

FAUCETHOME=`dirname $0`"/.."
PYTHONPATH=$FAUCETHOME:$FAUCETHOME/clib

MINRATING=9.2

for f in $* ; do
    rating=`PYTHONPATH=$PYTHONPATH pylint --rcfile=/dev/null $f | grep -ohE "rated at [0-9\.]+" | sed "s/rated at //g"`
    echo pylint $f: $rating
    if [ $(bc <<< "$rating < $MINRATING") -eq 1 ] ; then
        echo "$rating below min ($MINRATING)"
        exit 1
    fi
done

exit 0
