#!/bin/bash

MINRATING="9.2"
FAUCETHOME=`dirname $0`"/.."

# TODO: add clib
for src_dir in faucet tests ; do
    src_files=$FAUCETHOME/$src_dir/[a-z]*.py

    for f in $src_files ; do
        rating=`PYTHONPATH=$FAUCETHOME pylint --rcfile=/dev/null $f | grep -ohE "rated at [0-9\.]+" | sed "s/rated at //g"`
        echo pylint $f: $rating
        if [ $(bc <<< "$rating < $MINRATING") -eq 1 ] ; then
            echo "$rating below min ($MINRATING)"
            exit 1
        fi
   done
done

exit 0
