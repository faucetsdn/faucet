#!/bin/bash

FAUCETHOME=`dirname $0`"/../.."
PYTHONPATH=$FAUCETHOME:$FAUCETHOME/clib

MINRATING=9.44

lintfile=`tempfile`.lint

# TODO: --fail-under can't be used because it takes only integers.
for f in $* ; do
    PYTHONPATH=$PYTHONPATH pylint --rcfile=/dev/null --extension-pkg-whitelist=netifaces,pytricia -d import-error $f > $lintfile
    rating=`cat $lintfile | grep -ohE "rated at [0-9\.\-]+" | sed "s/rated at //g"`
    echo pylint $f: $rating
    failing=$(bc <<< "$rating < $MINRATING")
    if [ "$failing" -ne 0 ]; then
        cat $lintfile
        echo "$rating below min ($MINRATING), results in $lintfile"
        exit 1
    fi
    rm $lintfile
done

exit 0
