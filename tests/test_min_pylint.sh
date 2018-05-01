#!/bin/bash

MINRATING="9.2"
SRC_FILES=`dirname $0`"/../faucet/[a-z]*.py"


for f in $SRC_FILES ; do
  RATING=`pylint $f | grep -ohE "rated at [0-9\.]+" | sed "s/rated at //g"`
  echo pylint $f: $RATING
  if [ $(bc <<< "$RATING < $MINRATING") -eq 1 ] ; then
      echo "$RATING below min ($MINRATING)"
      exit 1
  fi
done

exit 0
