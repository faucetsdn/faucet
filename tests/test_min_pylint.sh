#!/bin/bash

MINRATING="9.0"
SRC_FILES="../faucet/*.py"

RATING=`ls -1 $SRC_FILES | parallel pylint | grep -ohE "rated at [0-9\.]+" | sed "s/rated at //g" |awk '{ total += $1; ++count } END { print total/count }'`
echo pylint rating: $RATING
if [ $(bc <<< "$RATING < $MINRATING") -eq 1 ] ; then
  echo "$RATING below min ($MINRATING)"
  exit 1
fi

exit 0
