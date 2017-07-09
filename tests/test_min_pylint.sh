#!/bin/bash

MINRATING="9.0"
SRC_FILES="../faucet/*.py"

pylint -E $SRC_FILES || exit 1
RATING=`pylint $SRC_FILES | grep -ohE "rated at [0-9\.]+" | sed "s/rated at //g"`
echo pylint rating: $RATING
if [ $(bc <<< "$RATING < $MINRATING") -eq 1 ] ; then
  echo "$RATING below min ($MINRATING)"
  exit 1
fi

exit 0
