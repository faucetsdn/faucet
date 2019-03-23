#!/bin/bash

FAUCETHOME=`dirname $0`"/../.."
TMPFILE=`tempfile`.srcfiles

if [[ "$*" == "" ]] ; then
  for i in clib faucet tests ; do find $FAUCETHOME/$i/ -type f -name [a-z]*.py ; done | xargs realpath > $TMPFILE || exit 1
else
  (cd $FAUCETHOME && readlink -f $*) > $TMPFILE || exit 1
fi

sort < $TMPFILE | while IFS= read -r f; do [[ -f "$f" ]] && echo "$f"; done
rm -f $TMPFILE
exit 0
