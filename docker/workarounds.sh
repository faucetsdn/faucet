#!/bin/bash

# Hack/workaround for testtools breaking pytype
# https://github.com/google/pytype/issues/133
COMPAT=`python3 -c 'from testtools import compat; print(compat.__file__)'`
FIX='s/_compat2x as _compat/_compat3x as _compat  # pytype workaround, was: _compat2x/'
sed -i -e "$FIX" $COMPAT
