#!/bin/bash

MINCOVERAGE=92
SCRIPTPATH=$(readlink -f "$0")
TESTDIR=`dirname $SCRIPTPATH`
BASEDIR=`readlink -f $TESTDIR/..`
cd $BASEDIR || exit 1

coverage erase || exit 1
for i in $TESTDIR/unit/*/test_*py $TESTDIR/integration/experimental_api_test_app.py; do
    TESTCMD="coverage run -a --source $BASEDIR/faucet $i -f"
    echo $TESTCMD
    PYTHONPATH=$BASEDIR $TESTCMD || exit 1
done
coverage report -m --fail-under=$MINCOVERAGE || exit 1
