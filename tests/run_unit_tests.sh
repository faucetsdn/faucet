#!/bin/bash

MINCOVERAGE=92
SCRIPTPATH=$(readlink -f "$0")
TESTDIR=`dirname $SCRIPTPATH`
BASEDIR=`readlink -f $TESTDIR/..`
cd $BASEDIR || exit 1

TESTCMD="PYTHONPATH=$BASEDIR coverage run --parallel-mode --source $BASEDIR/faucet"
SRCFILES="find $TESTDIR/unit/*/test_*py $TESTDIR/integration/experimental_api_test_app.py -type f"

coverage erase || exit 1
$SRCFILES | xargs realpath | shuf | parallel --delay 1 --bar --halt now,fail=1 -j 2 $TESTCMD || exit 1
coverage combine
coverage report -m --fail-under=$MINCOVERAGE || exit 1
