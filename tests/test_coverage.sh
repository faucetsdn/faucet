#!/bin/bash

MINCOVERAGE=93

coverage erase || exit 1
for i in test_*py ; do PYTHONPATH=.. coverage run -a --source ../faucet $i || exit 1 ; done
coverage report -m --fail-under=$MINCOVERAGE || exit 1
