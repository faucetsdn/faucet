#!/bin/bash

./src_files.sh | shuf | parallel --bar ./min_pylint.sh || exit 1
exit 0
