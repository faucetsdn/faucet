#!/bin/sh

# Retry a command up to 3 times/until exit status 0

CMD=$1
status=1

for retry in $(seq 1 3); do
    $CMD && status=0 && break
    status=$?
    sleep 1
done

echo $CMD has exit status $status
(exit $status)
