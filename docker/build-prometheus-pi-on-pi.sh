#!/bin/bash

# run from cron on Raspberry Pi build farm.

date
cd $(dirname $0) && \
cd .. && \
git stash && \
git checkout -q master && \
git pull 2>&1 || exit 1

TMPDIR=$(mktemp -d /tmp/$(basename $0).XXXXXX)
DOCKER_ID_USER="faucet"
DOCKER="docker"

build_tag()
{
    tag=$1
    branch=$2
    echo "building tag $tag (branch $branch)"
    git checkout -q $branch && \
    $DOCKER build -t $DOCKER_ID_USER/prometheus-pi:$tag -f docker/prometheus/Dockerfile . && \
    $DOCKER push $DOCKER_ID_USER/prometheus-pi:$tag
}

version=$(grep -Eo "ARG.*VERSION=[0-9\.]+" docker/prometheus/Dockerfile | cut -d '=' -f 2)
build_tag $version master

for s in created exited ; do
    for i in `$DOCKER ps --filter status=$s -q --no-trunc` ; do
        $DOCKER rm -f $i
    done
done
for i in `$DOCKER images --filter dangling=true -q --no-trunc` ; do
    $DOCKER rmi -f $i
done

rm -rf "$TMPDIR"
