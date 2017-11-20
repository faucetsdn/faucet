#!/bin/bash

# run from cron on Raspberry Pi build farm.

export TMPDIR=/tmp/`basename $0`
rm -rf $TMPDIR
mkdir -p $TMPDIR

date
cd .. && \
git stash && \
git checkout -q master && \
git pull 2>&1 || exit 1

export DOCKER_ID_USER="faucet"
export DOCKER="docker"

build_tag()
{
    tag=$1
    branch=$2
    echo "building tag $tag (branch $branch)"
    git checkout -q $branch
    $DOCKER build -t prometheus-pi -f docker/prometheus/Dockerfile .
    $DOCKER tag -f prometheus-pi $DOCKER_ID_USER/prometheus-pi:$tag
    $DOCKER push $DOCKER_ID_USER/prometheus-pi:$tag
}

VERSION=$(grep -Eo "ARG.*VERSION=[0-9\.]+" docker/prometheus/Dockerfile | cut -d '=' -f 2)
build_tag $VERSION master

$DOCKER rmi -f $($DOCKER images --filter "dangling=true" -q --no-trunc) 2>&1
rm -rf $TMPDIR
