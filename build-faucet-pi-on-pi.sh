#!/bin/bash

# run from cron on Raspberry Pi build farm.

export TMPDIR=/tmp/`basename $0`
rm -rf $TMPDIR
mkdir -p $TMPDIR

date
cd ~/faucet && \
git stash && \
git checkout -q master && \
git pull 2>&1 || exit 1

export DOCKER_ID_USER="faucet"
export DOCKER="docker"
export TAGS=`wget -q -O- 'https://registry.hub.docker.com/v2/repositories/faucet/faucet-pi/tags?page_size=1024'|jq --raw-output '."results"[]["name"]'|grep -E "^[0-9\.]+$"|sort > $TMPDIR/tags.txt`
export REPOTAGS=`git tag|grep -E "^[0-9\.]+$"|sort > $TMPDIR/repotags.txt`
export MISSINGTAGS=`diff -u $TMPDIR/tags.txt $TMPDIR/repotags.txt |grep -E "^\+[0-9]+"|sed "s/\+//g"`

build_tag()
{
    tag=$1
    branch=$2
    echo "building tag $tag (branch $branch)"
    git checkout -q $branch
    $DOCKER build -t faucet-pi -f Dockerfile.pi .
    $DOCKER build -t gauge-pi -f Dockerfile.pi-gauge .
    $DOCKER tag -f faucet-pi $DOCKER_ID_USER/faucet-pi:$tag
    $DOCKER tag -f gauge-pi $DOCKER_ID_USER/gauge-pi:$tag
    $DOCKER push $DOCKER_ID_USER/faucet-pi:$tag
    $DOCKER push $DOCKER_ID_USER/gauge-pi:$tag
}

# Build any tags missing from Docker Hub.
if [ "$MISSINGTAGS" != "" ] ; then
    for tag in $MISSINGTAGS ; do
	build_tag $tag $tag
    done
fi

build_tag latest master

$DOCKER rmi -f $($DOCKER images --filter "dangling=true" -q --no-trunc) 2>&1
rm -rf $TMPDIR
