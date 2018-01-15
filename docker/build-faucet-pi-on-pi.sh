#!/bin/bash

# run from cron on Raspberry Pi build farm.
# build and push tags supplied as arguments, or build tags missing from tag if no arguments.

date
cd $(dirname $0) && \
cd .. && \
git stash && \
git checkout -q master && \
git pull 2>&1 || exit 1

DOCKER_ID_USER="faucet"
DOCKER="docker"

parse_tags()
{
    read -r && grep -E "^[0-9\.]+$" | sort -V
}

build_tag()
{
    tag=$1
    branch=$2
    echo "building tag $tag (branch $branch)"
    git checkout -q $branch && \
    cd docker/base && \
    $DOCKER build -t $DOCKER_ID_USER/faucet-base-pi:$tag -f Dockerfile.pi . && \
    cd ../python && \
    $DOCKER build -t $DOCKER_ID_USER/faucet-python3-pi:$tag -f Dockerfile.pi . && \
    cd ../../ && \
    $DOCKER build -t $DOCKER_ID_USER/faucet-pi:$tag -f Dockerfile.pi . && \
    $DOCKER build -t $DOCKER_ID_USER/gauge-pi:$tag -f Dockerfile.pi-gauge . && \
    $DOCKER tag $DOCKER_ID_USER/faucet-base-pi:$tag $DOCKER_ID_USER/gauge-pi:latest && \
    $DOCKER tag $DOCKER_ID_USER/faucet-python3-pi:$tag $DOCKER_ID_USER/gauge-pi:latest && \
    $DOCKER tag $DOCKER_ID_USER/faucet-pi:$tag $DOCKER_ID_USER/gauge-pi:latest && \
    $DOCKER tag $DOCKER_ID_USER/gauge-pi:$tag $DOCKER_ID_USER/gauge-pi:latest && \
    $DOCKER push $DOCKER_ID_USER/faucet-base-pi:$tag && \
    $DOCKER push $DOCKER_ID_USER/faucet-python3-pi:$tag && \
    $DOCKER push $DOCKER_ID_USER/faucet-pi:$tag && \
    $DOCKER push $DOCKER_ID_USER/gauge-pi:$tag && \
    $DOCKER push $DOCKER_ID_USER/faucet-base-pi:latest && \
    $DOCKER push $DOCKER_ID_USER/faucet-python3-pi:latest && \
    $DOCKER push $DOCKER_ID_USER/faucet-pi:latest && \
    $DOCKER push $DOCKER_ID_USER/gauge-pi:latest
}


if [ "$1" != "" ] ; then
    for tag in $* ; do
        build_tag $tag $tag
    done
else
    TMPDIR=$(mktemp -d /tmp/$(basename $0).XXXXXX)
    wget -q -O- 'https://registry.hub.docker.com/v2/repositories/faucet/faucet-pi/tags?page_size=1024'|jq --raw-output '."results"[]["name"]' | parse_tags > $TMPDIR/dockertags.txt
    git tag | parse_tags > $TMPDIR/repotags.txt
    MISSINGDOCKERTAGS=$(diff -u $TMPDIR/dockertags.txt $TMPDIR/repotags.txt |grep -E "^\+\S+$"|sed "s/\+//g")
    rm -rf "$TMPDIR"
    # Build any tags missing from Docker Hub.
    if [ "$MISSINGDOCKERTAGS" != "" ] ; then
        echo missing docker tags: $MISSINGDOCKERTAGS
        for tag in $MISSINGDOCKERTAGS ; do
            build_tag $tag $tag
        done
    fi
fi

for s in created exited ; do
    for i in `$DOCKER ps --filter status=$s -q --no-trunc` ; do
        $DOCKER rm -f $i
    done
done
for i in `$DOCKER images --filter dangling=true -q --no-trunc` ; do
    $DOCKER rmi -f $i
done
