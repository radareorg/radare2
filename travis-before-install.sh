#!/bin/bash

if [ "$TRAVIS_OS_NAME" != "osx" ]; then
    DOCKER_TAG=latest
    if [ "${TRAVIS_PULL_REQUEST_BRANCH}" != "" ] ; then
	DOCKER_TAG="$TRAVIS_PULL_REQUEST_BRANCH"
    fi
    export DOCKER_TAG="${DOCKER_TAG}"
    docker pull radareorg/r2-travis:${DOCKER_TAG} || docker build -t radareorg/r2-travis:${DOCKER_TAG} -f Dockerfile.travis . ;
else
    rm -rf .nvm
    git clone https://github.com/creationix/nvm.git .nvm
    cd .nvm && git checkout `git describe --abbrev=0 --tags`
    . .nvm/nvm.sh
    nvm install 8.11.3
fi
