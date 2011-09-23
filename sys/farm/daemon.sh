#!/bin/sh
cd `dirname $PWD/$0` 
up() {
	if [ -d ../../.hg ]; then
		hg pull -u
	elif [ -d ../../.git ]; then
		git pull
	fi
}
. ./CONFIG
while : ; do
	up ; ( ./check.sh )  && ./run.sh
	sleep ${SLEEP}
done
