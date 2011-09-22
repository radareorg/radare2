#!/bin/sh
cd `dirname $PWD/$0` 
while : ; do
	( ./check.sh )  && ./run.sh
	sleep ${SLEEP}
done
