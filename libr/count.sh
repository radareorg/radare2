#!/bin/sh
if [ -n "$1" ]; then
	echo 0 > /tmp/.cc.txt
	N=0
else
	N=`cat /tmp/.cc.txt 2> /dev/null`
fi
N=$(($N+1))
basename `pwd`
echo $N | tee /tmp/.cc.txt
