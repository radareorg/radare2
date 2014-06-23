#!/bin/sh

[ "$1" = git ] && shift
[ "$1" = pull ] && shift

RR=$1
RB=$2
N=$3

if [ -z "$N" ]; then
	echo "Usage: sys/cherrypull.sh [url] [branch] [ncommits]"
	exit 1
fi

git branch -D branch
git co -b branch
git reset --hard @~100
git pull $RR $RB
C=`git log | grep ^commit | head -n $N | cut -d ' ' -f2`
RC=""
git co master
for a in $C ; do
	RC="$a $RC"
done
for a in $RC ; do
	git cherry-pick $a
done
git branch -D branch
