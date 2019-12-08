#!/bin/sh

[ "$1" = git ] && shift
[ "$1" = pull ] && shift

RR=$1
RB=$2
N=$3

if ! git diff --exit-code >/dev/null 2>&1; then
	echo "ERROR: There are local changes that must be commited or reseted"
	echo "ERROR: Cherrypulling process stopped to avoid data loss."
	exit 1
fi

if test -z "$N"; then
	echo "Usage: sys/cherrypull.sh [url] [branch] [ncommits]"
	exit 1
fi

git branch -D branch
git checkout -b branch
git reset --hard @~100
git pull $RR $RB
C=`git log | grep ^commit | head -n $N | cut -d ' ' -f2`
RC=""
git checkout master
for a in $C ; do
	RC="$a $RC"
done
for a in $RC ; do
	git cherry-pick $a
done
git branch -D branch
