#!/bin/sh
N=$1
OLDIR=`pwd`
cd `dirname $0` 2>/dev/null
if [ -z "$N" ]; then
	echo "Usage: shell.sh [commit-num] [cmd...]"
	exit 1
fi
shift
CMD="$@"

DIR=`ls -d build/radare2-$N-* 2>/dev/null`
if [ -z "${DIR}" ]; then
	echo "Cannot find rev $N"
	exit 1
fi
export PATH=`pwd`/$DIR/prefix/bin:${PATH}
type r2
if [ -z "$CMD" ]; then
	exec /bin/sh
fi
cd $OLDIR
pwd
echo "== $CMD"
exec $CMD
