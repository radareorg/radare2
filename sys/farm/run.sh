#!/bin/sh

cd `dirname $PWD/$0` ; cd ..
. ./farm/CONFIG

revision() {
	R=`hg tip 2>/dev/null|head -n 1|cut -d : -f 2`
	[ -z "$R" ] && R=`git log|head -n1 |cut -d ' ' -f 2`
	[ -n "$R" ] && echo $R
}

tstamp() {
	date +%Y%m%d-%H
}

logfile() {
	echo "log/${PACKAGE}-`tstamp`-`revision`-$1"
}

getcpu() {
	uname -a
	cat /proc/cpuinfo | grep "model name" | head -n1
	printf "cpus: "
	cat /proc/cpuinfo | grep processor | tail -n 1 | awk '{print $3}'
	printf "bogomips: "
	cat /proc/cpuinfo | grep bogomips | tail -n 1 | awk '{print $3}'
}

mkdir -p farm/log
for a in ${TARGETS} ; do
	L=farm/`logfile $a`
	T=$L.time
	C=$L.cpu
	getcpu > $C
	echo "= $a" | tee $L.log
	(time ./${a}.sh 2>&1 | tee -a $L.log) 2> $T
	echo $? > $L.ret
done
echo `revision` > farm/last-revision
exit 0
