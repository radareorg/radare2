#!/bin/sh

cd `dirname $PWD/$0` ; cd ..
. ./farm/CONFIG

revision() {
	echo `hg tip|head -n 1|cut -d : -f 2`
}

tstamp() {
	date +%Y%m%d-%H
}

logfile() {
	echo "log/${PACKAGE}-`tstamp`-`revision`-$1"
}

mkdir -p farm/log
for a in ${TARGETS} ; do
	L=farm/`logfile $a`
	echo "= $a" | tee $L.log
	./${a}.sh 2>&1 | tee -a $L.log
	echo $? > $L.ret
done
echo `revision` > farm/last-revision
exit 0
