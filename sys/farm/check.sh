#!/bin/sh

revision() {
	echo `hg tip|head -n 1|cut -d : -f 2`
}

cd `dirname $PWD/$0` ; cd ..
. ./farm/CONFIG
[ ! -f farm/last-revision ] && exit 1
now=`revision`
old=`cat farm/last-revision`
[ "$now" = "$old" ]
