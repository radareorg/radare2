#!/bin/sh
NAME=cmd_macros
LAST=`curl -s http://ci.rada.re/job/radare2-regressions/ | \
	perl -ne 's,>,\n,g;print' | \
	perl -ne 'if (/Last build/) {
		$str = $_;
		$str=~/\(\#(\d+)\)/;
		$str = $1;
		print $str;
	}'
`

R2R=/tmp/.r2r.txt
R2C=/tmp/.r2c.txt
PREV=""
PR2REV=""
while : ; do
	[ ${LAST} -lt 0 ] && break
	echo "+ Testing build $LAST..."
	curl -s http://ci.rada.re/job/radare2-regressions/${LAST}/consoleText > $R2R
	R2B=`grep 'Started by upstream project' $R2R | awk '{print $8 }'`
	curl -s http://ci.rada.re/job/radare2/${R2B}/consoleText > $R2C
	R2REV=`grep 'Checking out Revision' $R2C | awk '{print $4}'`
	echo "  - radare2    $R2B = $R2REV"
	REV=`grep 'Checking out Revision' $R2R | awk '{print $4}'`
	echo "  - regression $LAST $REV"
	grep ${NAME} $R2R | grep -q XX
	if [ $? != 0 ]; then
		echo "Passing test found."
		echo " + LAST=$LAST..$PLAST"
		echo " + RRREV=$REV..$PREV"
		echo " + R2REV=$R2REV..$PR2REV"
	fi
	PREV=$REV
	PR2REV=$R2REV
	PLAST=$LAST
	LAST=$(($LAST-1))
done

rm -f $R2R $R2C

