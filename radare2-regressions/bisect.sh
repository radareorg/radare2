#!/bin/sh
if [ -z "$1" ]; then
	echo "Use ./bisect.sh [test]"
	echo "    ./bisect.sh -a      # test all"
	echo "    ./bisect.sh -b      # test all BROKEN"
	exit 1
fi
TESTS=$@
SKIP=0
UPTO=128
if [ "${TESTS}" = "-a" ]; then
	TESTS_ALL=1
	TESTS=$(find t -type f| grep -v '/\.')
elif [ "${TESTS}" = "-b" ]; then
	TESTS=$(cd t ; grep -r BROKEN=1 *|cut -d : -f 1)
fi
if [ -z "${TESTS}" ]; then
	echo "* No matching test"
	exit 1
fi
for a in ${TESTS}; do
	if [ ! -x $a ]; then
		echo "* Cannot find test $a"
		exit 1
	fi
done
git clone .. radare2
cd radare2
echo "* Running bisect on ${TESTS}"
REVS=$(git log|grep ^commit |awk '{print $2}')
if [ ${SKIP} -gt 0 ]; then
	REV=""
	for a in ${REVS} ; do
		if [ ${SKIP} -gt 0 ]; then
			SKIP=$(($SKIP-1))
		else
			REV="$REV $a"
		fi
	done
	REVS="${REV}"
fi
for a in ${REVS}; do
	[ "${UPTO}" = 0 ] && break
	UPTO=$(($UPTO-1))
	echo "* `date`"
	echo "* Building revision $a ..."
	sleep 2
	sys/install-rev.sh ${a} > build.$a.log 2>&1
	cd .. # r2-regressions
	if [ 1 = "${TESTS_ALL}" ]; then
		make
	else
		for b in ${TESTS}; do
			( R2_SOURCED=1 ./$b ;
			  echo $? > .return ) | tee .output
			RET=
			[ "`cat .return`" != 0 ] && RET=1
			[ -n "`grep '\[XX\]' .output`" ] && RET=1
			if [ -z "${RET}" ]; then
				echo "* Worked on revision $a"
				exit 0
			else
				echo "* Error on revision $a"
			fi
			rm -f .output
		done
	fi
	cd radare2
done
exit 1
