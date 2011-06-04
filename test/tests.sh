# do not execute #
. ../config.sh

run_test() {
	printf "Running ${NAME} ... "
	echo "${CMDS}" > cmds.rad
	eval ${DBG} $r2 -v -i cmds.rad ${ARGS} ${FILE} ${PIP}
	if [ ! $? = 0 ]; then
		printf "ERROR+"
	fi
	if [ "$(cat cmds.out)" = "${EXPECT}" ]; then
		echo "SUCCESS"
	else
		echo "FAIL"
printf "\x1b[32m"
echo "--"
		cat cmds.out
echo "--"
echo "${EXPECT}"
echo "--"
printf "\x1b[0m"
	fi
	rm -f cmds.rad cmds.out
}

PIP=">cmds.out"
case "${DEBUG}" in
0|no)
	DBG="echo q |"
	;;
1|yes|gdb)
	DBG="gdb --args"
	PIP=""
	;;
2|valgrind)
	DBG="valgrind --leak-check=full --track-origins=yes"
	DBG="${DBG} --workaround-gcc296-bugs=yes --read-var-info=yes"
	PIP="2>&1 | tee out.valgrind"
	;;
esac

NAME=$0
export DBG CMDS NAME ARGS FILE EXPECT PIP
run_test
