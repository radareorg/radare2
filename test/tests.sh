# do not execute #
. ../config.sh

out=$(mktemp out.XXXXXX)
rad=$(mktemp rad.XXXXXX)
run_test() {
	printf "Running ${NAME} ... \r"
	echo "${CMDS}" > $rad
	eval ${DBG} $r2 -e scr.color=0 -n -v -i $rad ${ARGS} ${FILE} ${PIP}
	if [ ! $? = 0 ]; then
		printf "ERROR+"
	fi
	if [ "$(cat $out)" = "${EXPECT}" ]; then
		echo "Running ${NAME} ... SUCCESS"
	else
		echo "Running ${NAME} ... FAIL"
		printf "\x1b[32m"
		echo "--"
		cat $out
		echo "--"
		echo "${EXPECT}"
		echo "--"
		printf "\x1b[0m"
	fi
	rm -f $out $rad
}

PIP=">$out"
case "${DEBUG}" in
0|no)
	DBG="cat $rad |"
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
