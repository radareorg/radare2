#!/bin/sh

WRKDIR=$PWD/tmp
AGENT=codex-rs
PROMPT=<<EOF
Fix this bug, do not add unit tests, reason hard and find the root cause of the problem do not fix the consequence, do surgical patch but if needed refactor what's required to avoid adding unnecessary conditionals all around the code.
EOF

mkdir -p "${WRKDIR}/inbox"
mkdir -p "${WRKDIR}/outbox"
mkdir -p "${WRKDIR}/trash"

popcrash() {
	(
		cd "${WRKDIR}/inbox"
		ls | head -n1
	)
}

while : ; do
	F=`popcrash`
	if [ -z "${F}" ]; then
		echo "No pending crash to fix in the inbox.."
		pkill 'fuzz_*'
		sleep 10
		continue
	fi
	FF="${WRKDIR}/inbox/${F}"
	cat "$FF" | grep DEADLYSIG
	if [ $? != 0 ]; then
		mv "${FF}" "${WRKDIR}/trash"
	fi
	echo "${PROMPT}" > ${WRKDIR}/prompt.txt
	tail -n 60 "${WRKDIR}/inbox/${F}" >> ${WRKDIR}/prompt.txt
	(
		cd ../..
		${AGENT} exec "`cat ${WRKDIR}/prompt.txt`" 2>&1
	) | tee ${WRKDIR}/outbox/${F}.log
	if [ $? = 0 ]; then
		mv "${WRKDIR}/inbox/${F}" "${WRKDIR}/outbox/${F}.crash"
		git diff > "${WRKDIR}/outbox/${F}.patch"
		git reset --hard
		make b
	fi
done
