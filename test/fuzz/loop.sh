#!/bin/sh

WRKDIR=$PWD/tmp
AGENT=codex-rs
PROMPT=<<EOF
Fix this bug, do not add unit tests, reason hard and find the root cause of the problem do not fix the consequence, do surgical patch but if needed refactor what's required to avoid adding unnecessary conditionals all around the code.
EOF

mkdir -p "${WRKDIR}/inbox"
mkdir -p "${WRKDIR}/outbox"

popcrash() {
	(
		cd "${WRKDIR}/inbox"
		ls | head -n1
	)
}

while : ; do
	F=`popcrash`
	if [ -z "${F}" ]; then
		echo "No pending crash to process.. waiting for "
		continue
	fi
	echo "${PROMPT}" > ${WRKDIR}/prompt.txt
	tail -n 60 "${WRKDIR}/inbox/${F}" >> ${WRKDIR}/prompt.txt
	mv "${WRKDIR}/inbox/${F}" "${WRKDIR}/outbox/${F}.crash"
	${AGENT} exec "$(c)" >> ${WRKDIR}/outbox/${F}.log
done
