#!/bin/sh
for a in $@ ; do
	HEX="`head -n 1 $a |cut -c 3-`"
	GEN="`rasm2 -f $a`"
	if [ "${HEX}" = "${GEN}" ]; then
		echo "[OK] $a"
	else
		echo "[XX] $a"
		echo "     EXPTD ${HEX}"
		echo "     FOUND ${GEN}"
	fi
done
