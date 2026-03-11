#!/bin/sh

WRKDIR=$PWD/tmp
TYPES="fuzz_bin fuzz_bin2 fuzz_cmd fuzz_dwarf fuzz_fs fuzz_ia fuzz_pdb_parse fuzz_x509_parse"

mkdir -p "${WRKDIR}/inbox"
mkdir -p "${WRKDIR}/outbox"

while : ; do
	for a in ${TYPES} ; do
		LF=$(mktemp "$WRKDIR/inbox/$a.XXXXXX")
		echo "Logfile for $a is ${LF}"
		make r T=$a 2>&1 | tee "${LF}"
		echo "Logfile for $a was ${LF}"
		sleep 5
	done
	sleep 5
done
