#!/bin/sh

WRKDIR=$PWD/tmp
TYPES=fuzz_bin fuzz_bin2 fuzz_cmd fuzz_dwarf fuzz_fs fuzz_ia fuzz_pdb_parse fuzz_x509_parse

mkdir -p "${WRKDIR}/inbox"
mkdir -p "${WRKDIR}/outbox"

for a in ${TYPES} ; do
	LF=$(mktemp $WD/$a.XXXXXX)
	echo "Logfile ${LF}"
	make r T=$a | tee "${LF}"
done

