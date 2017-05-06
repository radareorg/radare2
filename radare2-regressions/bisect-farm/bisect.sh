#!/bin/sh

ONLY=
TEST=t/cmd_disasm
TEST=t/cmd_pdf_dwarf
TEST=t/anal/fcn_name

R2R_BINS=radare2-regressions/bins
R2R_BINS_URL=https://github.com/ret2libc/radare2-test-bins

if [ ! -d $R2R_BINS ]; then
	git clone $R2R_BINS_URL $R2R_BINS
	cd $R2R_BINS
else
	cd $R2R_BINS
	git pull
fi

for NUM in `sh ../ls.sh | sort -r` ; do
	echo "Running $NUM"
	sh ../shell.sh ${NUM} sh run_tests.sh $TEST
	if [ $? = 0 ]; then
		echo WORKED
		exit
	fi
done
