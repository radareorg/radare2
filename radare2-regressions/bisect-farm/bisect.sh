#!/bin/sh

ONLY=
TEST=t/cmd_disasm
TEST=t/cmd_pdf_dwarf
TEST=t/anal/fcn_name

R2R=radare2-regressions

if [ ! -d $R2R ]; then
	git clone https://github.com/radare/$R2R
	cd $R2R
else
	cd $R2R
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
