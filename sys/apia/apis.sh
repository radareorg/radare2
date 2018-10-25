#!/bin/sh
EXT=$(r2 -H LIBEXT)
LIBS=$(ls ../../libr/*/*.${EXT})
mkdir tmp
for LIB in $LIBS; do
	echo $LIB
	#SYMS=$(rabin2 -qs $LIB | grep -v '\.' |cut -d ' ' -f 3 | cut -c 2-)
	SYMS=$(rabin2 -qs $LIB | grep -v '\.' |cut -d ' ' -f 3 | cut -c 2- | grep r_)

	NAME=tmp/$(echo $LIB | awk -F / '{print $NF}')
	rabin2 -qi $LIB | grep r_ > $NAME.i
	echo > $NAME.s
	for SYM in $SYMS ; do
		echo " $SYM" >> $NAME.s
		printf "."
	done
	echo
done
