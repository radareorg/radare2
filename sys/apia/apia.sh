#!/bin/sh

A=r_$1
B=../../libr/$1/libr_$1.dylib
C=tmp/libr_$1.dylib

echo "Public"
rabin2 -qs $B | awk '{print $3}' | grep $A | sed -e 's,_r_,  r_,'

echo "Internal"
r2 -qcaac -c "ax~r_$1" $B | grep -v imp | sed -e 's, + ,+,g' | sed -e 's,code ,code,' | awk '{print $7" -> "$1}' | sort | sed -e 's,^,  ,' | grep -v str.

echo "External"
grep $A tmp/*.i | sed -e 's,^,  ,' | sed -e 's,tmp/lib,,' -e 's,.dylib.i:, -> ,'

echo "Unused"
for a in `cat $C.s | grep $A` ; do
	grep -q $a tmp/*.i
	if [ $? != 0 ]; then
		echo "  $a"
	fi
done
