#!/bin/sh
if [ -z "$2" ]; then
	echo "Usage: sh mkgir.sh RAsm r_asm"
	exit 1
fi
N=$1
A=$2

deps() {
	for a in `cat ../vapi/$1.deps`; do
		printf -- "--pkg $a "
	done
}

cat ../vapi/$A.vapi | perl vapi2vala.pl > $A.vala

HEADER="--use-header -H $A.h"
echo "valac $(deps $A) --library=$A-1.0 --gir=$A-1.0.gir $A.vala"
valac ${HEADER} -C $(deps $A) --library=$N-1.0 --gir=$N-1.0.gir $A.vala

mv $N-1.0.gir $N-1.0.tmp
cat $N-1.0.tmp | grep -v annotation > $N-1.0.gir
echo "g-ir-compiler -m $N -l lib$A.dylib $N-1.0.gir > $N-1.0.typelib"
g-ir-compiler -m $N -l lib$A.dylib $N-1.0.gir > $N-1.0.typelib

echo sudo cp r_asm-1.0.typelib /opt/local/lib/girepository-1.0/
#sudo cp $N-1.0.typelib /opt/local/lib/girepository-1.0/
