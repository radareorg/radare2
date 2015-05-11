#!/bin/sh

Rebuild() {
	cd $1
	make clean
	make -j8 || exit 1
	cd -
}

RebuildJava() {
	Rebuild shlr/java
	Rebuild libr/asm
	Rebuild libr/bin
	Rebuild libr/core
}

RebuildCapstone() {
	Rebuild shlr/capstone
	Rebuild libr/asm
	Rebuild libr/anal
}

RebuildSdb() {
	Rebuild shlr/sdb
	Rebuild libr/db
}

RebuildBin() {
	Rebuild libr/bin
	Rebuild libr/core
}

case "$1" in
bin)    RebuildBin ; ;;
sdb)    RebuildSdb ; ;;
bin)    RebuildBin ; ;;
java)   RebuildJava ; ;;
capstone|cs) RebuildCapstone ; ;;
*)
	echo "Usage: sys/rebuild.sh [java|capstone|sdb]"
	;;
esac
