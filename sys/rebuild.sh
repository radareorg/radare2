#!/bin/sh

while : ; do
	if [ -f sys/rebuild.sh ]; then
		break
	fi
	cd ..
	if [ "`pwd`" = / ]; then
		echo "Cant find sys/rebuild.sh"
		exit 1
	fi
done

Rebuild() {
	cd "$1" || exit 1
	make clean
	make -j8 || exit 1
	cd -
}

Build() {
	cd "$1" || exit 1
	make -j8 || exit 1
	cd -
}

RebuildIOSDebug() {
	Rebuild libr/debug
	# Rebuild libr/util
	# Rebuild libr/core
	Rebuild binr/radare2
	make -C binr/radare2 ios-sign
	if [ -n "${IOSIP}" ]; then
		scp binr/radare2/radare2 root@"${IOSIP}:."
	else
		echo "Set IOSIP environment variable to scp the radare2 program"
	fi
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

RebuildGdb() {
	Rebuild shlr/gdb
	Rebuild libr/io
	Rebuild libr/debug
}

case "$1" in
bin)    RebuildBin ; ;;
gdb)    RebuildGdb ; ;;
sdb)    RebuildSdb ; ;;
bin)    RebuildBin ; ;;
java)   RebuildJava ; ;;
iosdbg) RebuildIOSDebug ; ;;
capstone|cs) RebuildCapstone ; ;;
*)
	echo "Usage: sys/rebuild.sh [gdb|java|capstone|sdb|iosdbg|cs|sdb|bin]"
	;;
esac
