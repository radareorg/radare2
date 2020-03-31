#!/bin/sh

# Requires GNU Make, but some distros probably don't have the gmake symlink.
[ -z "$MAKE" ] && MAKE=make

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
	$MAKE clean
	$MAKE -j8 || exit 1
	cd -
}

Build() {
	cd "$1" || exit 1
	$MAKE -j8 || exit 1
	cd -
}

RebuildIOSDebug() {
	Rebuild libr/debug
	# Rebuild libr/util
	# Rebuild libr/core
	Rebuild binr/radare2
	$MAKE -C binr/radare2 ios-sign
	if [ -n "${IOSIP}" ]; then
		scp binr/radare2/radare2 root@"${IOSIP}:."
	else
		echo "Set IOSIP environment variable to scp the radare2 program"
	fi
}

RebuildJava() {
	Rebuild shlr/java
	Rebuild libr/asm
	Rebuild libr/anal
	Rebuild libr/bin
	Rebuild libr/core
}

RebuildCapstone() {
	if [ ! -d shlr/capstone ]; then
		make -C shlr capstone
	fi
	Rebuild shlr/capstone
	Rebuild libr/asm
	Rebuild libr/anal
}

RebuildSdb() {
	Rebuild shlr/sdb
	Rebuild libr/util
}

RebuildFs() {
	Rebuild shlr/grub
	Rebuild libr/fs
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

RebuildWindbg() {
	Rebuild shlr/windbg
	Rebuild libr/io
	Rebuild libr/debug
}

RebuildZip() {
	Rebuild shlr/zip
	Rebuild libr/io
}

RebuildTcc() {
	Rebuild shlr/tcc
	Rebuild libr/parse
}

case "$1" in
grub|fs)RebuildFs; ;;
bin)    RebuildBin ; ;;
gdb)    RebuildGdb ; ;;
windbg) RebuildWindbg ; ;;
sdb)    RebuildSdb ; ;;
spp)    RebuildSpp ; ;;
tcc)    RebuildTcc ; ;;
bin)    RebuildBin ; ;;
zip)    RebuildZip ; ;;
java)   RebuildJava ; ;;
iosdbg) RebuildIOSDebug ; ;;
capstone|cs) RebuildCapstone ; ;;
*)
	echo "Usage: sys/rebuild.sh [gdb|java|capstone|sdb|iosdbg|cs|sdb|bin]"
	;;
esac
