#!/bin/sh
# TODO: btrfs does not have READ hook
# TODO: cpio | tarfs

if [ -z "$1" ]; then
	echo "Use: makeplugin.sh [newplugname]"
	exit 1
fi
U=$(echo $1 | tr '[a-z]' '[A-Z]')
sed -e s,fat,$1,g -e s,FAT,$U,g fat.mk > $1.mk
sed -e s,fat,$1,g -e s,FAT,$U,g fs_fat.c > fs_$1.c
