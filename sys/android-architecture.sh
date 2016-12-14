#!/bin/sh

if [ "$#" -ne 1 ]; then
	echo "Please enter an android architecture..."
	echo "Usage $0: {aarch64|arm|mips|mips64|x86}"
	exit 1
fi

case "$1" in
aarch64|arm|mips|mips64|x86)
	cd `dirname "$PWD/$0"`

	case "$1" in
	aarch64|arm|x86)
		export CFLAGS="-O3"
		;;
	mips)
		export CFLAGS="-O3 -fPIC"
		;;
	mips64)
		export CFLAGS="-O3 -fPIC -pie -fpic"
		;;
	esac

	case "$1" in
	aarch64|arm|mips|mips64)
		android-shell.sh $1 ./android-build.sh $1-static
		;;
	x86)
		android-shell.sh x86 ./android-build.sh x86
		;;
	esac
	;;
*)
	echo "Wrong param: $1"
	echo "Usage $0: {aarch64|arm|mips|mips64|x86}"
	exit 1
esac
