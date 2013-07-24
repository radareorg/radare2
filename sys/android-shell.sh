#!/bin/sh
# android shell

if [ -n "$1" ]; then
	NDK_ARCH="$1"
	shift
fi
case "${NDK_ARCH}" in
arm|mips|x86)
	export NDK_ARCH
	;;
*)
	echo "Usage: $0 [arm|mips|x86]"
	exit 1
	;;
esac

LANG=C
export LANG
ROOT=`dirname $(pwd)/$0`
OS=`uname|tr 'A-Z' 'a-z'`
[ "${OS}" = macosx ] && OS=darwin

# TODO: autodetect or gtfo
if [ -f ~/.r2androidrc ]; then
	. ~/.r2androidrc
	echo "Using data from ~/.r2androidrc.."
else
	SDK=${HOME}/Downloads/android-sdk-${OS}
	NDK=${HOME}/Downloads/android-ndk-r7b
fi

if [ ! -d "${SDK}" ]; then 
	echo "Cannot find Android SDK ${SDK}"
	echo "Edit ~/.r2androidrc with:"
	echo 'SDK=~/Downloads/android-sdk-$(uname)'
	echo 'NDK=~/Downloads/android-ndk-r7b'
	exit 1
fi
if [ ! -d "${NDK}" ]; then
	echo "Cannot find Android NDK ${NDK}"
	echo "echo NDK=/path/to/ndk  > ~/.r2androidrc"
	echo "echo SDK=/path/to/sdk >> ~/.r2androidrc"
	exit 1
fi

TOOLCHAIN_MIPS=`ls ${NDK}/toolchains/ |grep "^mips" |sort |head -n 1`
TOOLCHAIN_ARM=`ls ${NDK}/toolchains/ |grep "^arm" |sort |head -n 1`
TOOLCHAIN_X86=`ls ${NDK}/toolchains/ |grep "^x86" |sort |head -n 1`

NDKPATH_MIPS=`echo ${NDK}/toolchains/${TOOLCHAIN_MIPS}/prebuilt/${OS}-x86*/bin/`
NDKPATH_ARM=`echo ${NDK}/toolchains/${TOOLCHAIN_ARM}/prebuilt/${OS}-x86*/bin/`
NDKPATH_X86=`echo ${NDK}/toolchains/${TOOLCHAIN_X86}/prebuilt/${OS}-x86*/bin/`

# r7b
#NDKPATH_ARM=`echo ${NDK}/toolchains/arm-*/prebuilt/$(uname|tr A-Z a-z)-x86/bin/`
#INCDIR=${NDK}/platforms/android-8/arch-arm/usr/include/
#CFLAGS=-I${INCDIR}
#echo $NDKPATH_ARM

PATH=$SDK/tools:$SDK/platform-tools:$NDK:${NDKPATH_X86}:${NDKPATH_ARM}:${NDKPATH_MIPS}:$PATH
export PATH
export CFLAGS
export NDK
[ -z "${SHELL}" ] && SHELL=sh
SHELL=sh
cp ${ROOT}/ndk-gcc ${NDK}
chmod +x ${NDK}/ndk-gcc
CC=ndk-gcc
PS1="[r2-android-${NDK_ARCH}]> "
export CC
export PS1
AR=arm-linux-androideabi-ar
export AR
A=$@
if [ -n "$A" ]; then
	${SHELL} -c "$A"
else
	${SHELL}
fi
