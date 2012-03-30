#!/bin/sh
# android shell

LANG=C
export LANG
ROOT=`dirname $PWD/$0`
OS=`uname|tr 'A-Z' 'a-z'`
[ "${OS}" = darwin ] && OS=macosx

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
	echo "Edit ~/.r2androidrc"
	exit 1
fi
if [ ! -d "${NDK}" ]; then
	echo "Cannot find Android NDK ${NDK}"
	echo "echo NDK=/path/to/ndk  > ~/.r2androidrc"
	echo "echo SDK=/path/to/sdk >> ~/.r2androidrc"
	exit 1
fi

NDKPATH_MIPS=`echo ${NDK}/toolchains/mips-*/prebuilt/${OS}-x86/bin/`
NDKPATH_ARM=`echo ${NDK}/toolchains/arm-*/prebuilt/${OS}-x86/bin/`
NDKPATH_X86=`echo ${NDK}/toolchains/x86-*/prebuilt/${OS}-x86/bin/`

# r7b
NDKPATH_ARM=`echo ${NDK}/toolchains/arm-*/prebuilt/$(uname|tr A-Z a-z)-x86/bin/`
#INCDIR=${NDK}/platforms/android-8/arch-arm/usr/include/
#CFLAGS=-I${INCDIR}
echo $NDKPATH_ARM

PATH=$SDK/tools:$SDK/platform-tools:$NDK:${NDKPATH_X86}:${NDKPATH_ARM}:${NDKPATH_MIPS}:$PATH
export PATH
export CFLAGS
export NDK
cp ${ROOT}/ndk-gcc ${NDK}
chmod +x ${NDK}/ndk-gcc
CC=ndk-gcc
export CC
export PS1
sh $@
#echo $SHELL
#$SHELL
