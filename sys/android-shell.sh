#!/bin/sh
# android shell

ROOT=`dirname $PWD/$0`
OS=`uname|tr 'A-Z' 'a-z'`
[ "${OS}" = darwin ] && OS=mac

# TODO: autodetect or gtfo
if [ -f ~/.r2androidrc ]; then
	. ~/.r2androidrc
else
	SDK=${HOME}/Downloads/android-sdk-${OS}_x86
	NDK=${HOME}/Downloads/android-ndk-r6b
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

NDKPATH_ARM=`echo ${NDK}/toolchains/arm-*/prebuilt/${OS}-x86/bin/`
NDKPATH_X86=`echo ${NDK}/toolchains/x86-*/prebuilt/${OS}-x86/bin/`
#INCDIR=${NDK}/platforms/android-8/arch-arm/usr/include/
#CFLAGS=-I${INCDIR}

PATH=$SDK/tools:$SDK/platform-tools:$NDK:${NDKPATH_X86}:${NDKPATH_ARM}:$PATH
export PATH
export CFLAGS
LANG=C
export LANG
cp ${ROOT}/ndk-gcc ${NDK}
chmod +x ${NDK}/ndk-gcc
CC=ndk-gcc
export CC
export PS1
sh $@
#echo $SHELL
#$SHELL
