#!/bin/sh
# android shell

ROOT=`dirname $PWD/$0`

# TODO: autodetect or gtfo
SDK=${HOME}/Downloads/android-sdk-mac_x86
NDK=${HOME}/Downloads/android-ndk-r6b

if [ ! -d "${SDK}" ]; then 
	echo "Cannot find Android SDK ${SDK}"
	exit 1
fi
if [ ! -d "${NDK}" ]; then
	echo "Cannot find Android NDK ${NDK}"
	exit 1
fi

NDKPATH=${NDK}/toolchains/arm-linux-androideabi-4.4.3/prebuilt/darwin-x86/bin/
INCDIR=${NDK}/platforms/android-8/arch-arm/usr/include/
CFLAGS=-I${INCDIR}

PATH=$SDK/tools:$SDK/platform-tools:$NDK:${NDKPATH}:$PATH
export PATH
export CFLAGS
cp ${ROOT}/ndk-gcc ${NDK}
chmod +x ${NDK}/ndk-gcc
CC=ndk-gcc
export CC
export PS1
sh
#echo $SHELL
#$SHELL
