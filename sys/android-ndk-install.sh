#!/bin/sh
V=r21d
# V=r9 # kitkat
O=""
case `uname` in
Linux)
	O=linux
	;;
Darwin)
	O=darwin
	;;
*)
	echo "Unsupported platform"
	exit 1
	;;
esac

API=28
[ -n "$1" ] && API="$1"

ARCH=arm64
[ -n "$2" ] && ARCH="$2"

echo Downloading NDK $V...
wget -c -q https://dl.google.com/android/repository/android-ndk-$V-$O-x86_64.zip
echo Unzipping in /tmp/ndkzip
unzip -q *.zip -d /tmp/ndkzip
export NDK=$(ls -d /tmp/ndkzip/* | head -n1)
echo NDK=${NDK}
echo NDK=${NDK} > $HOME/.r2androidrc
python $NDK/build/tools/make_standalone_toolchain.py \
        --arch ${ARCH} --api ${API} --install-dir toolchain
