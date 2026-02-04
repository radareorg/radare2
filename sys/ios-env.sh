#!/bin/sh

export PATH=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin:${PATH}
export PATH="$PWD/"sys:${PATH}
export CC="$PWD/"sys/ios-sdk-clang
export CFLAGS="-Oz -DNDEBUG"
# Default building in /var/jb/user prefix. use ROOTLESS=0 to rootful packaging
if [ -z "${ROOTLESS}" ]; then
	ROOTLESS=1
fi
