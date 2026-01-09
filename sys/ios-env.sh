#!/bin/sh

export PATH=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin:${PATH}
export PATH="$PWD/"sys:${PATH}
export CC="$PWD/"sys/ios-sdk-clang
export CFLAGS="-Oz -DNDEBUG"
