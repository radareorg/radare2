#!/bin/sh

export PATH=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin:${PATH}
export PATH=$(pwd)/sys:${PATH}
export CC=$(pwd)/sys/ios-sdk-clang
export CFLAGS=-Oz
