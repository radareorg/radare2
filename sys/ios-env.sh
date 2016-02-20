#!/bin/sh

export PATH=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin:$PATH
export PATH=$(pwd)/sys:${PATH}
export CC=$(pwd)/sys/ios-sdk-gcc
# set only for arm64, otherwise it is armv7
# select ios sdk version
export IOSVER=8.3
export IOSINC=$(pwd)/sys/ios-include
export CFLAGS=-O2

