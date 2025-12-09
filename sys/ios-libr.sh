#!/bin/sh
sys/sdk-ios.sh -simulator
sys/sdk-ios.sh -a arm64
lipo -create -output "ios-libr2.dylib \
	"$INSTALL_DST/$PREFIX"/lib/libr.dylib \
	"$INSTALL_DST/$PREFIX"/lib_simulator/libr.dylib
