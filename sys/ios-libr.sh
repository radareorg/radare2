#!/bin/sh
sys/ios-sdk.sh -simulator
sys/ios-sdk.sh -a arm64
lipo -create -output "ios-libr2.dylib \
	"$INSTALL_DST/$PREFIX"/lib/libr.dylib \
	"$INSTALL_DST/$PREFIX"/lib_simulator/libr.dylib
