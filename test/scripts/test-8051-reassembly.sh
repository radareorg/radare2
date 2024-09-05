#!/bin/sh
BUILD_DIRECTORY=$(mktemp -d tmp.XXXXXXXXXX)
[ -z "$BUILD_DIRECTORY" ] && exit 1
export EXIT_CODE=0

printf "Reassembling 8051... "
radare2 -a 8051 -m 0x8000 -e "scr.color=0" -qf -c "pI" ./bins/8051/MP_8192E_FW_NIC.bin > $BUILD_DIRECTORY/MP_8192E_FW_NIC.asm || exit 1
rasm2 -a 8051 -s 0x8000 -f $BUILD_DIRECTORY/MP_8192E_FW_NIC.asm -B > $BUILD_DIRECTORY/recompiled-firmware.bin || exit 1

cmp ./bins/8051/MP_8192E_FW_NIC.bin $BUILD_DIRECTORY/recompiled-firmware.bin
if [ $? -eq 0 ]; then
	echo "OK"
	EXIT_CODE=0
else
	radiff2 -q -D ./bins/8051/MP_8192E_FW_NIC.bin "$BUILD_DIRECTORY/recompiled-firmware.bin"
	echo "failed"
	EXIT_CODE=1
fi

rm -rf $BUILD_DIRECTORY

exit $EXIT_CODE
