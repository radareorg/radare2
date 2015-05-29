#!/bin/sh
# Import DEX/Dalvik information from `dexdump`
# Usage:
# r2 -c '.!doc/dexdump.sh $FILE' classes.dex

if [ -z "${DEXDUMP}" ]; then
	DEXDUMP="${HOME}/Downloads/android-sdk/sdk/build-tools/android-4.4.2/dexdump";
	if [ ! -x "${DEXDUMP}" ]; then
		DEXDUMP="dexdump"
	fi
fi
if [ -z "$1" ] ;then
	echo "Usage: dexdump.sh [dexfile] > dex.r2"
	exit 1
fi
echo "e asm.arch=dalvik"
echo "e asm.bits=32"
echo "fs symbols"

#${DEXDUMP} -d $1 ; exit 0

# Symbols
${DEXDUMP} -d $1 | perl -ne '
s/://g;
if (/invoke-/) {
	s/\s+/ /g;
	local @str = split (/ /);
	/\sL(.*)/;
	local $msg = $1;
	$msg=~tr/,()[]{}|\/\;$<> @#-+*/_____________________/;
	#$msg=~s//;
	print "fs callrefs\nCC call.L".$msg." @ 0x".$str[0]."\n";
} elsif (/\|\[/) {
	tr/()[]\/\;$<>/_________/;
	/^(.*) (.*) (.*)$/;
	print "fs symbols\nf sym.$3 = 0x$1\n";
} elsif (/const-string/) {
	s/\s+/ /g;
	local @str = split (/ /);
	/"(.*)"/;
	local $msg = $1;
	$msg=~tr/,()[]{}|\/\;$<> @#-+*/_____________________/;
	#$msg=~s//;
	print "fs strings\nCC str.".$msg." @ 0x".$str[0]."\n";
}
'
echo "fs *"
