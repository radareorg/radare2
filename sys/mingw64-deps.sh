#!/bin/sh

# find root
cd `dirname $(pwd)/$0`

if [ `uname` = Linux ]; then
case `uname -m` in
i?86)
URL="http://downloads.sourceforge.net/project/mingw-w64/Toolchains%20targetting%20Win64/Automated%20Builds/mingw-w64-bin_i686-linux_20110831.tar.bz2?r=http%3A%2F%2Fsourceforge.net%2Fprojects%2Fmingw-w64%2Ffiles%2FToolchains%2520targetting%2520Win64%2FAutomated%2520Builds%2F&ts=1315999254&use_mirror=switch"
;;
x86_64)
URL="http://downloads.sourceforge.net/project/mingw-w64/Toolchains%20targetting%20Win64/Automated%20Builds/mingw-w64-bin_x86_64-linux_20110831.tar.bz2?r=http%3A%2F%2Fsourceforge.net%2Fprojects%2Fmingw-w64%2Ffiles%2FToolchains%2520targetting%2520Win64%2FAutomated%2520Builds%2F&ts=1315999254&use_mirror=switch"
;;
esac
else
# TODO: use darwin_i686
#URL="http://downloads.sourceforge.net/project/mingw-w64/Toolchains%20targetting%20Win64/Automated%20Builds/mingw-w64-bin_x86_64-linux_20110831.tar.bz2?r=http%3A%2F%2Fsourceforge.net%2Fprojects%2Fmingw-w64%2Ffiles%2FToolchains%2520targetting%2520Win64%2FAutomated%2520Builds%2F&ts=1315999254&use_mirror=switch"
	echo "Sorry. Not yet supported for this platform"
	exit 1
fi

mkdir -p _work
cd _work
# open http://mingw-w64.sourceforge.net/
wget -c -O mingw64.tbz2 "${URL}"
mkdir -p mingw64
tar xjvf mingw64.tbz2 -C mingw64
