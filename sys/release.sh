#!/bin/sh
V=$1
if [ -z "$V" ]; then
	echo "Usage: sys/release.sh 3.2.0"
	exit 1
fi
git tag | grep -q $V
if [ $? = 0 ]; then
	echo "Already tagged. Use git tag -d $V"
	exit 1
fi
sed -e 's,^VERSION.*,VERSION '$V',' < configure.acr > configure.acr.tmp
mv configure.acr.tmp configure.acr
sh autogen.sh
git commit -a -m "Release $V" || exit 1
git tag $V
