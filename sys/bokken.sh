#!/bin/sh
# find root
cd `dirname $PWD/$0`

if [ ! -d _work ]; then
	mkdir _work
fi
cd _work || exit 1
if [ -d bokken ]; then
	cd bokken
	hg pull -u
else
	hg clone http://inguma.eu/repos/bokken
	cd bokken
fi
