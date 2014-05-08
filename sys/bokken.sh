#!/bin/sh
# find root
cd `dirname $PWD/$0`

mkdir  _work
cd _work || exit 1
if [ -d bokken ]; then
	cd bokken
	hg pull -u
else
	hg clone http://inguma.eu/repos/bokken
	cd bokken
fi
