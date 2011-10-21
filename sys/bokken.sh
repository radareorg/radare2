#!/bin/sh
# find root
cd `dirname $PWD/$0`

mkdir -p _work
cd _work
if [ -d bokken ]; then
	cd bokken
	hg pull -u
else
	hg clone http://inguma.eu/repos/bokken
	cd bokken
fi
