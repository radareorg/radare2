#!/bin/sh
cd `dirname $PWD/$0`/..
if [ -d radare2-bindings ]; then
	cd radare2-bindings
	git pull
else
	URL=`doc/repo BINDINGS`
	if [ -z "$URL" ]; then
		echo "No BINDINGS URL in doc/repo"
		exit 1
	fi
	git clone $URL radare2-bindings
fi
