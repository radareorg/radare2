#!/bin/sh
ACR_WRAP=acr-wrap

for i in *.wrap ; do
	o=`echo $i | sed -e 's,.wrap,.mk,'`
	if [ -n "`echo $o | grep zydis`" ]; then
		echo "[ACR] Skipping $i"
		continue
	fi
	echo "[ACR] Wrapping $i"
	${ACR_WRAP} $i > $o
done
