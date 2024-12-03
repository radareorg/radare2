#!/bin/sh
ACR_WRAP=acr-wrap

for i in *.wrap ; do
	o=`echo $i | sed -e 's,.wrap,.mk,'`
	echo "[ACR] Wrapping $i"
	${ACR_WRAP} $i > $o
done
