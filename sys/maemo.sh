#!/bin/sh
mad list >/dev/null 2>&1
if [ $? = 0 ]; then
	make clean
	echo './configure --prefix=/usr' | mad sh
	echo make | mad sh
	cd maemo
	make
else
	echo "Cannot find 'mad'. Please install QtSDK or QtCreator"
	exit 1
fi
