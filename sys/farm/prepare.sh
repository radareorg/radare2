#!/bin/sh
# install all deps in order to setup the farm
PREPARE="
	vala
	swig
	valabind
	python-deps
	mingw32-deps
	mingw64-deps
"

cd `dirname $PWD/$0` ; cd ..
for a in ${PREPARE} ; do
	./${a}.sh
done
