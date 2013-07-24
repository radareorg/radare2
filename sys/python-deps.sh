#!/bin/sh

# find root
cd `dirname $(pwd)/$0`

. ./CONFIG

./swig.sh
./vala.sh
./valabind.sh

#apt-get install ${PYTHON_VERSION}
:> .mark_python-deps
