#!/bin/sh
LNG=$1

if [ ! -d "test/${LNG}" ]; then
  echo "Cannot find ${LNG} test suite"
  exit 1
fi

case ${LNG} in
"python")
  LD_LIBRARY_PATH=$PWD/python
  PYTHONPATH=$PWD/python
  export LD_LIBRARY_PATH PYTHONPATH
  ;;
"perl")
  # TODO
  ;;
esac

cd test/${LNG}

shift
if [ -n "$@" ]; then
  while [ -n "$1" ]; do
    echo $a
    ${LNG} $1
    shift
  done
else
  for a in * ; do
    echo $a
    ${LNG} $a
  done
fi
