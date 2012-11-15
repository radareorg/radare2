#!/bin/sh
# Check bindings supported by valabind
# pancake // radare.org - 2010-2012

SUP_LANGS=""
LANGS="python perl ruby lua go java guile php5 node-ffi ctypes"
[ -z "${CC}" ] && CC=gcc
[ -z "${CXX}" ] && CXX=g++

R=`dirname $0`
PYTHON_CONFIG=`$R/python-config-wrapper -n`
export PYTHON_CONFIG

if [ "$1" = "force-all" ]; then
  :> supported.langs
  if [ -n "${PYTHON_CONFIG}" ]; then
      echo "check-langs.sh: Detected python"
      echo python >> supported.langs
  fi
  echo "#include <lua.h>" > .test.c
  ${CC} -I/usr/include/lua5.1 ${CFLAGS} -c .test.c
  if [ -f .test.o ]; then
      echo "check-langs.sh: Detected lua"
      echo lua >> supported.langs
  fi
  rm -f .test.c
  exit 0
fi

echo "Checking valabind languages support..."
valabind-cc --help > /dev/null 2>&1
if [ $? = 0 ]; then
  # GIR IS EXPERIMENTAL #
  #echo " - gir: yes"
  #SUP_LANGS="gir ${SUP_LANGS}"
  SUP_LANGS=""
  for a in ${LANGS}; do
    printf " - $a: "
    CC=${CC} CXX=${CXX} valabind-cc --test $a
    if [ $? = 0 ]; then
      echo yes
      SUP_LANGS="$a ${SUP_LANGS}"
    else
      echo no
    fi
  done
else
  echo "WARNING: cannot find valabind"
  echo " - gir: no"
fi

for a in lua python php5 ; do
	[ -f $a/r_core_wrap.cxx ] && SUP_LANGS="$a ${SUP_LANGS}"
done

# check g++
  ${CXX} --help >/dev/null 2>&1
  if [ $? = 0 ]; then
    echo " - cxx: yes ($CXX)"
    SUP_LANGS="cxx ${SUP_LANGS}"
  else
    echo " - cxx: no"
  fi

# check valac
  valac --help > /dev/null 2>&1
  if [ $? = 0 ]; then
    echo " - valac: yes"
    SUP_LANGS="valac ${SUP_LANGS}"
  else
    echo " - valac: no"
  fi

:> supported.langs
for a in ${SUP_LANGS}; do
  echo $a >> supported.langs
done
