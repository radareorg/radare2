#!/bin/sh
# Check bindings supported by valabind
# pancake // radare.org - 2010-2011

SUP_LANGS=""
LANGS="python perl ruby lua go java guile php5"
[ -z "${CC}" ] && CC=gcc
[ -z "${CXX}" ] && CXX=g++

if [ "$1" = "force-all" ]; then
  :> supported.langs
  PYTHONCONFIG=`./python-config-wrapper -n`
  if [ -n "${PYTHONCONFIG}" ]; then
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
  # GIR AND GEAR ARE EXPERIMENTAL #
  #echo " - gir: yes"
  #echo " - v8gear: yes"
  #SUP_LANGS="gir gear ${SUP_LANGS}"
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
  echo " - v8gear: no"
fi

for a in lua python php5 ; do
	[ -f $a/r_core_wrap.cxx ] && SUP_LANGS="$a ${SUP_LANGS}"
done

for a in valac g++ ; do
  $a --help > /dev/null 2>&1
  if [ $? = 0 ]; then
    echo " - $a: yes"
    SUP_LANGS="$a ${SUP_LANGS}"
  else
    echo " - $a: no"
  fi
done


:> supported.langs
for a in ${SUP_LANGS}; do
  echo $a >> supported.langs
done
