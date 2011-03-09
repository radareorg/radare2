#!/bin/sh
# Check bindings supported by valaswig
# pancake // radare.org - 2010-2011

SUP_LANGS=""
LANGS="python perl ruby lua go java"

if [ "$1" = "force-all" ]; then
  :> supported.langs
  PYTHONCONFIG=`./python-config-wrapper -n`
  if [ -n "${PYTHONCONFIG}" ]; then
      echo "check-langs.sh: Detected python"
      echo python >> supported.langs
  fi
  echo "#include <lua.h>" > .test.c
  ${CC} -c .test.c
  if [ -f .test.o ]; then
      echo "check-langs.sh: Detected lua"
      echo lua >> supported.langs
  fi
  rm -f .test.c
  exit 0
fi

for a in ${LANGS}; do
  printf "Checking $a support for valaswig... "
  CC=${CC} CXX=${CXX} valaswig-cc --test $a
  if [ $? = 0 ]; then
    echo yes
    SUP_LANGS="$a ${SUP_LANGS}"
  else
    echo no
  fi
done

:> supported.langs
for a in ${SUP_LANGS}; do
  echo $a >> supported.langs
done
