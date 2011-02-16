#!/bin/sh
# Check bindings supported by valaswig
# pancake // radare.org - 2010-2011

SUP_LANGS=""
LANGS="python perl ruby lua go java"

if [ "$1" = "force-all" ]; then
  echo ${LANGS} >> supported.langs
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
