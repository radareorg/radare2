#!/bin/sh
SUP_LANGS=""
LANGS="python perl ruby lua go java"
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
