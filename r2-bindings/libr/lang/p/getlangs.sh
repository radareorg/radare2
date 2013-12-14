#!/bin/sh
e=$1
#LANGS="python perl tcc lua ruby vala"
l="../../../supported.langs"

[ ! -f $l ] && exit 0
LANGS=$(cat $l | grep -e perl -e ruby -e python -e lua)

# check tcc
echo "main(){}" > a.c
gcc a.c -ltcc >/dev/null 2>&1
if [ $? = 0 ]; then
LANGS="tcc ${LANGS}"
fi
rm -f a.c

for a in ${LANGS} ; do
	printf "lang_$a.$e "
done
