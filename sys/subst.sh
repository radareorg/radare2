#!/bin/sh
a="$1"
b="$2"
if [ -z "$a" ]; then
	echo "Usage: sys/subst.sh [old] [new]"
	exit 1
fi
#[ -z "$a" ] && a="r_str_chop "
#[ -z "$b" ] && b="r_str_trim "
git grep "$a" libr binr | less -R
if [ -n "$b" ]; then
	FILES=`git grep "$a" libr binr | cut -d : -f 1 | uniq `
	for f in $FILES ; do
		echo "Sedded $a"
		sed -e "s/$a/$b/g" < $f > $f.sub
		mv $f.sub $f
	done
else
	echo "Oops"
fi
