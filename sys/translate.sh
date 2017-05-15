#!/bin/sh
if [ -z "$1" ]; then
	echo "Usage: sys/translate.sh [--reset] [lang|path]"
	cd sys/lang && ls
	exit 1
fi

if [ "$1" = "--reset" ]; then
	RESET=1
	shift
else
	RESET=0
fi

if [ -d "$1" ]; then
	:
else
	if [ -d "sys/lang/$1" ]; then
		L="sys/lang/$1"
	else
		if [ -d "$1" ]; then
			L="$1"
		else
			echo "Invalid language"
			exit 1
		fi
	fi
fi

echo
echo "WARNING: Translations are experimental and can only be changed at compile time"
echo "WARNING: Everyone is welcome to submit their translation efforts. I have no plans"
echo "WARNING: to support runtime language selection, because of the unnecessary overhead"
echo

for a in `cd "$L" && echo *` ; do
	F=`echo $a | sed -e s,_,/,g`
	echo "Processing $F"
	git checkout "$F"
	if [ "${RESET}" = 0 ]; then
		sed -f "$L/$a" < "$F" > .tmp
		if [ $? = 0 ]; then
			mv .tmp $F
		else
			echo "Failed"
		fi
	fi
done
