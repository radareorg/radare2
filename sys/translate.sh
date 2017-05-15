#!/bin/sh
if [ -z "$1" ]; then
	echo "Usage: sys/translate.sh [--list,--reset] [lang|path]"
	echo "Languages:"
	echo "- english"
	cd sys/lang && ls | xargs echo -
	exit 1
fi

if [ "$1" = "-l" -o "$1" = "--list" ]; then
	echo english
	cd sys/lang && ls | cat
	exit 0
fi

if [ "$1" = english ]; then
	RESET=1
	N=catalan
else
	if [ "$1" = "--reset" ]; then
		RESET=1
		shift
	else
		RESET=0
	fi
	N="$1"
fi

if [ -d "$N" ]; then
	:
else
	if [ -d "sys/lang/$N" ]; then
		L="sys/lang/$N"
	else
		if [ -d "$N" ]; then
			L="$N"
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
