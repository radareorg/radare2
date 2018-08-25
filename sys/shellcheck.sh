#!/bin/sh


checkshellscript() {
	filelist="$1"
	checkfun="$2"

	while read -r file 
	do
		$checkfun "$file"	
	done < "$filelist"
		
}

FMT=gcc
#if [ -n "${SHELLCHECK_XML}" ]; then
#	FMT=checkstyle
#fi

SHCHK="shellcheck --format=${FMT}"

if ! [ -f "./sys/scripts.list" ] ;then
	echo "Find all shellscripts, caching in sys/scripts.list"
	find . \! -path '/.git' -print0  | xargs -0 file | grep "POSIX shell script" | cut -d: -f1  > sys/scripts.list
fi

checkshellscript "./sys/scripts.list" "$SHCHK"
#checkshellscript "./sys/scripts.list" "checkbashisms"
