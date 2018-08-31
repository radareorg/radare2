#!/bin/sh

checkshellscript() {
	filelist="$1"
	checkfun="$2"

	while read -r file 
	do
		$checkfun "$file"	
	done < "$filelist"
		
}

echo "Find all shellscripts, caching $SCRIPTS"
SCRIPTS=$(git grep '/bin/sh' | cut -d: -f1)

checkshellscript "./sys/scripts.list" "shellcheck --format=gcc"
checkshellscript "./sys/scripts.list" "checkbashisms"
