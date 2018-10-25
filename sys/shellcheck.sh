#!/bin/sh

checkshellscript() {
	filelist="$1"
	checkfun="$2"

	printf '%s\n' "$filelist" | while IFS= read -r file 
	do
		$checkfun "$file"	
	done
}

if [ -f "$1" ]; then
	SCRIPTS="$1"
else
	SCRIPTS=$(git grep '^#!/bin/sh' | cut -d: -f1)
fi

checkshellscript "$SCRIPTS" "shellcheck --format=gcc"
checkshellscript "$SCRIPTS" checkbashisms
