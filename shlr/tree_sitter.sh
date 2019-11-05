#!/bin/sh
TS_URL="$1" # url
TS_BRA="$2" # branch name
TS_TIP="$3" # commit id

git_assert() {
	git --help > /dev/null 2>&1
	if [ $? != 0 ]; then
		echo "ERROR: Cannot find git command in PATH"
		if [ "$1" = check ]; then
			return 1
		fi
		exit 1
	fi
	return 0
}

fatal_msg() {
	echo "[tree-sitter] $1"
	exit 1
}

git_clone() {
	git_assert
	echo '[tree-sitter] Cloning tree-sitter from git...' >&2
	git clone --quiet --single-branch --branch "${TS_BRA}" "${TS_URL}" tree-sitter \
	|| fatal_msg 'Cannot clone tree-sitter from git'
	cd tree-sitter && git checkout --quiet "$TS_TIP" || fatal_msg "Cannot checkout $TS_TIP"
}

get_tree_sitter() {
	git_clone || fatal_msg 'Clone failed'
}

### MAIN ###

if [ -d tree-sitter ]; then
	echo "[tree-sitter] Nothing to do"
	exit 0
fi
git_assert
get_tree_sitter
