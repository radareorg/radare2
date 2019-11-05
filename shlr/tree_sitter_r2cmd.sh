#!/bin/sh
TSCMD_URL="$1" # url
TSCMD_BRA="$2" # branch name
TSCMD_TIP="$3" # commit id

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
    echo "[tree-sitter-r2cmd] $1"
    exit 1
}

git_clone() {
    git_assert
    echo '[tree-sitter-r2cmd] Cloning tree-sitter-r2cmd from git...' >&2
    git clone --quiet --single-branch --branch "${TSCMD_BRA}" "${TSCMD_URL}" tree-sitter-r2cmd \
	|| fatal_msg 'Cannot clone tree-sitter-r2cmd from git'
    cd tree-sitter-r2cmd && git checkout --quiet "$TSCMD_TIP" || fatal_msg "Cannot checkout $TSCMD_TIP"
}

get_tree_sitter_r2cmd() {
    git_clone || fatal_msg 'Clone failed'
}

### MAIN ###

if [ -d tree-sitter-r2cmd ]; then
    echo "[tree-sitter-r2cmd] Nothing to do"
    exit 0
fi
git_assert
get_tree_sitter_r2cmd
