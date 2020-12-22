#!/bin/sh
REPONAME="$1" # repository name
URL="$2" # url
BRA="$3" # branch name
TIP="$4" # commit id

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
    echo "[${REPONAME}] $1"
    exit 1
}

git_clone() {
    git_assert
    echo "[${REPONAME}] Cloning ${REPONAME} from git..." >&2
    git clone --quiet --single-branch --branch "${BRA}" "${URL}" "${REPONAME}" \
	|| fatal_msg "Cannot clone $REPONAME from git"
    cd "${REPONAME}" && git checkout --quiet "$TIP" || fatal_msg "Cannot checkout $TIP"
}

get_repo() {
    git_clone || fatal_msg 'Clone failed'
}

### MAIN ###

if [ -d "$REPONAME" ]; then
    echo "[${REPONAME}] Nothing to do"
    exit 0
fi
git_assert
get_repo
