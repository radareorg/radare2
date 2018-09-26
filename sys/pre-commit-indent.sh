#!/bin/sh
#
# A hook script to verify what is about to be committed follows the coding
# style. Called by "git commit" with no arguments. The hook should exit with
# non-zero status after issuing an appropriate message if it wants to stop the
# commit.
#
# To enable this hook, move it to ".git/hooks/pre-commit".

restore_exit() {
    git apply < "${UNSTAGED_DIFF}" 2>/dev/null
    rm -f "${TMPFILE}"
    rm -f "${UNSTAGED_DIFF}"
    if [ "$#" -ne 1 ] ; then
	exit 1
    else
	exit $1
    fi
}

trap restore_exit 1 2 6

TMPFILE="$(mktemp)"
if [ -z "$TMPFILE" ] ; then
    echo "mktemp returned an empty string for \"TMPFILE\"."
    exit 1
fi

UNSTAGED_DIFF="$(mktemp)"
if [ -z "$UNSTAGED_DIFF" ] ; then
    echo "mktemp returned an empty string for \"UNSTAGED_DIFF\"."
    exit 1
fi

git diff > ${UNSTAGED_DIFF} || exit 1
git checkout -- . || exit 1
git diff --cached | ./sys/clang-format-diff.py -p1 > "${TMPFILE}"

if [ -s "${TMPFILE}" ] ; then
	echo "Please follow the coding style!"
	echo "Run \`git diff --cached | ./sys/clang-format-diff.py -p1 -i\` to apply the changes listed below and remember to add them to git."
	echo
	cat "${TMPFILE}"
	echo
	echo "If you think the current style is ok, just run \`git commit --no-verify\` to bypass this check."
	restore_exit 1
fi

restore_exit 0
