#!/bin/sh

IFILE="$1"

if [ -z "${IFILE}" ]; then
	echo "Usage: indent.sh [-i|-u] [file]"
	echo " -i - indent in place (modify file"
	echo " -u - indent in place (modify file"
	exit 1
fi

CWD="$PWD"
INPLACE=0
UNIFIED=0

if [ "${IFILE}" = "-i" ]; then
	shift
	INPLACE=1
	IFILE="$1"
fi

if [ "${IFILE}" = "-u" ]; then
	shift
	UNIFIED=1
	IFILE="$1"
fi

while : ; do
	[ "$PWD" = / ] && break
	if [ -f doc/clang-format ]; then
		cp -f doc/clang-format ${CWD}/.clang-format
		(
		cd "$CWD"
		clang-format "${IFILE}"  > .tmp-format
		# fix ternary conditional indent
		cat .tmp-format | sed -e 's, \? ,? ,g' > .tmp-format2
		# do not space before parenthesis on function signatures
		awk '{if (/^static/ || /^R_API/) { gsub(/ \(/,"("); }; print;}' \
			< .tmp-format2 > .tmp-format
		if [ "$UNIFIED" = 1 ]; then
			diff -ru "${IFILE}" .tmp-format
			rm .tmp-format
		elif [ "$INPLACE" = 1 ]; then
			mv .tmp-format $a
		else
			cat .tmp-format
			rm .tmp-format
		fi
		)
		rm -f ${CWD}/.clang-format
	fi
	cd ..
done
