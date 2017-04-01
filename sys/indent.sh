#!/bin/sh

# known bugs
# ----------
# - labels are indented
# - #if 0 code is indented
# - //comment should be // comment

IFILE="$1"
P=`readlink $0`
[ -z "$P" ] && P="$0"
cd `dirname $P`/..

if [ -z "${IFILE}" ]; then
	echo "Usage: r2-indent [-i|-u] [file] [...]"
	echo " -a    indent all whitelisted files"
	echo " -i    indent in place (modify file)"
	echo " -u    unified diff of the file"
	exit 1
fi

if [ "${IFILE}" = - ]; then
	cat > /tmp/input
	IFILE=/tmp/input
fi

CWD="$PWD"
INPLACE=0
ALLWHITE=0
UNIFIED=0
ROOTDIR=/

UNCRUST=1

if [ "${IFILE}" = "-a" ]; then
	shift
	ALLWHITE=1
	IFILE="$1"
	$CWD/sys/indent-whitelist.sh $@
	exit 0
fi

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

if [ "`echo $IFILE | cut -c 1`" != / ]; then
	IFILE="$OLDPWD/$IFILE"
fi

if [ "${UNCRUST}" = 1 ]; then
	# yell, rather than overwrite an innocent file
	command -v uncrustify >/dev/null 2>&1 || {
		if ! r2pm -r type uncrustify >/dev/null; then
			echo "This script requires uncrustify to function. Check r2pm -i uncrustify"
			exit 1
		fi
	}
else
	# yell, rather than overwrite an innocent file
	if ! type clang-format >/dev/null; then
		echo "This script requires clang-format to function"
		exit 1
	fi
fi

indentFile() {
	if [ ! -f "${IFILE}" ]; then
		echo "Cannot find $IFILE"
		return
	fi
	echo "Indenting ${IFILE} ..." >&2
	(
	if [ "${UNCRUST}" = 1 ]; then
		cp -f doc/clang-format ${CWD}/.clang-format
		cd "$CWD"
		r2pm -r uncrustify -c ${CWD}/doc/uncrustify.cfg -f "${IFILE}" -o .tmp-format || exit 1
	else
		cp -f doc/clang-format ${CWD}/.clang-format
		cd "$CWD"
		clang-format "${IFILE}"  > .tmp-format
	fi
# one of those rules fuckups the ascii art in comment blocks

	# fix ternary conditional indent
#	perl -ne 's/ \? /? /g;print' < .tmp-format > .tmp-format2
#	cat .tmp-format2 | perl -ne 's/\r//g;print' | sed -e 's, : ,: ,g' > .tmp-format
	mv .tmp-format .tmp-format2
	# do not space before parenthesis on function signatures
	awk '{if (/^static/ || /^R_API/) { gsub(/ \(/,"("); }; print;}' \
		< .tmp-format2 > .tmp-format
	# allow oneliner else statements
	mv .tmp-format .tmp-format2
	perl -ne 's/\telse\n[ \t]*/\telse /g;print' < .tmp-format2 | \
		awk '{if (/\telse \t+/) {gsub(/\telse \t+/, "\telse ");} print;}' > .tmp-format
	mv .tmp-format .tmp-format2
	perl -ne 's/} else\n[ \t]*/} else /g;print' < .tmp-format2 | \
		awk '{if (/} else \t+/) {gsub(/} else \t+/, "} else ");} print;}' > .tmp-format
	# do not place spaces after tabs
	#mv .tmp-format .tmp-format2
	#perl -ne 's,\t[ ]+,\t,g;print' < .tmp-format2 > .tmp-format
	# drop spaces an multiline backslashes
	mv .tmp-format .tmp-format2
	perl -ne 's/[ ]+\\$/\\/g;print' < .tmp-format2 > .tmp-format
	# spaces in { brackets
	#mv .tmp-format .tmp-format2
	#perl -ne 's/{\s/{ /g;print' < .tmp-format2 > .tmp-format
	#perl -ne 's/{([^ \n])/{ \1/g if(!/"/);print' < .tmp-format2 > .tmp-format
	# spaces in } brackets
	#mv .tmp-format .tmp-format2
	#perl -ne 's/([^ \t])}/$1 }/g if(!/"/);print' < .tmp-format2 > .tmp-format
	# _( macro
	mv .tmp-format .tmp-format2
	perl -ne 's/_\s\(/_(/g;print' < .tmp-format2 > .tmp-format
	# 0xa0
	mv .tmp-format .tmp-format2
	perl -ne 's/[\xa0\xc2]//g;print' < .tmp-format2 > .tmp-format
	# remove spaces after #if 
	#mv .tmp-format .tmp-format2
	#perl -ne 's/#if\ */#if /g;print' < .tmp-format2 > .tmp-format
	# add spce after every //

	if [ "$UNIFIED" = 1 ]; then
		diff -ru "${IFILE}" .tmp-format
		rm .tmp-format
	elif [ "$INPLACE" = 1 ]; then
		if [ -s .tmp-format ]; then
			mv .tmp-format "${IFILE}"
		else
			rm -f .tmp-format
			rm -f .tmp-format2
			rm -f ${CWD}/.clang-format
			echo "Syntax error. Not re-indented"
			exit 1
		fi
	else
		cat .tmp-format
		rm .tmp-format
	fi
	rm -f .tmp-format2
	)
	rm -f ${CWD}/.clang-format
}

while : ; do
	[ "$PWD" = / ] && break
		if [ -f doc/clang-format ]; then
			ROOTDIR=$PWD
			while : ; do
				[ -z "${IFILE}" ] && break
				indentFile
				shift
				IFILE="$1"
			done
		fi
		cd ..
done
