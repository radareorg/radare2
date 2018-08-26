#!/bin/sh

show_help() {
    echo "Usage: ${0} [-i] [-h] <git-like-diff>"
    echo " -i    indent in place (modify files)"
    echo " -h    print this help message"
    echo
    echo "Examples:"
    echo "$ ${0} master..my-branch > my-branch.patch"
    echo "$ ${0} -i master..my-branch"
    exit 1
}

P=`readlink $0`
[ -z "$P" ] && P="$0"
script_dir=`dirname $P`

diff=
inplace=

while :; do
    case $1 in
	-i)
	    inplace=1
	    ;;
	-h)
	    show_help
	    exit 0
	    ;;
	--)
	    shift
	    ;;
	-?*)
            printf 'WARN: Unknown option: %s\n' "$1" >&2
	    show_help
	    exit 1
	    ;;
	*)
	    if [ -z "${1}" ] ; then
		show_help
		exit 1
	    fi
	    diff=$1
	    break
	    ;;
    esac

    shift
done

tmpfile=$(mktemp)
tmpfile_src=$(mktemp)

git diff -U0 --no-color ${diff} | ${script_dir}/clang-format-diff.py -p1 > ${tmpfile_src}
# function declarations/definitions do not have space before '('
awk '{if (/^[+]static/ || /^[+]R_API/) { gsub(/ \(/,"("); }; print;}' < ${tmpfile_src} > ${tmpfile}

if [ "${inplace}" == "1" ] ; then
    git apply -p0 < ${tmpfile}
else
    cat ${tmpfile}
fi

rm ${tmpfile}
