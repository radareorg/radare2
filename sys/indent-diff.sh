#!/bin/sh

show_help() {
    echo "Usage: ${0} [-h] [-i] [-c] [-d <git-like-diff>]"
    echo " -i                             indent in place (modify files)"
    echo " -c, --cached                   check cached diff"
    echo " -d, --diff <git-like-diff>     check specified diff"
    echo " -h                             print this help message"
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
cached=

while :; do
    case $1 in
	-i)
	    inplace=1
	    ;;
	-c|--cached)
	    cached=--cached
	    ;;
	-d|--diff)
	    diff=$2
	    shift
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
	    break
	    ;;
    esac

    shift
done

if [ -z "${diff}" ] & [ -z "${cached}" ] ; then
    show_help
    exit 1
fi

tmpfile=$(mktemp)
tmpfile_src=$(mktemp)

git diff -U0 --no-color ${cached} ${diff} | ${script_dir}/clang-format-diff.py -p1 > ${tmpfile}

if [ "${inplace}" == "1" ] ; then
    git apply -p0 < ${tmpfile}
else
    cat ${tmpfile}
fi

rm ${tmpfile}
