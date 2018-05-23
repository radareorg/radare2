# create .h from .c
# > git grep R_API open.c |cut -d : -f 2- | sed -e 's, {,;,'

# find files with \r\n
# > git grep `printf "\r\n"`

# find and replace

case "$1" in
h)
	git grep ^R_API $2 |cut -d : -f 2- | sed -e 's, {,;,'
	;;
g)
	git grep "$2"
	;;
n)
	shift
	while : ; do
		A="$1"
		perl -ne 's/\r\n/\n/g;print' < $A > $A._
		mv $A._ $A
		shift
		[ -z "$1" ] && break
	done
	;;
*)
	echo "Usage sys/ref.sh [action] [...]"
	echo " h [path]          # print R_API function signatures from C to H"
	echo " s [sed]           # perform regex on a bunch of files"
	echo " n [newlines]      # newlines replacements"
	echo " g [regex] [path]  # perform regex on a bunch of files"
	;;
esac
