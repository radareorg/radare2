#!/bin/sh

# this script creates the radare2/t/overlay directory
# containing all the changes that will be applied into r2r

if [ ! -d ../t ]; then
	echo "Must be run from radare2/radare2-regressions"
	exit 1
fi

O=../t/overlay
B=`cd $O 2>/dev/null && git rev-parse --abbrev-ref HEAD`

create() {
	if [ "$B" = master ];then
		echo "You are now in master, not gonna overwrite your overlay"
		exit 0
	fi
	echo "Creating overlay for branch $B"

	if [ -d "$O" ]; then
	(
		cd ../t
		git rm -rf "overlay/$B"
	)
	fi
	rm -rf $O
	mkdir -p $O
	MF=$(git status -s| grep '^ M' |cut -d ' ' -f 3-)
	NF=$(git status -s| grep '^A ' |cut -d ' ' -f 3-)
	if [ -z "${MF}${NF}" ]; then
		echo "Do some changes in r2r to make git status happy."
		exit 1
	fi

	for a in $MF ; do
		d=`dirname $a`
		mkdir -p "$O/$B/$d"
		git diff $a > "$O/$B/$a.patch"
	done

	for a in $NF ; do
		d=`dirname $a`
		mkdir -p "$O/$B/$d"
		cp $a "$O/$B/$a"
	done
	(
		cd ../t
		git add overlay/$B
	)
	echo "Created ../t/overlay/$B"
}

apply() {
	if [ "$B" != master ]; then
		echo "You are not in master, overlay will not be applied"
		exit 0
	fi
	if [ ! -d "$O" ]; then
		echo "Cannot find $O"
		exit 1
	fi
	# git reset --hard
	OL=$(cd "$O" 2> /dev/null && ls)
	if [ -z "$OL" ]; then
		echo "Cannot find any overlay to apply"
		exit 0
	fi
	for o in $OL ; do
	(
		F=`cd "$O/$o" 2> /dev/null && find . -type f`
		for a in $F ; do
			if [ -n "`echo $a | grep .patch`" ]; then
				echo "Patch $a"
				patch -p1 < "$O/$o/$a"
			else
				echo "Add $a"
				d=`dirname "$a"`
				mkdir -p "$d"
				cp -f "$O/$o/$a" "$a"
				git add "$a"
			fi
		done
	)
	done
	echo "Applied radare2/t/overlay into r2r. You may want to commit that in r2r."
}

case "$1" in
''|-h)
	echo "Usage: ./overlay.sh [auto|apply|create]"
	echo " auto   - if r2.branch == master { apply }{ create }"
	echo " create - creates ../t/overlay with changes in this r2r"
	echo " apply  - apply ../t/overlay into here."
	;;
apply)
	apply
	;;
create)
	create
	;;
auto)
	if [ "$B" = master ]; then
		apply
	else
		create
	fi
	;;
*)
	eval $1
	;;
esac
