#!/bin/sh

IFILE="$1"
P=`readlink $0`
[ -z "$P" ] && P="$0"
cd `dirname $P`/..
CWD="$PWD"
if [ "`echo $IFILE | cut -c 1`" != / ]; then
	IFILE="$OLDPWD/$IFILE"
fi

showHelp() {
	echo "Usage: r2-docker [-u] [file] [...]"
	echo " -u    update/build the radare2 docker image"
	echo " -l    list radare2 docker images"
	echo " -s    enter the shell"
	exit 1
}

case "$1" in
-u)
	docker build -t radare2 .
	;;
-l)
	docker images | grep radare2
	;;
shell|sh|-s)
	docker run -ti radare2 || echo "run r2-docker -u to update the docker image"
	;;
-h|'')
	showHelp
	;;
/*|*)
	if [ -f "$1" ]; then
		F=`basename $1`
		D=`dirname $1`
		# bypass home restriction
		rm -rf dockervol
		mkdir -p dockervol
		cp -f "$1" "dockervol/$F"
		docker run -v $PWD/dockervol:/mnt -p 9090:9090 -ti radare2 r2 /mnt/$F
		rm -rf dockervol
	else
		docker run -v $PWD/dockervol:/mnt -p 9090:9090 -ti radare2 r2 $1
	fi
	;;
esac

