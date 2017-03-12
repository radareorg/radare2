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
	echo " -d    debug program (linux-x86-32/64)"
	echo " -l    list radare2 docker images"
	echo " -s    enter the shell"
	echo " -r    remove radare2 docker image"
	exit 1
}

ALLOW_DEBUG="--security-opt seccomp:unconfined"
#ALLOW_DEBUG="--privileged"

case "$1" in
-r)
	docker rmi radare2
	;;
-d)
	R2FLAGS=-d $0 $2
	;;
-u)
	docker build -t radare2 .
	;;
-l)
	docker images | grep radare2
	;;
shell|sh|-s)
	docker run ${ALLOW_DEBUG} -v $PWD/dockervol:/mnt -ti radare2 || echo "run r2-docker -u to update the docker image"
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
		docker run ${ALLOW_DEBUG} -v $PWD/dockervol:/mnt -p 9090:9090 -ti radare2 r2 ${R2FLAGS} /mnt/$F
		rm -rf dockervol
	else
		docker run ${ALLOW_DEBUG} -v $PWD/dockervol:/mnt -p 9090:9090 -ti radare2 r2 ${R2FLAGS} $1
	fi
	;;
esac

