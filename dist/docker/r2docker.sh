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
	echo "Usage: r2-docker [-pudlsr] [file] [...]"
	echo " -p    pull latest radare2 docker image from docker hub"
	echo " -u    build the radare2 docker image"
	echo " -d    debug program (linux-x86-32/64)"
	echo " -l    list radare2 docker images"
	echo " -s    enter the shell"
	echo " -r    remove radare2 docker image"
	exit 1
}

# Check if docker is present
[ -z "$(command -v docker)" ] && (
	echo "You must install docker first. (see https://docs.docker.com/engine/installation/)"
) && exit 1

# Add capatibility to use ptrace with radare2
ALLOW_DEBUG="--cap-add=SYS_PTRACE"

# Remove by default all capabilities
DEFAULT_CAP="--cap-drop=ALL"

case "$1" in
-p)
	docker pull radare/radare2:latest
	# Tag image to preserve old reference
	docker tag radare/radare2:latest radare2:latest
	;;
-r)
	# Delete all radare2 containers
	docker rm -f $(docker ps -a | grep radare2 | awk '{print $1}') 2> /dev/null
	# Delete tag to preserve old reference
	docker rmi radare2:latest 2> /dev/null
	docker rmi radare/radare2:latest 2> /dev/null
	;;
-d)
	R2FLAGS=-d $0 $2
	;;
-u)
	docker build -t radare/radare2:latest .
	# Tag image to preserve old reference
	docker tag radare/radare2:latest radare2:latest
	;;
-l)
	docker images | grep radare2
	;;
shell|sh|-s)
	docker run ${ALLOW_DEBUG} ${DEFAULT_CAP} -v $PWD/dockervol:/mnt -ti radare/radare2:latest || echo "run r2-docker -u to update the docker image"
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
		docker run ${ALLOW_DEBUG} ${DEFAULT_CAP} -v $PWD/dockervol:/mnt -p 9090:9090 -ti radare/radare2:latest r2 ${R2FLAGS} /mnt/$F
		rm -rf dockervol
	else
		docker run ${ALLOW_DEBUG} ${DEFAULT_CAP} -v $PWD/dockervol:/mnt -p 9090:9090 -ti radare/radare2:latest r2 ${R2FLAGS} $1
	fi
	;;
esac

