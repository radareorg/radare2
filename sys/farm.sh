#!/bin/sh
# Build script for radare2 - pancake<nopcode.org>

[ -z "${MAKEFLAGS}" ] && MAKEFLAGS="-j4"
[ -z "${MAKE}" ] && MAKE=make
[ -z "${NAME}" ] && NAME=radare2
[ -z "${DIR}" ] && DIR=radare2.build
[ -z "${URL}" ] && URL=http://github.com/radare/${NAME}
PYTHON=python2
WD=${PWD}/${DIR}
NOW=$(date +%Y%m%d-%H%M%S)
if [ -z "$1" ]; then
	LOGFILE=${WD}/build.log.${NOW}
else
	LOGFILE="$1"
fi

PREFIX=/usr
DESTDIR=${WD}/prefix
DONTFIND=""
CONFIGUREFLAGS="--prefix=${PREFIX}"
DOLOG="2>&1 | tee -a ${LOGFILE}" # verbose build
DOLOG="2>&1 | tee -a ${LOGFILE} > /dev/null"

testcc() {
	eval type $1 > /dev/null 2>&1
	if [ $? = 0 ]; then
		log "[==] Found $1"
		cc=$1
	else
		log "[==] Cannot find $1"
	fi
}

log() {
	echo $@ ; echo $@ >> ${LOGFILE}
}

logchk() {
	if [ $1 = 0 ]; then
		log "[==] RESULT: ok"
	else
		log "[==] RESULT: Shit happens"
	fi
}

logcmd() {
	eval "( $@ ; logchk $? ) ${DOLOG}"
}

r2uninstall() {
	cd radare2
	make uninstall DESTDIR=${DESTDIR}
}

installdeps() {
	VALA=vala-0.18.0

	echo "I am going to install ${VALA} and valabind..."
	sleep 2

	wget -c http://download.gnome.org/sources/vala/0.9/${VALA}.tar.bz2
	tar xjvf ${VALA}.tar.bz2
	cd ${VALA}
	./configure --prefix=/usr
	make
	make install
	cd ..
	echo ${VALA} > ${WD}/version.vala

	type swig > /dev/null 2>&1
	if [ $? = 1 ]; then
		# TODO: install swig from svn!
		echo "Cannot find 'swig'. apt-get install swig or get it from svn"
		echo "svn co https://swig.svn.sourceforge.net/svnroot/swig/trunk swig"
	else
		if [ -d valabind ]; then
			cd valabind
			git reset --hard
			git clean -xdf
			git pull
		else
			git clone http://github.com/radare/valabind
			cd valabind
		fi
		chmod +x configure
		./configure --prefix=/usr
		${MAKE} ${MAKEFLAGS}	
		${MAKE} install DESTDIR=${DESTDIR}
		cd ..
	fi
}

uninstalldeps() {
	VALA=`cat ${WD}/version.vala`
	cd ${VALA}
	${MAKE} uninstall DESTDIR=${DESTDIR}
	cd ..
	rm -rf ${VALA} ${VALA}.tar.bz2
	cd valabind
	${MAKE} uninstall DESTDIR=${DESTDIR}
}

mkdir -p ${DIR}
cd ${DIR}

# TODO: clean spaguettis
case "$1" in
"-i")
	if [ -z "$2" ]; then
		echo "Usage: build.sh -i [path]"
		exit 1
	fi
	DONTFIND=1
	DESTDIR="$2"
	;;
"-I")
	if [ -z "$2" ]; then
		echo "Usage: build.sh -I [path]"
		exit 1
	fi
	DESTDIR="$2"
	r2uninstall
	exit 0
	;;
"-d")
	if [ -z "$2" ]; then
		echo "Usage: build.sh -d [path]"
		exit 1
	fi
	DESTDIR="$2"
	installdeps
	exit 0
	;;
"-D")
	if [ -z "$2" ]; then
		echo "Usage: build.sh -D [path]"
		exit 1
	fi
	DESTDIR="$2"
	uninstalldeps
	exit 0
	;;
"-c")
	rm -f ${WD}/build.*
	rm -rf ${WD}/prefix
	rm -rf ${WD}/vala*
	;;
"-h")
	cat<<EOF
Usage: build.sh [logfile|-option]
  -i [destdir]    install r2
  -I [destdir]    uninstall r2
  -c              clean build directory
  -d [destdir]    compile and install dependencies
  -D [destdir]    uninstall dependencies
  -h              show this help
Dependencies:
  vala        http://live.gnome.org/Vala
  swig        http://www.swig.org/
  valabind    http://github.com/radare/valabind
Examples:
  sys/farm.sh              do the build and generate log
  sudo sys/farm.sh -i /    install system-wide (/+/usr)
  sudo sys/farm.sh -I      uninstall
  sudo sys/farm.sh -d /    install dependencies system-wide
  sys/farm.sh -d ~/prefix  install dependencies in home
  sudo sys/farm.sh -c      clean build directory
  rm -rf radare2.build     remove build directory
EOF
	exit 0
	;;
esac

log "[==] Logging ${LOGFILE}"
:> ${LOGFILE}
ln -fs ${LOGFILE} ${WD}/build.log
log "[==] Retrieving system information"
date >> ${LOGFILE}
uname -a >> ${LOGFILE}
cat /proc/cpuinfo >> ${LOGFILE}

type git > /dev/null 2>&1
if [ ! $? = 0 ]; then
	cat <<EOF
Cannot find 'git'.
EOF
	exit 1
fi

log "[==] Working directory: $WD/$DIR"

if [ -d "${NAME}" ]; then
	log "[==] Cleaning up old build directory..."
	cd ${NAME}
	git clean -xdf
	git reset --hard

	log "[==] Updating repository to HEAD..."
	logcmd hg revert -a
	logcmd hg pull -u
else
	log "[==] Checking out from ${URL}..."
	git clone ${URL} 2>&1 | tee -a ${LOGFILE}
	cd ${NAME}
fi

if [ -e "config-user.mk" ]; then
	log "[==] Running clean and mrproper..."
	${MAKE} clean > /dev/null 2>&1
	${MAKE} mrproper > /dev/null 2>&1
fi

log "[==] Running configure..."
logcmd time ./configure ${CONFIGUREFLAGS}

log "[==] Running make ${MAKEFLAGS}"
logcmd time ${MAKE} ${MAKEFLAGS}

log "[==] Symbolic installation... "
${MAKE} symstall DESTDIR="${DESTDIR}" > /dev/null 2>&1

if [ -z "${DONTFIND}" ]; then
	log "[==] List of symbollically installed files"
	logcmd "(cd ${DESTDIR} && find *)"
fi

log "[==] Running some tests..."
export PATH=${DESTDIR}/${PREFIX}/bin:$PATH
export PKG_CONFIG_PATH=${DESTDIR}/${PREFIX}/lib/pkgconfig
export LD_LIBRARY_PATH=${DESTDIR}/${PREFIX}/lib
logcmd type r2
logcmd type rasm2
logcmd type rabin2
logcmd radare2 -V

if [ -z "${DONTFIND}" ]; then
	log "[==] List of installed files"
	logcmd "(cd ${DESTDIR} && find *)"

	log "[==] Uninstalling.."
	logcmd time ${MAKE} uninstall DESTDIR="${DESTDIR}"

	log "[==] List of residual files"
	logcmd "(cd ${DESTDIR} && find *)"
fi

log "[==] Installing in ${PREFIX}"
logcmd time ${MAKE} install DESTDIR="${DESTDIR}"

log "[==] Configuring valabind bindings..."
cd swig
logcmd time ./configure --prefix=${PREFIX}

log "[==] Compiling swig/..."
logcmd time ${MAKE} ${MAKEFLAGS}

log "[==] Installing valabind bindings..."
logcmd time ${MAKE} install DESTDIR=${DESTDIR}

log "[==] Testing bindings.."
export PYTHONPATH=${DESTDIR}/${PREFIX}/lib/python2.5/site-packages/
logcmd ${PYTHON} -c "'from r2.r_util import *;b=RBuffer()'"
logcmd ${PYTHON} -c "'from r2.r_asm import *;a=RAsm()'"
logcmd ${PYTHON} -c "'from r2.r_core import *;c=RCore()'"
# TODO. add more tests here

# back to root dir
cd ..

log "[==] Looking for mingw32 crosscompilers.."
cc=""
for a in i486-mingw32-gcc i586-mingw32msvc-gcc ; do
	testcc $a
	[ -n "$cc" ] && break
done

if [ -n "$cc" ]; then
	log "[==] mingw32 build using $cc"
	if [ -e "config-user.mk" ]; then
		${MAKE} clean > /dev/null 2>&1
		${MAKE} mrproper >/dev/null 2>&1
	fi
	rm -f *.zip
	log "[==] mingw32 configure"
	logcmd ./configure --without-gmp --with-ostype=windows --with-compiler=$cc --host=i586-unknown-windows
	log "[==] mingw32 make"
	logcmd ${MAKE} ${MAKEFLAGS}
	log "[==] mingw32 w32dist"
	logcmd ${MAKE} w32dist
	cp radare2-w32*.zip ${WD}

	# build bindings
	cd swig
	log "[==] mingw32 swig: configure"
	logcmd ./configure --without-gmp --with-ostype=windows --with-compiler=$cc --host=i586-unknown-windows
	log "[==] mingw32 swig: make"
	logcmd ${MAKE} ${MAKEFLAGS} w32
	log "[==] mingw32 swig: w32dist"
	logcmd ${MAKE} w32dist
	cd ..
	
else
	log "[==] Cannot find any compatible w32 crosscompiler. Report if not true"
fi

echo "[==] Please report ${LOGFILE}"
