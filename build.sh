#!/bin/sh
# Build script for radare2 - pancake<nopcode.org>

[ -z "${NAME}" ] && NAME=radare2
[ -z "${DIR}" ] && DIR=radare2.build
[ -z "${URL}" ] && URL=http://radare.org/hg/${NAME}
WD=${PWD}/${DIR}
NOW=$(date +%Y%m%d-%H%M%S)
if [ -z "$1" ]; then
	LOGFILE=${WD}/build.log.${NOW}
else
	LOGFILE="$1"
fi
PREFIX=/usr
DESTDIR=${WD}/prefix
MAKE=make
CONFIGUREFLAGS=--prefix=${PREFIX}
DOLOG="2>&1 | tee -a ${LOGFILE}"
DOLOG="2>&1 | tee -a ${LOGFILE} > /dev/null"

testcc() {
	log "[==] Testing $1"
	
}

log() {
	echo $@
	echo $@ >> ${LOGFILE}
}

logcmd() {
	eval $@ ${DOLOG}
}

registerpurge() {
	if [ -z "`grep purge ~/.hgrc`" ]; then
		echo 'purge=' >> ~/.hgrc
	fi
}

log "[==] Logging ${LOGFILE}"
:> ${LOGFILE}
ln -fs ${LOGFILE} ${WD}/build.log
log "[==] Retrieving system information"
uname -a >> ${LOGFILE}
cat /proc/cpuinfo >> ${LOGFILE}

log "[==] Working directory: $WD/$DIR"
mkdir -p ${DIR}
cd ${DIR}

if [ -d "${NAME}" ]; then
	log "[==] Cleaning up old build directory..."
	cd ${NAME}
	registerpurge
	hg purge --all
else
	log "[==] Checking out from ${URL}..."
	hg clone ${URL} 2>&1 | tee -a ${LOGFILE}
	cd ${NAME}
fi

if [ -e "Makefile" ]; then
	log "[==] Running mrproper..."
	${MAKE} mrproper
fi

log "[==] Running configure..."
logcmd time ./configure ${CONFIGUREFLAGS}

log "[==] Running make ${MAKEFLAGS}"
logcmd time ${MAKE} ${MAKEFLAGS}

log "[==] Installing in ${PREFIX}"
logcmd time ${MAKE} install DESTDIR="${DESTDIR}"

log "[==] Running some tests..."
export PATH=${DESTDIR}/${PREFIX}/bin:$PATH
export PKG_CONFIG_PATH=${DESTDIR}/${PREFIX}/lib/pkgconfig
export LD_LIBRARY_PATH=${DESTDIR}/${PREFIX}/lib
logcmd type r2
logcmd type rasm2
logcmd type rabin2
logcmd radare2 -V

log "[==] List of installed files"
logcmd "(cd ${DESTDIR} && find *)"

log "[==] Uninstalling.."
logcmd time ${MAKE} uninstall DESTDIR="${DESTDIR}"

log "[==] List of residual files"
logcmd "(cd ${DESTDIR} && find *)"

log "[==] Symbolic installation... "
${MAKE} symstall DESTDIR="${DESTDIR}" 2>&1 > /dev/null

log "[==] List of symbollically installed files"
logcmd "(cd ${DESTDIR} && find *)"

log "[==] Configuring valaswig bindings..."
cd swig
logcmd time ./configure --prefix=${PREFIX}

log "[==] Compiling swig/..."
logcmd time ${MAKE}

log "[==] Installing valaswig bindings..."
logcmd time ${MAKE} install DESTDIR=${DESTDIR}

log "[==] Testing bindings.."
logcmd python -c 'from r2.r_core import *;c=RCore()'
# TODO. add more tests here

log "[==] Looking for mingw32 crosscompilers.."
cc=""
for a in i486-mingw32-gcc i586-mingw32msvc-gcc ; do
	cc=$(testcc $a)
	[ -n "$cc"] && break
done

if [ -n "$cc" ]; then
	log "[==] mingw32 build"
	${MAKE} mrproper
	log "[==] mingw32 configure"
	logcmd ./configure --without-gmp --with-ostype=windows --with-compiler=$cc --host=i586-unknown-windows
	log "[==] mingw32 make"
	logcmd ${MAKE}
	log "[==] mingw32 w32dist"
	logcmd ${MAKE} w32dist
else
	log "[==] Cannot find any compatible w32 crosscompiler. Report if not true"
fi

echo "[==] Please report ${LOGFILE}"
