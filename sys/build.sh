#!/bin/sh

GetPlatform() {
	# Get OS and platform to decide if we need to limit memory usage
	# during the build
	PLATFORM=$(uname -a)
	case "$PLATFORM" in
	"Linux raspberrypi"*) MAX_MEM_PER_JOB=300000;;
	"Linux"*) MAX_MEM_PER_JOB=150000;;
	*) MAX_MEM_PER_JOB=200000 # If platform is not Linux (fallback value)
	esac
}

BuildJobsThrottler(){
	echo "Building on Linux : computing number of allowed parallel jobs."
	echo "Maximum allowed RAM memory per job is $MAX_MEM_PER_JOB kB."

	# Get number of CPUs on this target
	# getconf does not exit on Darwin. Use sysctl on Darwin machines.
	CPU_N=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)
	printf "Number of CPUs is %s and "  "$CPU_N"

	# Get remaining RAM that could be used for this build
	FREE_RAM=$(grep MemAvailable /proc/meminfo | sed 's/[^0-9]//g')

	DEFAULT_MAX_MEM_PER_JOB=200000
	[ -z "${MAX_MEM_PER_JOB}" ] && MAX_MEM_PER_JOB="$DEFAULT_MAX_MEM_PER_JOB" # Defensive, prevent devision by 0

	# Assuming we may have many 300MB compilation jobs running in parallel
	MEM_ALLOWED_JOBS=$((FREE_RAM / MAX_MEM_PER_JOB))
	echo "current free RAM allows us to run $MEM_ALLOWED_JOBS jobs in parallel."

	# Set number of build jobs to be run in parallel as the minimum between $MEM_ALLOWED_JOBS and $CPU_N
	MAKE_JOBS=$((MEM_ALLOWED_JOBS<CPU_N?MEM_ALLOWED_JOBS:CPU_N))
	if [ ${MAKE_JOBS} -lt 1 ]; then
		MAKE_JOBS=8
	fi
	echo "So, the build will run on $MAKE_JOBS job(s)."
}

OSNAME=$(uname)

if [ "${OSNAME}" = Linux ]; then
	# Identify current platform
	GetPlatform
	# Define number of parallel jobs depending on ncpus and memory
	BuildJobsThrottler
fi

if [ -z "${MAKE}" ]; then
	MAKE=make
	gmake --help >/dev/null 2>&1
	[ $? = 0 ] && MAKE=gmake
fi

[ -z "${MAKE_JOBS}" ] && MAKE_JOBS=12
[ -z "${CERTID}" ] && CERTID=org.radare.radare2

# find root
A=$(dirname "$PWD/$0")
cd "$A" && cd .. || exit 1

DEFAULT_PREFIX=/usr/local
if [ "${OSNAME}" = Darwin ]; then
	# purge previous installations on other common paths
	if [ -f /usr/bin/r2 ]; then
		type sudo || NOSUDO=1
		[ "$(id -u)" = 0 ] || SUDO=sudo
		[ -n "${NOSUDO}" ] && SUDO=
	fi
fi

[ -z "${PREFIX}" ] && PREFIX="${DEFAULT_PREFIX}"

for a in $* ; do
	case "$a" in
	-h|--help)
		echo "Usage: sys/build.sh [/usr/local]"
		exit 0
		;;
	'')
		:
		;;
	--**|-)
		shift
		CFGARG="${CFGARG} $a"
		;;
	*)
		PREFIX="$a"
		;;
	esac
done

if [ "${USE_CS5}" = 1 ]; then
	CFGARG="${CFGARG} --with-capstone5"
fi

if [ "${OSNAME}" = Linux ] && [ -n "${PREFIX}" ] && [ "${PREFIX}" != /usr ]; then
	CFGARG="${CFGARG} --with-rpath"
fi

ccache --help > /dev/null 2>&1
if [ $? = 0 ]; then
	[ -z "${CC}" ] && CC=gcc
	CC="ccache ${CC}"
	export CC
fi

# Required to build on FreeBSD
if [ ! -x /usr/bin/gcc ] && [ -x /usr/bin/cc ]; then
	export CC=cc
	export HOST_CC=cc
fi

# purge first
if [ "${PREFIX}" != "/usr" ]; then
	A=$(readlink /usr/bin/radare2 2>/dev/null)
	B="${PWD}/binr/radare2/radare2"
	if [ -n "$A" ] && [ ! -f "$A" ]; then
		A="$B"
	fi
	if [ "$A" = "$B" ]; then
		echo "Purging r2 installation from /usr..."
		./configure --prefix=/usr > /dev/null
		echo ${SUDO} ${MAKE} uninstall
		SD=""
		type sudo && SD=sudo
		${SD} ${MAKE} uninstall
	fi
fi

# build
${MAKE} mrproper > /dev/null 2>&1
[ "${OSNAME}" = Linux ] && export LDFLAGS="-Wl,--as-needed ${LDFLAGS}"
[ -z "${KEEP_PLUGINS_CFG}" ] && rm -f plugins.cfg
unset R2DEPS
pwd

./configure ${CFGARG} --prefix="${PREFIX}" || exit 1
${MAKE} -s -j${MAKE_JOBS} MAKE_JOBS=${MAKE_JOBS} || exit 1
if [ "${OSNAME}" = Darwin ]; then
	./sys/macos-cert.sh
	${MAKE} macos-sign macos-sign-libs CERTID="${CERTID}" || (
		echo "CERTID not defined. If you want the bins signed to debug without root"
		echo "follow the instructions described in doc/macos.md and run make macos-sign."
	)
fi
