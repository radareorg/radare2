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

if [ "`uname`" = Linux ]; then
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

if [ "`uname`" = Darwin ]; then
	DEFAULT_PREFIX=/usr/local
	# purge previous installations on other common paths
	if [ -f /usr/bin/r2 ]; then
		type sudo || NOSUDO=1
		[ "$(id -u)" = 0 ] || SUDO=sudo
		[ -n "${NOSUDO}" ] && SUDO=
		# purge first
		echo "Purging r2 installation..."
		./configure --prefix=/usr > /dev/null
		${SUDO} ${MAKE} uninstall > /dev/null
	fi
else
	DEFAULT_PREFIX=/usr
	[ -n "${PREFIX}" -a "${PREFIX}" != /usr ] && \
		CFGARG="${CFGARG} --with-rpath"
fi

[ -z "${PREFIX}" ] && PREFIX="${DEFAULT_PREFIX}"

for a in $* ; do
	case "$a" in
	-h|--help)
		echo "Usage: sys/build.sh [/usr]"
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

ccache --help > /dev/null 2>&1
if [ $? = 0 ]; then
	[ -z "${CC}" ] && CC=gcc
	CC="ccache ${CC}"
	export CC
fi

# Required to build on FreeBSD
if [ ! -x /usr/bin/gcc -a -x /usr/bin/cc ]; then
	export CC=cc
	export HOST_CC=cc
fi

#echo
#echo "export USE_R2_CAPSTONE=$USE_R2_CAPSTONE"
#echo
## Set USE_R2_CAPSTONE env var to ignore syscapstone check
#if [ -z "${USE_R2_CAPSTONE}" ]; then
#	pkg-config --atleast-version=4.0 capstone 2>/dev/null
#	if [ $? = 0 ]; then
#		echo '#include <capstone/capstone.h>' > .a.c
#		echo 'int main() {return 0;}' >> .a.c
#		gcc `pkg-config --cflags --libs capstone` -o .a.out .a.c
#		if [ $? = 0 ]; then
#			CFGARG="${CFGARG} --with-syscapstone"
#		else
#			echo
#			echo "** WARNING ** capstone pkg-config is wrongly installed."
#			echo
#		fi
#		rm -f .a.c .a.out
#	fi
#fi

# build
${MAKE} mrproper > /dev/null 2>&1
[ "`uname`" = Linux ] && export LDFLAGS="-Wl,--as-needed ${LDFLAGS}"
if [ -z "${KEEP_PLUGINS_CFG}" ]; then
	rm -f plugins.cfg
fi
unset DEPS
pwd

./configure ${CFGARG} --prefix="${PREFIX}" || exit 1
${MAKE} -s -j${MAKE_JOBS} MAKE_JOBS=${MAKE_JOBS} || exit 1
if [ "`uname`" = Darwin ]; then
	./sys/macos-cert.sh
	${MAKE} macos-sign macos-sign-libs CERTID="${CERTID}" || (
		echo "CERTID not defined. If you want the bins signed to debug without root"
		echo "follow the instructions described in doc/macos.md and run make macos-sign."
	)
fi
