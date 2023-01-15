
[ -z "${MAKE_JOBS}" ] && MAKE_JOBS=12
export MAKE_JOBS

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
	[ -z "${MAX_MEM_PER_JOB}" ] && MAX_MEM_PER_JOB="$DEFAULT_MAX_MEM_PER_JOB" # Defensive, prevent division by 0

	# Assuming we may have many 300MB compilation jobs running in parallel
	MEM_ALLOWED_JOBS=$((FREE_RAM / MAX_MEM_PER_JOB))
	echo "current free RAM allows us to run $MEM_ALLOWED_JOBS jobs in parallel."

	# Set number of build jobs to be run in parallel as the minimum between $MEM_ALLOWED_JOBS and $CPU_N
	export MAKE_JOBS=$((MEM_ALLOWED_JOBS<CPU_N?MEM_ALLOWED_JOBS:CPU_N))
	if [ ${MAKE_JOBS} -lt 1 ]; then
		MAKE_JOBS=8
	fi
	echo "So, the build will run on $MAKE_JOBS job(s)."
}

if [ "${OSNAME}" = Linux ]; then
	# Identify current platform
	GetPlatform
	# Define number of parallel jobs depending on ncpus and memory
	BuildJobsThrottler
fi
