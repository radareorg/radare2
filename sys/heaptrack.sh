#!/bin/sh

if [ -z "$1" ]; then
	echo "Usage: heaptrack.sh [-c r2cmd] <file> [files...]"
	echo ""
	echo "Runs heaptrack on r2 to profile memory usage."
	echo ""
	echo "Options:"
	echo "  -c <cmd>  Custom r2 command (default: 'aaa; iH')"
	echo ""
	echo "Examples:"
	echo "  sys/heaptrack.sh /bin/ls"
	echo "  sys/heaptrack.sh -c 'pd 100' /bin/ls"
	echo "  sys/heaptrack.sh /bin/ls /bin/cat /bin/echo"
	exit 1
fi

R2CMD="aaa; iH"
if [ "$1" = "-c" ]; then
	if [ -z "$2" ]; then
		echo "Error: -c requires a command argument"
		exit 1
	fi
	R2CMD="$2"
	shift 2
fi

if [ -z "$1" ]; then
	echo "Error: No files specified"
	exit 1
fi

run_heaptrack() {
	FILE="$1"
	CMD="$2"
	TEMPDIR=$(mktemp -d /tmp/heaptrack.XXXXXX)
	
	RAWFILE="${TEMPDIR}/heaptrack.raw"
	DATAFILE="${TEMPDIR}/heaptrack.zst"
	
	heaptrack -r -o "$RAWFILE" r2 -q -c "$CMD" "$FILE" >/dev/null 2>&1
	
	RAWFILE=$(ls -t "${TEMPDIR}"/*.raw.zst 2>/dev/null | head -1)
	if [ -z "$RAWFILE" ]; then
		rm -rf "$TEMPDIR"
		return 1
	fi
	
	zstd -dc < "$RAWFILE" | /usr/lib/heaptrack/libexec/heaptrack_interpret 2>/dev/null | zstd -c > "$DATAFILE"
	
	if [ ! -f "$DATAFILE" ]; then
		rm -rf "$TEMPDIR"
		return 1
	fi
	
	heaptrack_print -f "$DATAFILE" 2>/dev/null
	
	rm -rf "$TEMPDIR"
	return 0
}

printf "%-40s %10s %10s %10s %10s %12s %12s\n" "FILE" "PEAK" "RSS" "LEAKED" "ALLOCS" "TEMPS" "TIME"
printf "%-40s %10s %10s %10s %10s %12s %12s\n" "----" "----" "---" "------" "------" "-----" "----"

for FILE in "$@"; do
	if [ ! -f "$FILE" ]; then
		printf "%-40s %s\n" "$FILE" "FILE NOT FOUND"
		continue
	fi

	METRICS=$(run_heaptrack "$FILE" "$R2CMD")
	if [ $? -ne 0 ]; then
		printf "%-40s %s\n" "$(basename "$FILE")" "HEAPTRACK FAILED"
		continue
	fi

	METRICS=$(echo "$METRICS" | grep -E "^(total runtime|calls to allocation|temporary memory|peak heap|peak RSS|total memory leaked)")

	PEAK=$(echo "$METRICS" | grep "peak heap memory consumption" | awk '{print $5}')
	RSS=$(echo "$METRICS" | grep "peak RSS" | awk '{print $6}')
	LEAKED=$(echo "$METRICS" | grep "total memory leaked" | awk '{print $4}')
	ALLOCS=$(echo "$METRICS" | grep "calls to allocation functions" | awk '{print $5}')
	TEMPS=$(echo "$METRICS" | grep "temporary memory allocations" | awk '{print $4}')
	TIME=$(echo "$METRICS" | grep "total runtime" | awk '{print $3}')

	printf "%-40s %10s %10s %10s %10s %12s %12s\n" "$(basename "$FILE")" "$PEAK" "$RSS" "$LEAKED" "$ALLOCS" "$TEMPS" "$TIME"
done