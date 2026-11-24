#!/bin/sh
# Check a live stub with the radare2 built in this checkout.
set -eu

usage() {
	printf 'Usage: %s gdb://host:port [read|step] [expected-byte]\n' "$0" >&2
	exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 3 ] || usage
case "${2:-read}" in
	read|step) ;;
	*) usage ;;
esac
case "${3:-}" in
	""|[0-9a-fA-F][0-9a-fA-F]) ;;
	*) usage ;;
esac

r2_bin=${R2_GDB_CLIENT:-./binr/radare2/radare2}
commands='dr PC; p8 1 @ r:PC'
if [ "${2:-read}" = step ]; then
	commands="$commands; ds; dr PC"
fi
output=$("$r2_bin" -NN -q -e scr.color=0 -D gdb -c "$commands; :detach; q!" "$1")
printf '%s\n' "$output"
printf '%s\n' "$output" | awk -v mode="${2:-read}" -v expected="${3:-}" '
	/^0x[0-9a-fA-F]+$/ {
		if (!pc++) {
			initial = $0
		}
		final = $0
	}
	/^[0-9a-fA-F][0-9a-fA-F]$/ && (!length(expected) || tolower($0) == tolower(expected)) { memory = 1 }
	END { exit !(pc && memory && (mode != "step" || (pc > 1 && initial != final))) }
'
