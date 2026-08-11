#!/bin/sh
# usage: setuprootfs.sh <pristine.bin> <output.bin> <r2blob> <size_mb> '<links>' [overlay ...]
#
# Build the guest rootfs image: grow the pristine jslinux ext2 image to
# <size_mb>, inject <r2blob> as /bin/r2blob with busybox-style symlinks
# for every name in <links>, and overlay every file from guest/ at the
# same path inside the image (0755 when executable on the host, 0644
# otherwise). Additional rootfs overlays may follow the required arguments.
# Everything runs through debugfs on the image file, so no root privileges
# are needed. debugfs rm/mkdir warnings about
# missing/existing entries are harmless; e2fsck exit codes 1/2 just
# mean "fixed", only >= 4 is a real error.
set -eu

if [ $# -lt 5 ]; then
	echo "usage: $0 <pristine.bin> <output.bin> <r2blob> <size_mb> '<links>' [overlay ...]" >&2
	exit 1
fi
PRISTINE=$1
OUT=$2
R2BLOB=$3
SIZE_MB=$4
LINKS=$5
GUEST="$(dirname "$0")/guest"
shift 5
TMP="$OUT.tmp"
DBG="$OUT.inject.dbg"

fsck_image() {
	RET=0
	e2fsck -fy "$1" || RET=$?
	[ "$RET" -lt 4 ] || exit "$RET"
}

file_is_executable() {
	MODE=$(stat -c '%a' "$1" 2> /dev/null || stat -f '%Lp' "$1")
	[ $((0$MODE & 0111)) -ne 0 ]
}

overlay_commands() {
	OVERLAY=$1
	for D in $(cd "$OVERLAY" && find . -mindepth 1 -type d | sort); do
		echo "mkdir /${D#./}"
	done
	for F in $(cd "$OVERLAY" && find . -type f | sort); do
		F=${F#./}
		B=${F##*/}
		D=${F%/*}
		[ "$D" = "$F" ] && D=""
		# Docker Desktop's X_OK check succeeds for every shared file, so use
		# the stored mode bits to keep headers and archives non-executable.
		if file_is_executable "$OVERLAY/$F"; then
			M=0100755
		else
			M=0100644
		fi
		echo "cd /$D"
		echo "rm $B"
		echo "write $OVERLAY/$F $B"
		echo "sif $B mode $M"
	done
	for F in $(cd "$OVERLAY" && find . -type l | sort); do
		F=${F#./}
		B=${F##*/}
		D=${F%/*}
		[ "$D" = "$F" ] && D=""
		T=$(readlink "$OVERLAY/$F")
		echo "cd /$D"
		echo "rm $B"
		echo "symlink $B $T"
	done
}

cp -f "$PRISTINE" "$TMP"
truncate -s "${SIZE_MB}M" "$TMP"
fsck_image "$TMP"
resize2fs "$TMP"
{
	echo "cd /bin"
	echo "rm r2blob"
	echo "write $R2BLOB r2blob"
	echo "sif r2blob mode 0100755"
	for L in $LINKS; do
		echo "rm $L"
		echo "symlink $L r2blob"
	done
	overlay_commands "$GUEST"
	for OVERLAY in "$@"; do
		overlay_commands "$OVERLAY"
	done
} > "$DBG"
debugfs -w -f "$DBG" "$TMP"
fsck_image "$TMP"
mv "$TMP" "$OUT"
