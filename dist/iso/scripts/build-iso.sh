#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="${SOURCE_DIR:-$(pwd)}"
BUILD_ROOT="${BUILD_ROOT:-/tmp/r2iso-build}"
ISO_NAME="${ISO_NAME:-r2iso}"
OUTPUT_DIR="${OUTPUT_DIR:-output}"
WORK_DIR="${WORK_DIR:-build/live-build}"
DEBIAN_RELEASE="${DEBIAN_RELEASE:-bookworm}"
ARCH="${ARCH:-amd64}"
R2_GIT_URL="${R2_GIT_URL:-https://github.com/radareorg/radare2.git}"
R2_GIT_REF="${R2_GIT_REF:-master}"
R2PM_PLUGINS="${R2PM_PLUGINS:-r2ghidra r2frida}"
KEEP_R2_SOURCE="${KEEP_R2_SOURCE:-0}"
KEEP_R2PM_CACHE="${KEEP_R2PM_CACHE:-0}"
BOOTLOADERS="${BOOTLOADERS:-}"

if [ "${KEEP_R2_SOURCE}" != "0" ] && [ "${KEEP_R2_SOURCE}" != "1" ]; then
	echo "KEEP_R2_SOURCE must be 0 or 1" >&2
	exit 1
fi
if [ "${KEEP_R2PM_CACHE}" != "0" ] && [ "${KEEP_R2PM_CACHE}" != "1" ]; then
	echo "KEEP_R2PM_CACHE must be 0 or 1" >&2
	exit 1
fi
if [ -z "${BOOTLOADERS}" ]; then
	case "${ARCH}" in
	amd64) BOOTLOADERS="syslinux,grub-efi" ;;
	arm64|aarch64) BOOTLOADERS="grub-efi" ;;
	*) BOOTLOADERS="grub-efi" ;;
	esac
fi

case "${WORK_DIR}" in
/*) WORK_ABS="${WORK_DIR}" ;;
*) WORK_ABS="${BUILD_ROOT}/${WORK_DIR}" ;;
esac

echo "[*] Installing build dependencies in container"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
	ca-certificates \
	curl \
	debootstrap \
	git \
	live-build \
	mtools \
	squashfs-tools \
	syslinux-common \
	xorriso

echo "[*] Preparing live-build workspace at ${WORK_DIR}"
rm -rf "${WORK_ABS}"
mkdir -p "${WORK_ABS}" "${SOURCE_DIR:?}/${OUTPUT_DIR}"
cd "${WORK_ABS}"

lb config \
	--mode debian \
	--distribution "${DEBIAN_RELEASE}" \
	--architectures "${ARCH}" \
	--binary-images iso-hybrid \
	--debian-installer none \
	--bootloaders "${BOOTLOADERS}" \
	--apt-recommends false \
	--archive-areas "main"

mkdir -p config/package-lists config/hooks/live config/includes.chroot/usr/local/sbin

cat > config/package-lists/r2iso.list.chroot <<'EOF'
ca-certificates
curl
file
git
libcapstone-dev
liblz4-dev
libmagic-dev
libssl-dev
libuv1-dev
libxxhash-dev
libzstd-dev
libzip-dev
make
pkg-config
python3
wget
zlib1g-dev
build-essential
EOF

install -m 0755 "${SOURCE_DIR}/scripts/install-r2pm-plugins.sh" \
	"config/includes.chroot/usr/local/sbin/install-r2pm-plugins.sh"

cat > config/hooks/live/010-build-radare2.chroot <<EOF
#!/usr/bin/env bash
set -euo pipefail

R2_GIT_URL='${R2_GIT_URL}'
R2_GIT_REF='${R2_GIT_REF}'
R2PM_PLUGINS='${R2PM_PLUGINS}'
KEEP_R2_SOURCE='${KEEP_R2_SOURCE}'
KEEP_R2PM_CACHE='${KEEP_R2PM_CACHE}'

export DEBIAN_FRONTEND=noninteractive
mkdir -p /usr/src

git clone --depth 1 --branch "\${R2_GIT_REF}" "\${R2_GIT_URL}" /usr/src/radare2 || {
	git clone --depth 1 "\${R2_GIT_URL}" /usr/src/radare2
	cd /usr/src/radare2
	git fetch --depth 1 origin "\${R2_GIT_REF}"
	git checkout FETCH_HEAD
}

cd /usr/src/radare2
./configure --prefix=/usr
make -j"\$(nproc)"
make install

/usr/local/sbin/install-r2pm-plugins.sh "\${R2PM_PLUGINS}"

apt-get purge -y \
	build-essential \
	git \
	libcapstone-dev \
	liblz4-dev \
	libmagic-dev \
	libssl-dev \
	libuv1-dev \
	libxxhash-dev \
	libzstd-dev \
	libzip-dev \
	make \
	pkg-config \
	zlib1g-dev || true
apt-get autoremove -y
apt-get clean
rm -rf /var/lib/apt/lists/*

if [ "\${KEEP_R2_SOURCE}" != "1" ]; then
	rm -rf /usr/src/radare2
fi
if [ "\${KEEP_R2PM_CACHE}" != "1" ]; then
	rm -rf /root/.cache/radare2 /root/.local/share/radare2
fi
EOF
chmod +x config/hooks/live/010-build-radare2.chroot

echo "[*] Building ISO with live-build"
lb build

ISO_SOURCE="$(find . -maxdepth 1 -type f -name '*.iso' | head -n 1)"
if [ -z "${ISO_SOURCE}" ]; then
	echo "No ISO produced by live-build" >&2
	exit 1
fi

ISO_TARGET="${SOURCE_DIR}/${OUTPUT_DIR}/${ISO_NAME}-${DEBIAN_RELEASE}-${ARCH}.iso"
cp -f "${ISO_SOURCE}" "${ISO_TARGET}"

echo "[+] ISO ready: ${ISO_TARGET}"
