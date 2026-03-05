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
R2PM_PLUGINS="${R2PM_PLUGINS:-r2dec}"
KEEP_R2_SOURCE="${KEEP_R2_SOURCE:-0}"
KEEP_R2PM_CACHE="${KEEP_R2PM_CACHE:-0}"
BOOTLOADERS="${BOOTLOADERS:-}"
ROOTFS_DIR="${ROOTFS_DIR:-rootfs}"
ISO_MOTD="${ISO_MOTD:-Welcome to r2iso}"
ROOT_PASSWORD_MODE="${ROOT_PASSWORD_MODE:-empty}"
ROOT_PASSWORD="${ROOT_PASSWORD:-radare2}"
HOST_BUILD_PACKAGES="${HOST_BUILD_PACKAGES:-ca-certificates curl debootstrap git live-build mtools squashfs-tools syslinux-common xorriso}"
ISO_CHROOT_PACKAGES="${ISO_CHROOT_PACKAGES:-ca-certificates curl file git gcc meson ninja-build vim libcapstone-dev liblz4-dev libmagic-dev libssl-dev libuv1-dev libxxhash-dev libzstd-dev libzip-dev make pkg-config python3 wget zlib1g-dev build-essential}"
ISO_CHROOT_PURGE_PACKAGES="${ISO_CHROOT_PURGE_PACKAGES:-build-essential libcapstone-dev liblz4-dev libmagic-dev libssl-dev libuv1-dev libxxhash-dev libzstd-dev libzip-dev zlib1g-dev}"

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
if [ -z "${HOST_BUILD_PACKAGES}" ]; then
	echo "HOST_BUILD_PACKAGES cannot be empty" >&2
	exit 1
fi
if [ -z "${ISO_CHROOT_PACKAGES}" ]; then
	echo "ISO_CHROOT_PACKAGES cannot be empty" >&2
	exit 1
fi
case "${ROOT_PASSWORD_MODE}" in
empty|password|locked) ;;
*)
	echo "ROOT_PASSWORD_MODE must be empty, password or locked" >&2
	exit 1
	;;
esac
if [ "${ROOT_PASSWORD_MODE}" = "password" ] && [ -z "${ROOT_PASSWORD}" ]; then
	echo "ROOT_PASSWORD cannot be empty when ROOT_PASSWORD_MODE=password" >&2
	exit 1
fi

case "${WORK_DIR}" in
/*) WORK_ABS="${WORK_DIR}" ;;
*) WORK_ABS="${BUILD_ROOT}/${WORK_DIR}" ;;
esac

echo "[*] Installing build dependencies in container"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ${HOST_BUILD_PACKAGES}

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

: > config/package-lists/r2iso.list.chroot
for pkg in ${ISO_CHROOT_PACKAGES}; do
	echo "${pkg}" >> config/package-lists/r2iso.list.chroot
done

install -m 0755 "${SOURCE_DIR}/scripts/install-r2pm-plugins.sh" \
	"config/includes.chroot/usr/local/sbin/install-r2pm-plugins.sh"
if [ -n "${ROOTFS_DIR}" ]; then
	if [ ! -d "${SOURCE_DIR}/${ROOTFS_DIR}" ]; then
		echo "ROOTFS_DIR does not exist: ${ROOTFS_DIR}" >&2
		exit 1
	fi
	echo "[*] Copying rootfs overlay from ${ROOTFS_DIR}"
	cp -a "${SOURCE_DIR}/${ROOTFS_DIR}/." config/includes.chroot/
fi
if [ -n "${ISO_MOTD}" ]; then
	mkdir -p config/includes.chroot/etc
	printf '%s\n' "${ISO_MOTD}" > config/includes.chroot/etc/motd
fi

cat > config/hooks/live/010-build-radare2.chroot <<EOF
#!/usr/bin/env bash
set -euo pipefail

R2_GIT_URL='${R2_GIT_URL}'
R2_GIT_REF='${R2_GIT_REF}'
R2PM_PLUGINS='${R2PM_PLUGINS}'
KEEP_R2_SOURCE='${KEEP_R2_SOURCE}'
KEEP_R2PM_CACHE='${KEEP_R2PM_CACHE}'
ROOT_PASSWORD_MODE='${ROOT_PASSWORD_MODE}'
ROOT_PASSWORD='${ROOT_PASSWORD}'
ISO_CHROOT_PACKAGES='${ISO_CHROOT_PACKAGES}'
ISO_CHROOT_PURGE_PACKAGES='${ISO_CHROOT_PURGE_PACKAGES}'

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

case "\${ROOT_PASSWORD_MODE}" in
empty)
	passwd -d root || true
	passwd -u root || true
	;;
password)
	echo "root:\${ROOT_PASSWORD}" | chpasswd
	;;
locked)
	passwd -l root || true
	;;
esac

apt-mark manual \${ISO_CHROOT_PACKAGES} >/dev/null 2>&1 || true
if [ -n "\${ISO_CHROOT_PURGE_PACKAGES}" ]; then
	apt-get purge -y \${ISO_CHROOT_PURGE_PACKAGES} || true
fi
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
