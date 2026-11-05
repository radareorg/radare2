#!/usr/bin/env bash
set -eu

ISO_NAME="${ISO_NAME:-r2iso}"
DEBIAN_RELEASE="${DEBIAN_RELEASE:-bookworm}"
ARCH="${ARCH:-amd64}"
OUTPUT_DIR="${OUTPUT_DIR:-output}"
WORK_DIR="${WORK_DIR:-build/live-build}"
R2_GIT_URL="${R2_GIT_URL:-https://github.com/radareorg/radare2.git}"
R2_GIT_REF="${R2_GIT_REF:-master}"
R2PM_PLUGINS="${R2PM_PLUGINS:-}"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates git live-build

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}" "${OUTPUT_DIR}"
cd "${WORK_DIR}"

lb config --mode debian --distribution "${DEBIAN_RELEASE}" --architectures "${ARCH}" --binary-images iso-hybrid --debian-installer none
mkdir -p config/hooks/live config/includes.chroot/usr/local/sbin
install -m 0755 /src/scripts/install-r2pm-plugins.sh config/includes.chroot/usr/local/sbin/install-r2pm-plugins.sh
if [ -d /src/rootfs ]; then
	cp -a /src/rootfs/. config/includes.chroot/
fi

cat > config/hooks/live/010-build-radare2.chroot <<HOOK
#!/usr/bin/env bash
set -eu
git clone --depth 1 --branch "${R2_GIT_REF}" "${R2_GIT_URL}" /usr/src/radare2
cd /usr/src/radare2
./configure --prefix=/usr
make -j"\$(nproc)"
make install
/usr/local/sbin/install-r2pm-plugins.sh "${R2PM_PLUGINS}"
rm -rf /usr/src/radare2 /root/.cache/radare2 /root/.local/share/radare2
HOOK
chmod +x config/hooks/live/010-build-radare2.chroot

lb build
cp -f ./*.iso "/src/${OUTPUT_DIR}/${ISO_NAME}-${DEBIAN_RELEASE}-${ARCH}.iso"
