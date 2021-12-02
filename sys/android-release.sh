#!/bin/sh
# path to radare2-bin repo
R2B="${PWD}/../radare2-bin"
# source of r2, where radare2 tarballs live
R2T="${PWD}"
ARCHS="arm mips aarch64 x86"

countdown() {
	N=$1
	while : ; do
		printf "[=] Holding breath for $N seconds...   \r"
		[ $N = 0 ] && break
		N=$(($N-1))
		sleep 1
	done
	echo '[>] Starting the release machinery!'
}

msg() {
	echo "\033[32m$@\033[0m"
}

echo
echo "Building r2 tarballs for the Android App"
echo "========================================"
echo " This script will build r2 tarballs for all Android targets"
echo " and commit them into the radare2-bin repository which are"
echo " used by the Android app."
echo
echo "Target archs: ${ARCHS}"
echo

countdown 5

v="`./configure --version| head -n 1|awk '{print $1}'|cut -d - -f 2`"
[ -z "${v}" ] && v=1.4.0

if [ -n "$1" ]; then
	ARCHS="$@"
fi

echo "Building for $ARCHS ..."

makeReadme() {
	echo "radare2 for android-$1"
	echo "========================"
	echo "Date: `date +%Y-%m-%d`"
	echo "Version: $v"
}

if [ ! -d "${R2B}" ]; then
	mkdir -p "${R2B}"
	cd "${R2B}/.."
	git clone https://github.com/radareorg/radare2-bin
fi

cd "$R2B"
for a in ${ARCHS} ; do
	echo "Releasing $a ..."
	git checkout android-${a} || exit 1
	if [ -f "${R2T}/radare2-${v}-android-${a}.tar.gz" ]; then
		msg "[*] Dist tarball already built for ${a}."
	else
		msg "[>] Building Android dist for ${a}..."
		(
		cd "${R2T}"
		sys/android-build.sh ${a} > radare2-${v}-android-${a}.log
		)
	fi
	if [ ! -f "${R2T}/radare2-${v}-android-${a}.tar.gz" ]; then
		msg "[X] Build for $a has failed"
		exit 1
	fi
	msg "[>] Committing $a into radare2-bin..."
	# cp -f "${R2T}/radare2-${v}-android-${a}.tar.gz" . || exit 1
	cp -f "${R2T}/radare2-${v}-android-${a}.tar.gz" . # || exit 1
	rm -f README.md
	makeReadme $a > README.md
	cat README.md
	git add README.md
	git commit -a -m 'Update tarball' || exit 1
	git rebase -i @~2 || exit 1
	git push -f || exit 1
done
