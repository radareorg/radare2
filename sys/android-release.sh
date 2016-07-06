#!/bin/sh
# path to radare2-bin repo
R2B="${PWD}/../radare2-bin"
# source of r2, where radare2 tarballs live
R2T="${PWD}"

ARCHS="arm mips aarch64 x86"
v="`./configure --version| head -n 1|awk '{print $1}'|cut -d - -f 2`"
[ -z "${v}" ] && v=0.10.4

if [ -n "$1" ]; then
	ARCHS="$@"
fi

echo "Building for $ARCHS ..."

make-readme() {
	echo "radare2 for android-$1"
	echo "========================"
	echo "Date: `date +%Y-%m-%d`"
	echo "Version: $v"
}

if [ ! -d "${R2B}" ]; then
	mkdir -p "${R2B}"
	cd "${R2B}/.."
	git clone https://github.com/radare/radare2-bin
fi

cd "$R2B"
for a in ${ARCHS} ; do 
	echo "Releasing $a ..."
	git checkout android-${a} || exit 1
	if [ ! -f "${R2T}/radare2-${v}-android-${a}.tar.gz" ]; then
		(
		cd "${R2T}"
		sys/android-${a}.sh
		)
	fi
	if [ ! -f "${R2T}/radare2-${v}-android-${a}.tar.gz" ]; then
		echo "Build for $a failed"
		exit 1
	fi
	# cp -f "${R2T}/radare2-${v}-android-${a}.tar.gz" . || exit 1
	cp -f "${R2T}/radare2-${v}-android-${a}.tar.gz" . # || exit 1
	rm -f README.md
	make-readme $a > README.md
	cat README.md
	git add README.md
	git commit -a -m 'Update tarball' || exit 1
	git rebase -i @~2 || exit 1
	git push -f || exit 1
done
