#!/bin/sh

mkdir -p build
if [ ! -d radare2 ]; then
	git clone https://github.com/radare/radare2
	cd radare2
else
	cd radare2
	git pull
fi

echo "Generating commits history list"
git log --reverse |grep ^commit |nl | awk '{print $1" "$3}' > ../commits.txt
LAST=`tail -n1 ../commits.txt|cut -d ' ' -f1`
cd ..

ROOT=`pwd`
echo "[+] Found ${LAST} commits."
while : ; do
	[ -d build/radare2-${LAST}-${HASH} ] && continue
	HASH=`grep ^${LAST} commits.txt|cut -d ' ' -f2`
	echo "[+] Checkout out ${LAST} aka ${HASH}"
	git clone radare2 build/radare2-${LAST}-${HASH}/src >/dev/null
	(
	cd build/radare2-${LAST}-${HASH}/src
	git reset --hard ${HASH}
	rm -rf .git
	cp -f ${ROOT}/capstone-2.1.2.tar.gz ${ROOT}/build/radare2-${LAST}-${HASH}/src/shlr/
	PREFIX=${ROOT}/build/radare2-${LAST}-${HASH}/prefix
	mkdir -p ${PREFIX}
	echo "  - Building"
	(
	./configure --prefix=${PREFIX}
	time make -j4
	make install
	) > ${PREFIX}/build.log 2>&1
	)
	LAST=$((${LAST}-1))
done
