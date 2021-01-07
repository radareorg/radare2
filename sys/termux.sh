#!/data/data/com.termux/files/usr/bin/bash
if [ -z "${PREFIX}" ]; then
	echo "PREFIX env var not set, are you running this script from Termux?"
fi
export ANDROID=1

bash ./configure --with-compiler=termux --prefix=${PREFIX}
rm -f ${PREFIX}/lib/libr_*
make -j2
make symstall
