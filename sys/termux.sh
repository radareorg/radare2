#!/data/data/com.termux/files/usr/bin/bash
if [ -z "${PREFIX}" ]; then
	echo "PREFIX env var not set, are you running this script from Termux?"
	PREFIX=/data/data/com.termux/files/usr
fi
export ANDROID=1
# make clean > /dev/null 2>&1
rm -f libr/include/r_version.h
cp -f dist/plugins/plugins.termux.cfg plugins.cfg
./configure-plugins
bash ./configure --with-compiler=termux --prefix=${PREFIX} || exit 1
make libr/include/r_version.h
touch -t 19700101 libr/include/r_version.h
rm -f "${PREFIX}/lib/"libr_*
make -j2 || exit 1
make symstall
