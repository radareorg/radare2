#!/bin/sh
CC=cccl

# Configure
if [ ! -e "libr/config.mk" ]; then
	COMPILER=${CC} USERCC=${CC} CC=${CC} LD=${CC} ./configure --with-ostype=windows
	if [ $? -ne 0 ]; then
		echo "Configure failed. Exiting"
		exit 1
	fi
	rm test.exe test.obj
fi

# cl.exe does not use the environment variables when ran from make
# so let's give it to cl.exe with -LIBPATH (translated from -L by cccl)
_IFS=${IFS}
IFS=\;
for path in ${LIBPATH}${LIB}; do
	LDFLAGS="${LDFLAGS} -L\"${path}\""
done
IFS=${_IFS}

# Use /FS to allow cl.exe to write to the same .pdb file
CFLAGS="-FS"

# export CCCL_OPTIONS="--cccl-verbose"
export CFLAGS="${CFLAGS}"
export LDFLAGS="${LDFLAGS}"
export HOST_CFLAGS="${CFLAGS}"
export HOST_LDFLAGS="${LDFLAGS}"
export R2DIR="${R2DIR}"

# Set capstone to release
sed -i s/CS_RELEASE=0/CS_RELEASE=1/ shlr/Makefile
# Disable some plugins
sed -i "s,p/tricore.mk ,," libr/config.mk
sed -i "s,p/z80.mk ,," libr/config.mk

# Now we can make
make CC=${CC} USERCC=${CC} HOST_CC=${CC} USE_CAPSTONE=1
ERR=$?

# Reset capstone Makefile (git)
sed -i s/CS_RELEASE=1/CS_RELEASE=0/ shlr/Makefile
exit $ERR
