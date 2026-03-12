#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)
IMAGE_NAME=${IMAGE_NAME:-radare2-i386-r2r}
OUT_DIR=${OUT_DIR:-"${REPO_DIR}/dist/docker/out/i386-r2r"}
R2_MAKE_JOBS=${R2_MAKE_JOBS:-4}
R2R_JOBS=${R2R_JOBS:-4}
R2_PREFIX=${R2_PREFIX:-/tmp/r2i386}
R2_CONFIGURE_FLAGS=${R2_CONFIGURE_FLAGS:-}
R2R_TIMEOUT_SECS=${R2R_TIMEOUT_SECS:-7200}
SMOKE_TIMEOUT_SECS=${SMOKE_TIMEOUT_SECS:-300}

mkdir -p "${OUT_DIR}"

docker build \
	--platform linux/386 \
	-t "${IMAGE_NAME}" \
	-f "${SCRIPT_DIR}/i386-r2r.Dockerfile" \
	"${SCRIPT_DIR}"

docker run --rm \
	--platform linux/386 \
	--user "$(id -u):$(id -g)" \
	-e HOME=/tmp \
	-e R2_MAKE_JOBS="${R2_MAKE_JOBS}" \
	-e R2R_JOBS="${R2R_JOBS}" \
	-e R2_PREFIX="${R2_PREFIX}" \
	-e R2_CONFIGURE_FLAGS="${R2_CONFIGURE_FLAGS}" \
	-e R2R_TIMEOUT_SECS="${R2R_TIMEOUT_SECS}" \
	-e SMOKE_TIMEOUT_SECS="${SMOKE_TIMEOUT_SECS}" \
	-e CC="${CC-}" \
	-e CFLAGS="${CFLAGS-}" \
	-e LDFLAGS="${LDFLAGS-}" \
	-v "${REPO_DIR}:/src:ro" \
	-v "${OUT_DIR}:/out" \
	"${IMAGE_NAME}" \
	/bin/sh -ec '
		rm -rf /tmp/radare2 "$R2_PREFIX" /tmp/r2wrap
		git clone --quiet --no-hardlinks /src /tmp/radare2 || git clone --quiet /src /tmp/radare2
		git -C /src diff --binary HEAD | git -C /tmp/radare2 apply --allow-empty
		rm -rf /tmp/radare2/test/bins
		if [ -d /src/test/bins ]; then
			ln -s /src/test/bins /tmp/radare2/test/bins
		fi
		cd /tmp/radare2
		if [ ! -d test/bins ]; then
			make -C test bins
		fi
		./configure --prefix="$R2_PREFIX" --with-checks-level=0 $R2_CONFIGURE_FLAGS
		make -j"$R2_MAKE_JOBS"
		make install
		mkdir -p /tmp/r2wrap
		ln -fs "$R2_PREFIX/bin/radare2" /tmp/r2wrap/r2bin
		ln -fs "$R2_PREFIX/bin/rasm2" /tmp/r2wrap/rasm2bin
		cat > /tmp/r2wrap/r2 <<EOS
#!/bin/sh
exec env LD_LIBRARY_PATH=$R2_PREFIX/lib /tmp/r2wrap/r2bin "\$@"
EOS
		cat > /tmp/r2wrap/rasm2 <<EOS
#!/bin/sh
exec env LD_LIBRARY_PATH=$R2_PREFIX/lib /tmp/r2wrap/rasm2bin "\$@"
EOS
		chmod +x /tmp/r2wrap/r2 /tmp/r2wrap/rasm2
		PATH="$R2_PREFIX/bin:$PATH"
		LD_LIBRARY_PATH="$R2_PREFIX/lib"
		export PATH LD_LIBRARY_PATH
		make -C test rc
		make -C test/unit run LIBDIR="$R2_PREFIX/lib" INCLUDEDIR="$R2_PREFIX/include/libr"
		cd test
		timeout "$SMOKE_TIMEOUT_SECS" env \
			R2R_RADARE2=/tmp/r2wrap/r2 \
			R2R_RASM2=/tmp/r2wrap/rasm2 \
			R2R_JOBS="$R2R_JOBS" \
			r2r -L -u -n db/cmd
		timeout "$R2R_TIMEOUT_SECS" env \
			R2R_RADARE2=/tmp/r2wrap/r2 \
			R2R_RASM2=/tmp/r2wrap/rasm2 \
			R2R_JOBS="$R2R_JOBS" \
			r2r -L -u -o results-i386.json db/cmd || true
		cp -f results-i386.json /out/ 2>/dev/null || true
	'
