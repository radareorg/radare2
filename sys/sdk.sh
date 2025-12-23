#!/bin/bash

# Unified SDK script

. sys/sdk-common.sh

WRKDIR=/tmp
SDKDIR=${WRKDIR}/r2-sdk
if [ -n "$1" ]; then
	if [ -f "$1" ]; then
		echo "Target directory exists. Cant build the SDK in there"
		exit 1
	fi
	SDKDIR="$1"
fi

OS=`uname`

set -eo pipefail

if [ "$OS" = "Darwin" ]; then
	# On macOS, build xcframework for iOS and macOS
	echo "Building xcframework for iOS and macOS"
	
	# Build iOS SDK
	echo "Building iOS SDK..."
	INSTALL_DST_IOS="/tmp/r2ios"
	sys/sdk-ios.sh -archs arm64 -simulator -d "$INSTALL_DST_IOS"
	
	# Build macOS SDK
	echo "Building macOS SDK..."
	INSTALL_DST_MACOS="/tmp/r2macos"
	sys/sdk-macos.sh -archs x86_64+arm64 -d "$INSTALL_DST_MACOS"

	make_framework() {
		local inst="$1"
		local flavor="$2"
		local out_root="$3"
		local fw="${out_root}/Radare2.framework"

		local dylib=""
		local incdir=""
		local sharedir=""

		case "$flavor" in
			ios)
				dylib="${inst}/usr/local/lib/libr.dylib"
				incdir="${inst}/usr/local/include/libr"
				sharedir="${inst}/usr/local/share/radare2/last"
				;;
			sim)
				dylib="${inst}/usr/local/lib_simulator/libr.dylib"
				incdir="${inst}/usr/local/include_simulator/libr"
				sharedir="${inst}/usr/local/share/radare2/last"
				;;
			macos)
				dylib="${inst}/usr/local/lib/libr.dylib"
				incdir="${inst}/usr/local/include/libr"
				sharedir="${inst}/usr/local/share/radare2/last"
				;;
			*)
				echo "make_framework: unknown flavor: $flavor" >&2
				exit 1
				;;
		esac

		r2_define() {
			local name="$1"
			local header="$2"

			awk -v n="$name" '
				$1 == "#define" && $2 == n {
					val=$3
					for (i = 4; i <= NF; i++) {
						val = val " " $i
					}

					if (val ~ /^".*"$/) {
						sub(/^"/, "", val)
						sub(/"$/, "", val)
					}

					print val
					exit 0
				}
				END { exit 1 }
				' "$incdir/$header"
		}

		local R2_VERSION="$(r2_define R2_VERSION r_version.h)"
		local R2_ABIVERSION="$(r2_define R2_ABIVERSION r_lib.h)"

		rm -rf "$fw"

		# Default: shallow (iOS, simulator)
		local hdrdir="$fw/Headers"
		local moddir="$fw/Modules"
		local resdir="$fw/Resources"
		local infodir="$fw"
		local bindir="$fw"
		local install_id_path="@rpath/Radare2.framework/Radare2"

		# macOS: versioned (non-shallow) framework layout
		if [ "$flavor" = "macos" ]; then
			local ver="$fw/Versions/A"
			hdrdir="$ver/Headers"
			moddir="$ver/Modules"
			resdir="$ver/Resources"
			infodir="$resdir"
			bindir="$ver"
			install_id_path="@rpath/Radare2.framework/Versions/A/Radare2"

			mkdir -p "$hdrdir" "$moddir" "$resdir"

			ln -s "A" "$fw/Versions/Current"
			ln -s "Versions/Current/Headers"   "$fw/Headers"
			ln -s "Versions/Current/Modules"   "$fw/Modules"
			ln -s "Versions/Current/Resources" "$fw/Resources"
			ln -s "Versions/Current/Radare2"   "$fw/Radare2"
		else
			mkdir -p "$hdrdir" "$moddir" "$resdir"
		fi

		cp "$dylib" "$bindir/Radare2"

		xcrun install_name_tool -id "$install_id_path" "$bindir/Radare2"

		xcrun install_name_tool \
			-change "@rpath/libr.dylib" "$install_id_path" \
			"$bindir/Radare2"

		cp -R "$incdir/"* "$hdrdir/"
		(
			cd "$hdrdir"
			rm -rf ptrace_wrap.h r2naked.h sflib sdb/gcc_stdatomic.h sdb/msvc_stdatomic.h
		)

		python3 - <<'PY' "$fw/Headers"
from pathlib import Path
import os, re, sys

hdr_root = Path(sys.argv[1])
if not hdr_root.is_dir():
    raise SystemExit(f"Headers dir not found: {hdr_root}")

relpaths = set()
by_base = {}

for root, _, files in os.walk(hdr_root):
    for fn in files:
        if not fn.endswith(".h"):
            continue
        full = Path(root) / fn
        rel = full.relative_to(hdr_root).as_posix()
        relpaths.add(rel)
        by_base.setdefault(fn, set()).add(rel)

include_re = re.compile(r'^(\s*#\s*include\s*)([<"])([^>"]+)([>"])(.*)$', re.M)

def rewrite_text(text: str) -> str:
    def repl(m: re.Match) -> str:
        prefix = m.group(1)
        target = m.group(3).strip()
        trailer = m.group(5)

        # Already fixed up
        if target.startswith('Radare2/'):
            return m.group(0)

        new_target = None

        if target in relpaths:
            new_target = target
        elif "/" not in target and target in by_base:
            cands = by_base[target]
            if target in cands:
                new_target = target
            elif len(cands) == 1:
                new_target = next(iter(cands))
            else:
                new_target = None

        if new_target is None:
            return m.group(0)

        return f"{prefix}<Radare2/{new_target}>{trailer}"

    return include_re.sub(repl, text)

for root, _, files in os.walk(hdr_root):
    for fn in files:
        if not fn.endswith(".h"):
            continue
        path = Path(root) / fn
        text = path.read_text(encoding="utf-8")
        new_text = rewrite_text(text)
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")

PY

		cat > "$moddir/module.modulemap" <<'EOF'
framework module Radare2 {
  umbrella "Headers"
  export *
}
EOF

		local supported_platform=""
		case "$flavor" in
			ios) supported_platform="iPhoneOS" ;;
			sim) supported_platform="iPhoneSimulator" ;;
			macos) supported_platform="" ;;
		esac

		local min_os_version="${IOSVER:-14.0}"

		local dt_platform_name=""
		local dt_sdk_name=""
		local dt_xcode_build=""
		local build_machine_os_build=""

		if [ "$flavor" != "macos" ]; then
			if [ "$flavor" = "sim" ]; then
				dt_platform_name="iphonesimulator"
			else
				dt_platform_name="iphoneos"
			fi

			local sdkver="$(xcrun --sdk "${dt_platform_name}" --show-sdk-version)"
			dt_sdk_name="${dt_platform_name}${sdkver}"

			dt_xcode_build="$(xcodebuild -version | awk '/Build version/{print $3}')"
			build_machine_os_build="$(sw_vers -buildVersion)"
		fi

		local infopath="$infodir/Info.plist"

		cat > "$infopath" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>org.radare2.Radare2</string>
  <key>CFBundleName</key>
  <string>Radare2</string>
  <key>CFBundlePackageType</key>
  <string>FMWK</string>
  <key>CFBundleSignature</key>
  <string>????</string>
  <key>CFBundleShortVersionString</key>
  <string>${R2_VERSION}</string>
  <key>CFBundleVersion</key>
  <string>${R2_ABIVERSION}</string>
  <key>CFBundleExecutable</key>
  <string>Radare2</string>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
EOF

		if [ "$flavor" != "macos" ]; then
			cat >> "$infopath" <<EOF
  <key>CFBundleSupportedPlatforms</key>
  <array>
    <string>${supported_platform}</string>
  </array>
  <key>MinimumOSVersion</key>
  <string>${min_os_version}</string>
  <key>DTPlatformName</key>
  <string>${dt_platform_name}</string>
  <key>DTSDKName</key>
  <string>${dt_sdk_name}</string>
  <key>DTXcodeBuild</key>
  <string>${dt_xcode_build}</string>
  <key>BuildMachineOSBuild</key>
  <string>${build_machine_os_build}</string>
EOF
		fi

		cat >> "$infopath" <<'EOF'
</dict>
</plist>
EOF

		cp -aL "$sharedir/." "$resdir/"
	}

	FW_ROOT="/tmp/r2-framework-slices"
	rm -rf "$FW_ROOT"
	mkdir -p "$FW_ROOT/ios" "$FW_ROOT/sim" "$FW_ROOT/macos"

	make_framework "$INSTALL_DST_IOS"   ios   "$FW_ROOT/ios"
	make_framework "$INSTALL_DST_IOS"   sim   "$FW_ROOT/sim"
	make_framework "$INSTALL_DST_MACOS" macos "$FW_ROOT/macos"

	# Create xcframework
	echo "Creating xcframework..."
	XCF_DST="/tmp/Radare2.xcframework"
	rm -rf "$XCF_DST"
	mkdir -p "$XCF_DST"
	xcodebuild -create-xcframework \
		-framework "$FW_ROOT/ios/Radare2.framework" \
		-framework "$FW_ROOT/sim/Radare2.framework" \
		-framework "$FW_ROOT/macos/Radare2.framework" \
		-output "$XCF_DST"
	
	if [ $? -eq 0 ]; then
		echo "XCFramework created at $XCF_DST"
		# Zip it
		OUTDIR=$PWD
		(
			cd "$(dirname "$XCF_DST")" || exit 1
			ditto -c -k --sequesterRsrc --keepParent \
				"$(basename "$XCF_DST")" \
				"${OUTDIR}/Radare2.xcframework.zip"
		)
		echo "Zipped to Radare2.xcframework.zip"
	else
		echo "Failed to create xcframework"
		exit 1
	fi
else
	# Generic Unix build
	export CFLAGS="$CFLAGS -fPIC"
	make mrproper
	if [ -z "${R2_PLUGINS_CFG}" ]; then
		R2_PLUGINS_CFG=dist/plugins-cfg/plugins.bin.cfg
	fi
	cp -f "${R2_PLUGINS_CFG}" plugins.cfg
	./configure --prefix="$PREFIX" --with-libr --without-gpl --with-checks-level=0 || exit 1
	make -j8 || exit 1
	rm -rf "${SDKDIR}"
	mkdir -p "${SDKDIR}"/lib
	rm -f libr/libr.a
	cp -rf libr/include "${SDKDIR}"
	mkdir -p "${SDKDIR}/include/sdb"
	cp -rf subprojects/sdb/include/sdb/* "${SDKDIR}/include/sdb"
	FILES=`find libr shlr -iname '*.a'`
	cp -f ${FILES} "${SDKDIR}"/lib
	AR=`uname -m`
	SF=r2sdk-${OS}-${AR}

	(
	cd "${WRKDIR}"
	mv r2-sdk "${SF}"
	zip -r "${SF}".zip "${SF}"
	)
	mv "${WRKDIR}/${SF}" .
	mv "${WRKDIR}/${SF}".zip .
	ln -fs "${SF}" r2sdk
fi
