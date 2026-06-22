{
  lib,
  stdenv,
  fetchFromGitHub,
  buildPackages,
  capstone,
  file,
  libewf,
  libusb-compat-0_1,
  libuv,
  libzip,
  lz4,
  meson,
  ninja,
  openssl,
  perl,
  pkg-config,
  python3,
  readline,
  xxhash,
  zlib,
  src,
}:
let
  binaryninja = fetchFromGitHub {
    owner = "Vector35";
    repo = "binaryninja-api";
    rev = "ba13f6ec7d0ce9a18a03a1c895fb72d18e03014a";
    hash = "sha256-ApBDmrepz27ioEjtqgdGzGF0tPkDghp7dA8L9eHHW6w=";
  };

  sdb = fetchFromGitHub {
    owner = "radareorg";
    repo = "sdb";
    tag = "2.4.4";
    hash = "sha256-JN27SkDqHtX83d1CPUF9hbVKwE/dwhDgn5MlCX9RPrc=";
  };

  qjs = fetchFromGitHub {
    owner = "quickjs-ng";
    repo = "quickjs";
    rev = "3087a2ce5bcb66cc1fcd9f34d3e5ce3bd43a67d9";
    hash = "sha256-Z6DUe/W1+3SYPRPCiL3oNL5ovXCsW3dsFuGkA9WF3W4=";
  };
in
stdenv.mkDerivation (finalAttrs: {
  pname = "radare2";
  version = "6.1.7";

  inherit src;

  mesonFlags = [
    (lib.mesonBool "use_sys_capstone" true)
    (lib.mesonBool "use_sys_lz4" true)
    (lib.mesonBool "use_sys_magic" true)
    (lib.mesonBool "use_sys_openssl" true)
    (lib.mesonBool "use_sys_xxhash" true)
    (lib.mesonBool "use_sys_zip" true)
    (lib.mesonBool "use_sys_zlib" true)
    (lib.mesonOption "r2_gittap" finalAttrs.version)
  ];

  enableParallelBuilding = true;
  depsBuildBuild = [ buildPackages.stdenv.cc ];
  strictDeps = true;

  nativeBuildInputs = [
    pkg-config
    meson
    ninja
    python3
  ];

  buildInputs = [
    capstone
    file
    libewf
    libusb-compat-0_1
    libuv
    lz4
    openssl
    perl
    readline
    zlib
  ];

  propagatedBuildInputs = [
    file
    libzip
    xxhash
  ];

  postUnpack = ''
    pushd $sourceRoot/subprojects

    cp -r ${binaryninja} binaryninja
    chmod -R +w binaryninja
    cp packagefiles/binaryninja/meson.build binaryninja

    cp -r ${sdb} sdb
    chmod -R +w sdb

    cp -r ${qjs} qjs
    chmod -R +w qjs
    cp packagefiles/qjs/meson.build qjs

    popd
  '';

  postFixup = lib.optionalString stdenv.hostPlatform.isDarwin ''
    install_name_tool -add_rpath $out/lib $out/lib/libr_io.${finalAttrs.version}.dylib
  '';

  meta = {
    description = "UNIX-like reverse engineering framework and command-line toolset";
    homepage = "https://radare.org";
    changelog = "https://github.com/radareorg/radare2/releases/tag/${finalAttrs.version}";
    license = with lib.licenses; [
      gpl3Only
      lgpl3Only
    ];
    platforms = lib.platforms.unix;
    mainProgram = "radare2";
  };
})