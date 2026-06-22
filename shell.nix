{
  pkgs ? import <nixpkgs> { },
}:
with pkgs;
mkShell {
  strictDeps = true;

  nativeBuildInputs = [
    meson
    ninja
    pkg-config
    python3
    git
  ];

  buildInputs =
    [
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
      libzip
      xxhash
    ]
    ++ lib.optionals stdenv.isDarwin [
      libiconv
    ];
}