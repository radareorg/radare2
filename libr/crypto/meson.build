r_crypto_sources = [
  'des.c',
  'crypto.c',
  'p/crypto_aes.c',
  'p/crypto_aes_algo.c',
  'p/crypto_aes_cbc.c',
  'p/crypto_base64.c',
  'p/crypto_base91.c',
  'p/crypto_blowfish.c',
  'p/crypto_cps2.c',
  'p/crypto_des.c',
  'p/crypto_punycode.c',
  'p/crypto_rc2.c',
  'p/crypto_rc4.c',
  'p/crypto_rc6.c',
  'p/crypto_rol.c',
  'p/crypto_ror.c',
  'p/crypto_rot.c',
  'p/crypto_serpent.c',
  'p/crypto_serpent_algo.c',
  'p/crypto_xor.c',
]

r_crypto = library('r_crypto', r_crypto_sources,
  include_directories: [platform_inc],
  dependencies: [r_util_dep],
  c_args: library_cflags,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_crypto_dep = declare_dependency(link_with: r_crypto,
                                  include_directories: [platform_inc])

pkgconfig_mod.generate(r_crypto,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_crypto',
  filebase: 'r_crypto',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
