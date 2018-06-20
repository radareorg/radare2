files = [
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

r_crypto = library('r_crypto', files,
  include_directories: [platform_inc],
  link_with: [r_util],
  c_args: ['-DCORELIB=1'],
  install: true,
  implicit_include_directories: false,
  soversion: r2_libversion
)

pkgconfig_mod.generate(
  libraries: [r_crypto],
  subdirs: 'libr',
  version: r2_version,
  name: 'r_crypto',
  filebase: 'r_crypto',
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
