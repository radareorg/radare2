r_crypto_sources = files(
  'des.c',
  'crypto.c',
  'p/crypto_aes.c',
  'p/crypto_aes_algo.c',
  'p/crypto_aes_cbc.c',
  'p/crypto_aes_wrap.c',
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
  'p/crypto_sm4.c',
  'p/crypto_sm4_algo.c',
  'p/crypto_serpent_algo.c',
  'p/crypto_xor.c',
)

r_crypto_sources += files(
  'hash/adler32.c',
  'hash/hcalc.c',
  'hash/crca.c',
  'hash/sip.c',
  'hash/entropy.c',
  'hash/fletcher.c',
  'hash/hamdist.c',
  'hash/hash.c',
  'hash/ssdeep.c',
  'hash/luhn.c',
  'hash/state.c'
)

r_crypto_deps = [r_util_dep]

if use_sys_xxhash
  r_crypto_deps += sys_xxhash
else
  r_crypto_sources += files('hash/xxhash.c')
endif

if use_sys_openssl and use_ssl_crypto
  r_crypto_deps += sys_openssl
else
  r_crypto_sources += files('hash/md4.c', 'hash/md5.c', 'hash/sha1.c', 'hash/sha2.c')
endif

r_crypto = library('r_crypto', r_crypto_sources,
  include_directories: [platform_inc],
  dependencies: r_crypto_deps,
  link_with: [r_util],
  c_args: library_cflags,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_crypto_dep = declare_dependency(link_with: r_crypto,
  include_directories: [platform_inc])

if get_option('blob')
r_crypto_static = static_library('r_crypto_static', r_crypto_sources,
  include_directories: [platform_inc],
  dependencies: [r_util_static_dep],
  link_with: [r_util_static],
  c_args: library_cflags,
  install: true,
  implicit_include_directories: false,
)
r_crypto_static_dep = declare_dependency(link_with: r_crypto_static,
  include_directories: [platform_inc])
endif

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
