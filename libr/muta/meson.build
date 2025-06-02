r_muta_sources = files(
  'crypto.c',
  'p/muta_aes.c',
  'p/muta_aes_algo.c',
  'p/muta_aes_cbc.c',
  'p/muta_aes_wrap.c',
  'p/muta_bech32.c',
  'p/muta_base64.c',
  'p/muta_base91.c',
  'p/muta_blowfish.c',
  'p/muta_cps2.c',
  'p/muta_des.c',
  'p/muta_ed25519.c',
  'p/muta_punycode.c',
  'p/muta_rc2.c',
  'p/muta_rc4.c',
  'p/muta_rc6.c',
  'p/muta_rol.c',
  'p/muta_ror.c',
  'p/muta_rot.c',
  'p/muta_serpent.c',
  'p/muta_sm4.c',
  'p/muta_sm4_algo.c',
  'p/muta_serpent_algo.c',
  'p/muta_xor.c',
)

r_muta_sources += files(
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

r_muta_sources += files(
  'signature/ed25519/fe.c',
  'signature/ed25519/ge.c',
  'signature/ed25519/sc.c',
)

r_muta_deps = [r_util_dep]

if use_sys_xxhash
  r_muta_deps += sys_xxhash
else
  r_muta_sources += files('hash/xxhash.c')
endif

if use_sys_openssl and use_ssl_crypto
  r_muta_deps += sys_openssl
else
  r_muta_sources += files('hash/md4.c', 'hash/md5.c', 'hash/sha1.c', 'hash/sha2.c')
endif

r_muta = library('r_muta', r_muta_sources,
  include_directories: [platform_inc],
  dependencies: r_muta_deps,
  link_with: [r_util],
  c_args: library_cflags,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_muta_dep = declare_dependency(link_with: r_muta,
  include_directories: [platform_inc])

if get_option('blob')
r_muta_static = static_library('r_muta_static', r_muta_sources,
  include_directories: [platform_inc],
  dependencies: [r_util_static_dep],
  link_with: [r_util_static],
  c_args: library_cflags,
  install: true,
  implicit_include_directories: false,
)
r_muta_static_dep = declare_dependency(link_with: r_muta_static,
  include_directories: [platform_inc])
endif

pkgconfig_mod.generate(r_muta,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_muta',
  filebase: 'r_muta',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
