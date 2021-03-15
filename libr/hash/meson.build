r_hash_sources = [
  'adler32.c',
  'hcalc.c',
  'crca.c',
  'entropy.c',
  'fletcher.c',
  'hamdist.c',
  'hash.c',
  'luhn.c',
  'state.c'
]

dependencies = [mth, r_util_dep]

if use_sys_xxhash
  dependencies += [sys_xxhash]
else
  r_hash_sources += ['xxhash.c']
endif

if use_sys_openssl
  dependencies += [sys_openssl]
else
  r_hash_sources += ['md4.c', 'md5.c', 'sha1.c', 'sha2.c']
endif

r_hash = library('r_hash', r_hash_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: dependencies,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_hash_dep = declare_dependency(link_with: r_hash,
                                include_directories: [platform_inc])

pkgconfig_mod.generate(r_hash,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_hash',
  filebase: 'r_hash',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
