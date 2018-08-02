files = [
  'adler32.c',
  'calc.c',
  'crca.c',
  'entropy.c',
  'hamdist.c',
  'hash.c',
  'luhn.c',
  'md4.c',
  'md5.c',
  'sha1.c',
  'sha2.c',
  'state.c'
]

dependencies = [mth, r_util_dep]

if get_option('use_sys_xxhash')
  xxhash_dep = dependency('xxhash', required: false)
  if not xxhash_dep.found()
    xxhash_dep = cc.find_library('xxhash', required: false)
  endif
  if not xxhash_dep.found()
    error('Cannot find xxhash dependency')
  endif
  dependencies += [xxhash_dep]
  message('Using system xxhash library')
else
  message('Using bundled xxhash')
  files += ['xxhash.c']
endif

r_hash = library('r_hash', files,
  include_directories: [platform_inc],
  dependencies: dependencies,
  install: true,
  implicit_include_directories: false,
  soversion: r2_libversion
)

r_hash_dep = declare_dependency(link_with: r_hash,
                                include_directories: [platform_inc])

pkgconfig_mod.generate(
  libraries: [r_hash],
  subdirs: 'libr',
  version: r2_version,
  name: 'r_hash',
  filebase: 'r_hash',
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
