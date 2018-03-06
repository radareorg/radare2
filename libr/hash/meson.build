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
  'state.c',
  'xxhash.c'
]

r_hash = library('r_hash', files,
  include_directories: [platform_inc],
  dependencies: [mth],
  link_with: [r_util],
  install: true,
  implicit_include_directories: false
)


pkg = import('pkgconfig')
pkg.generate(libraries: [r_hash],
             subdirs: 'libr',
             version: r2version,
             name: 'r_hash',
             filebase: 'r_hash',
             requires: [
               'r_util'
             ],
             description: 'radare foundation libraries')
