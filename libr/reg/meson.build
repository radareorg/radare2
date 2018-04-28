files = [
  'arena.c',
  'cond.c',
  'double.c',
  'profile.c',
  'reg.c',
  'value.c',
]

r_reg = library('r_reg', files,
  include_directories: [platform_inc],
  link_with: [r_util],
  install: true,
  implicit_include_directories: false,
  soversion: r2_libversion
)

pkgconfig_mod.generate(
  libraries: [r_reg],
  subdirs: 'libr',
  version: r2_version,
  name: 'r_reg',
  filebase: 'r_reg',
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
