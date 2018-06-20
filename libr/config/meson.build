files = [
  'callback.c',
  'config.c',
]

r_config = library('r_config', files,
  include_directories: [platform_inc],
  link_with: [
    r_util,
    libr_shlr
  ],
  install: true,
  implicit_include_directories: false,
  soversion: r2_libversion
)

pkgconfig_mod.generate(
  libraries: [r_config],
  subdirs: 'libr',
  version: r2_version,
  name: 'r_config',
  filebase: 'r_config',
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
