files = [
  'callback.c',
  'config.c',
]

r_config = library('r_config', files,
  include_directories: [platform_inc],
  dependencies: [
    r_util_dep,
    sdb_dep
  ],
  install: true,
  implicit_include_directories: false,
  soversion: r2_libversion
)

r_config_dep = declare_dependency(link_with: r_config,
                                  include_directories: [platform_inc])

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
