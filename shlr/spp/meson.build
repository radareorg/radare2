project('spp', 'c')
spp_version = '1.3.0'

configure_file(input: 'config.def.h',
  output: 'config.h',
  copy: true)

spp_files = [
  'spp.c',
]

inc_dirs = [
  '../../libr/include',
  '../../shlr/sdb/src'
]

libspp_static = static_library('spp', spp_files,
  include_directories: inc_dirs,
  c_args: ['-DUSE_R2=1'],
  install: not meson.is_subproject()
)

libspp = shared_library('spp', spp_files,
  include_directories: inc_dirs,
  install: not meson.is_subproject(),
  soversion: spp_version
)

spp_static_dep = declare_dependency(
  include_directories: inc_dirs,
  c_args: ['-DUSE_R2=1'],
  link_with: libspp_static,
)

spp_dep = declare_dependency(
  c_args: ['-DUSE_R2=1'],
  link_with: libspp
)

pkgconfig_mod = import('pkgconfig')
pkgconfig_mod.generate(libspp,
  version: spp_version,
  name: 'spp',
  subdirs: ['.'],
  filebase: 'spp',
  description: 'spp library'
)

if not meson.is_subproject()
  install_headers('spp.h')
  subdir('bin')
endif
