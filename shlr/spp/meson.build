project('spp', 'c')
spp_version = '1.0.0'

configure_file(input: 'config.def.h',
  output: 'config.h',
  copy: true)

spp_files = [
  'spp.c',
  's_api.c'
]

libspp_static = static_library('spp', spp_files,
  install: not meson.is_subproject()
)

libspp = shared_library('spp', spp_files,
  install: not meson.is_subproject(),
  soversion: spp_version
)

spp_static_dep = declare_dependency(
  link_with: libspp_static,
)

spp_dep = declare_dependency(
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

  spp_exe = executable('spp', ['main.c'],
    dependencies: spp_dep,
    install: true
  )
endif
