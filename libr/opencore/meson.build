# radare2 - MIT - Copyright 2026 - pancake
# standalone library, only depends on libc (and libdl on old glibc)

r_opencore_deps = []
if host_machine.system() != 'windows'
  r_opencore_deps += cc.find_library('dl', required: false)
endif

r_opencore = static_library('r_opencore', 'opencore.c',
  dependencies: r_opencore_deps,
  install: true,
  implicit_include_directories: false
)

r_opencore_dep = declare_dependency(
  link_with: r_opencore,
  dependencies: r_opencore_deps,
  include_directories: include_directories('.')
)

install_headers('r_opencore.h', install_dir: r2_incdir)
