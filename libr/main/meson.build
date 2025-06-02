r_main_sources = [
  'main.c',
  'r2agent.c',
  'r2pm.c',
  'rabin2.c',
  'radare2.c',
  'radiff2.c',
  'rafind2.c',
  'ragg2.c',
  'rahash2.c',
  'rapatch2.c',
  'rarun2.c',
  'rasign2.c',
  'rasm2.c',
  'ravc2.c',
  'rax2.c'
]

r_main_deps = [
  r_config_dep,
  r_cons_dep,
  r_io_dep,
  r_util_dep,
  r_flag_dep,
  r_arch_dep,
  r_asm_dep,
  r_core_dep,
  r_esil_dep,
  r_debug_dep,
  r_bin_dep,
  r_lang_dep,
  r_io_dep,
  r_anal_dep,
  r_bp_dep,
  r_egg_dep,
  r_reg_dep,
  r_search_dep,
  r_syscall_dep,
  r_socket_dep,
  r_fs_dep,
  r_magic_dep,
  r_muta_dep
]

r_main = library('r_main', r_main_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: r_main_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_main_dep = declare_dependency(link_with: r_main,
  include_directories: [platform_inc],
  dependencies: r_main_deps)

if get_option('blob')
r_main_static_deps = [
  r_config_static_dep,
  r_cons_static_dep,
  r_io_static_dep,
  r_util_static_dep,
  r_arch_static_dep,
  r_flag_static_dep,
  r_asm_static_dep,
  r_core_static_dep,
  r_debug_static_dep,
  r_bin_static_dep,
  r_lang_static_dep,
  r_io_static_dep,
  r_anal_static_dep,
  r_bp_static_dep,
  r_egg_static_dep,
  r_reg_static_dep,
  r_search_static_dep,
  r_syscall_static_dep,
  r_socket_static_dep,
  r_fs_static_dep,
  r_magic_static_dep,
  r_muta_static_dep
]
  r_main_static = static_library('r_main_static', r_main_sources,
    include_directories: [platform_inc],
    c_args: library_cflags,
    dependencies: r_main_static_deps,
    install: true,
    implicit_include_directories: false,
  )
  r_main_static_dep = declare_dependency(
    link_with: r_main_static,
    include_directories: [platform_inc],
    dependencies: r_main_static_deps
  )
endif

pkgconfig_mod.generate(r_main,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_main',
  libraries: pkgcfg_sanitize_libs,
  filebase: 'r_main',
  requires: [
    'r_core',
    'r_asm',
    'r_syscall'
  ],
  description: 'radare foundation libraries'
)
