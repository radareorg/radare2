executable('ragg2', 'ragg2.c',
  include_directories: [platform_inc],
  dependencies: [
    r_util_dep,
    r_main_dep,
    r_egg_dep,
    r_bin_dep,
    r_core_dep,
    r_debug_dep,
    r_fs_dep,
    r_config_dep,
    r_bp_dep,
    r_muta_dep
  ],
  install: true,
  install_rpath: rpath_exe,
  implicit_include_directories: false
)
