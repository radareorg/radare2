executable('r2blob', 'r2blob.c',
  include_directories: [platform_inc],
  dependencies: [
    r_main_dep,
    r_util_dep,
  ],
  install: true,
  install_rpath: rpath_exe,
  implicit_include_directories: false
)

meson.add_install_script('meson_install_links.sh')
