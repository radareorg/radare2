executable('r2blob', 'r2blob.c',
  include_directories: [platform_inc],
  dependencies: [
    r_main_dep,
  ],
  install: true,
  install_rpath: rpath_exe,
  implicit_include_directories: false
)

executable('r2blob.static', 'r2blob.c',
  include_directories: [platform_inc],
  dependencies: [
    r_main_static_dep,
  ],
  install: true,
  install_rpath: rpath_exe,
  implicit_include_directories: false
)

meson.add_install_script('meson_install_links.sh')
