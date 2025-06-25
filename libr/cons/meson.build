r_cons_sources = [
  '2048.c',
  'canvas_line.c',
  'canvas.c',
  'cons.c',
  'cpipe.c',
  'cutf8.c',
  'editor.c',
  'grep.c',
  'help.c',
  'hud.c',
  'input.c',
  'less.c',
  'line.c',
  'pager.c',
  'pal.c',
  'pixel.c',
  'rgb.c',
  'stiv.c',
  'visual.c',
  'winutils.c'
]

r_cons = library('r_cons', r_cons_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [r_util_dep],
  link_with: [r_util],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_cons_dep = declare_dependency(link_with: r_cons,
                                include_directories: [platform_inc])

if get_option('blob')
r_cons_static = static_library('r_cons_static', r_cons_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [r_util_static_dep],
  link_with: [r_util_static],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
)

r_cons_static_dep = declare_dependency(link_with: r_cons_static,
                                include_directories: [platform_inc])
endif

pkgconfig_mod.generate(r_cons,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_cons',
  filebase: 'r_cons',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
