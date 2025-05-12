r_cons_sources = [
  '2048.c',
  'canvas.c',
  'canvas_line.c',
  'cons.c',
  'help.c',
  'html.c',
  'editor.c',
  'grep.c',
  'hud.c',
  'input.c',
  'pixel.c',
  'less.c',
  'stiv.c',
  'line.c',
  'winutils.c',
  'pager.c',
  'pal.c',
  'cpipe.c',
  'rgb.c',
  'cutf8.c'
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
