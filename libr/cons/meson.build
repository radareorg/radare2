r_cons_sources = [
  '2048.c',
  'canvas.c',
  'canvas_line.c',
  'cons.c',
  'html.c',
  # 'dietline.c',
  'editor.c',
  'grep.c',
  'hud.c',
  'input.c',
  'less.c',
  'stiv.c',
  'line.c',
  'more.c',
  'output.c',
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
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_cons_dep = declare_dependency(link_with: r_cons,
                                include_directories: [platform_inc])

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
