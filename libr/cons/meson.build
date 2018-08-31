files = [
  '2048.c',
  'canvas.c',
  'canvas_line.c',
  'cons.c',
  # 'dietline.c',
  'editor.c',
  'grep.c',
  'hud.c',
  'input.c',
  'less.c',
  'line.c',
  'output.c',
  'pal.c',
  'pipe.c',
  'rgb.c',
  'utf8.c'
]

r_cons = library('r_cons', files,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [r_util_dep, sdb_dep],
  install: true,
  implicit_include_directories: false,
  soversion: r2_libversion
)

r_cons_dep = declare_dependency(link_with: r_cons,
                                include_directories: [platform_inc])

pkgconfig_mod.generate(
  libraries: [r_cons],
  subdirs: 'libr',
  version: r2_version,
  name: 'r_cons',
  filebase: 'r_cons',
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
