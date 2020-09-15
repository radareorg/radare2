r_lang_sources = [
  'lang.c',
  # included in lang.c
  #'p/c.c',
  #'p/cpipe.c',
  #'p/lib.c',
  #'p/pipe.c',
  #'p/rust.c',
  #'p/vala.c'
  #'p/zig.c',
  #'p/spp.c',
]

spp_inc = [platform_inc, include_directories('../../shlr/spp')]

r_lang = library('r_lang', r_lang_sources,
  include_directories: [platform_inc, spp_inc],
  c_args: library_cflags,
  dependencies: [r_util_dep, r_cons_dep],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_lang_dep = declare_dependency(link_with: r_lang,
                                include_directories: [platform_inc])

pkgconfig_mod.generate(r_lang,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_lang',
  filebase: 'r_lang',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util',
    'r_cons'
  ],
  description: 'radare foundation libraries'
)
