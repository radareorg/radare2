r_lang_sources = [
  'lang.c'
]

spp_inc = [platform_inc, include_directories('../../shlr/spp')]
# qjs_inc = [ include_directories('../../shlr/qjs/src') ]
qjs_inc = '../../shlr/qjs/src'
r_lang_sources += '../../shlr/qjs/src/quickjs.c'
r_lang_sources += '../../shlr/qjs/src/libbf.c'
r_lang_sources += '../../shlr/qjs/src/cutils.c'
r_lang_sources += '../../shlr/qjs/src/libregexp.c'
r_lang_sources += '../../shlr/qjs/src/libunicode.c'

visibility_flags = [
  '-fvisibility=hidden',
  '-Dutf8_encode=utf8_encode_r2'
]

r_lang = library('r_lang', r_lang_sources,
  include_directories: [platform_inc, spp_inc, qjs_inc],
  gnu_symbol_visibility: 'hidden',
  c_args: library_cflags + visibility_flags,
  dependencies: [
    r_util_dep,
    r_io_dep,
    r_socket_dep,
    r_asm_dep,
    r_arch_dep,
    r_esil_dep,
    r_crypto_dep,
    r_cons_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_lang_dep = declare_dependency(link_with: r_lang, include_directories: [platform_inc, qjs_inc])

if get_option('blob')
r_lang_static = static_library('r_lang_static', r_lang_sources,
  include_directories: [platform_inc, spp_inc, qjs_inc],
  gnu_symbol_visibility: 'hidden',
  c_args: library_cflags + visibility_flags,
  dependencies: [
    r_util_static_dep,
    r_asm_static_dep,
    r_arch_static_dep,
    r_esil_static_dep,
    r_crypto_static_dep,
    r_cons_static_dep
  ],
  install: true,
  implicit_include_directories: false,
)

r_lang_static_dep = declare_dependency(link_with: r_lang_static,
  include_directories: [platform_inc, qjs_inc])
endif

pkgconfig_mod.generate(r_lang,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_lang',
  filebase: 'r_lang',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util',
    'r_asm',
    'r_crypto',
    'r_esil',
    'r_arch',
    'r_cons'
  ],
  description: 'radare foundation libraries'
)
