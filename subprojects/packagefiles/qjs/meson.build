project('qjs', 'c', meson_version : '>=0.60.0', version : '7e292050a21d3dd5076f70116ae95cc5200c40c1')

sources = [
  'cutils.c',
  'libregexp.c',
  'libunicode.c',
  'quickjs.c',
  'xsum.c'
]

incs = include_directories('.')
visibility_flags = [
  '-fvisibility=hidden',
  '-Dutf8_encode=utf8_encode_r2'
]

qjs_static = static_library(
  'qjs', sources,
  gnu_symbol_visibility: 'hidden',
  c_args: visibility_flags,
  include_directories: incs
)


