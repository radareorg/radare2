project('qjs', 'c', meson_version : '>=0.60.0', version : '7e292050a21d3dd5076f70116ae95cc5200c40c1')

sources = [
  'cutils.c',
  'libbf.c',
  'libregexp.c',
  'libunicode.c',
  'quickjs.c',
]

incs = include_directories('.')

qjs_static = static_library(
  'qjs', sources,
  include_directories: incs
)

