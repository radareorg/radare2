project('qjs', 'c', meson_version : '>=0.60.0', version : '7e292050a21d3dd5076f70116ae95cc5200c40c1')

cc = meson.get_compiler('c')

sources = [
  'libregexp.c',
  'libunicode.c',
  'quickjs.c',
  'dtoa.c'
]

incs = include_directories('.')

qjs_c_args = ['-DWIN32_LEAN_AND_MEAN', '-D_WIN32_WINNT=0x0602']
if cc.get_argument_syntax() == 'msvc'
  # QuickJS intentionally mixes integer and floating point values in several
  # places, so keep those conversions quiet on MSVC.
  qjs_c_args += ['/wd4244', '/wd4146']
endif

visibility_flags = [
  '-Dutf8_encode=utf8_encode_r2'
]
if host_machine.system() == 'android'
  visibility_flags += ['-Dinline=', '-Wno-unused-function']
endif

qjs_static = static_library(
  'qjs', sources,
  gnu_symbol_visibility: 'hidden',
  c_args: visibility_flags + qjs_c_args,
  include_directories: incs
)
