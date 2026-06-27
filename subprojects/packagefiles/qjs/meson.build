project('qjs', 'c', meson_version : '>=0.60.0', version : '7e292050a21d3dd5076f70116ae95cc5200c40c1')

sources = [
  'libregexp.c',
  'libunicode.c',
  'quickjs.c',
  'dtoa.c'
]

incs = include_directories('.')

qjs_c_args = ['-DWIN32_LEAN_AND_MEAN', '-D_WIN32_WINNT=0x0602']

# Build qjs without inline assembly (see the cutils.h i386-fpcw-optout patch).
# Its only inline asm is the 32-bit x86 x87 FPU control-word macro, which on
# i386 (e.g. alpine-x86-32 / iSH) expands to a declaration right after a label
# and breaks the build. No-op on every other target.
qjs_c_args += ['-DJS_NO_INLINE_ASM']

visibility_flags = [
  '-fvisibility=hidden',
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

