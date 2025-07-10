# modified wrapdb and rizin version

project(
  'zlib',
  'c',
  version: '1.3.1',
  license: 'zlib',
  meson_version: '>=0.49.0',
)

cc = meson.get_compiler('c')

if cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

link_args = []
if host_machine.system() not in ['windows', 'darwin']
  link_args = cc.get_supported_link_arguments(
    '-Wl,--version-script,@0@/zlib.map'.format(meson.current_source_dir()),
  )
endif

compile_args = []

if cc.get_argument_syntax() == 'msvc'
  compile_args += ['-D_CRT_SECURE_NO_DEPRECATE', '-D_CRT_NONSTDC_NO_DEPRECATE']
endif

if cc.has_header('unistd.h')
  compile_args += '-DHAVE_UNISTD_H'
endif

if cc.has_header('stdarg.h')
  compile_args += '-DHAVE_STDARG_H'
endif

# add_project_arguments('-D_LARGEFILE64_SOURCE', language: 'c')

src = files([
  'adler32.c',
  'crc32.c',
  'deflate.c',
  'infback.c',
  'inffast.c',
  'inflate.c',
  'inftrees.c',
  'trees.c',
  'zutil.c',
  'compress.c',
  'uncompr.c',
  'gzclose.c',
  'gzlib.c',
  'gzread.c',
  'gzwrite.c'
])

headers = files(['zconf.h', 'zlib.h'])

if host_machine.system() == 'windows'
  compile_args += '-DWINDOWS'
  win = import('windows')
  win_args = []
  if cc.get_argument_syntax() != 'msvc'
    win_args += '-DGCC_WINDRES'
  endif
  src += win.compile_resources('win32/zlib1.rc', args: win_args)
endif

zlib = library(
  'z',
  src,
  c_args: compile_args,
  vs_module_defs : 'win32/zlib.def',
  link_args: link_args
)

depinc = include_directories('.')
zlib_dep = declare_dependency(
  link_with: zlib,
  include_directories: depinc,
)

