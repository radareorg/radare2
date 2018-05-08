subdir('p')

files = [
  'asm.c',
  'code.c',
  'arch/whitespace/wsdis.c',
]

r_asm = library('r_asm', files,
  include_directories: [
    platform_inc,
    include_directories(
      '../../shlr',
      'arch/include',
      'arch'
    )
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    r_util,
    r_syscall,
    r_parse,
    r_lang,
    r_flag,
    r_socket,
    r_asm_plugins,
    libr_shlr
  ],
  install: true,
  implicit_include_directories: false,
  soversion: r2_libversion
)

pkgconfig_mod.generate(
  libraries: [r_asm],
  subdirs: 'libr',
  version: r2_version,
  name: 'r_asm',
  filebase: 'r_asm',
  requires: [
    'r_util',
    'r_syscall',
    'r_parse',
    'r_lang',
    'r_flag',
    'r_socket'
  ],
  description: 'radare foundation libraries'
)
