files = [
  'code.c',
  'parse.c',
  'p/parse_6502_pseudo.c',
  'p/parse_arm_pseudo.c',
  'p/parse_att2intel.c',
  'p/parse_avr_pseudo.c',
  'p/parse_dalvik_pseudo.c',
  'p/parse_m68k_pseudo.c',
  'p/parse_mips_pseudo.c',
  'p/parse_mreplace.c',
  'p/parse_ppc_pseudo.c',
  'p/parse_sh_pseudo.c',
  'p/parse_x86_pseudo.c',
  'p/parse_z80_pseudo.c',
  'p/parse_mreplace/mreplace.c',
  'p/parse_mreplace/mmemory.c'
]

r_parse = library('r_parse', files,
  include_directories: platform_inc,
  c_args: library_cflags,
  dependencies: [
    r_util_dep,
    r_flag_dep,
    r_syscall_dep,
    r_reg_dep,
    sdb_dep,
    tcc_dep
  ],
  install: true,
  implicit_include_directories: false,
  soversion: r2_libversion
)

r_parse_dep = declare_dependency(link_with: r_parse,
                                 include_directories: platform_inc)

pkgconfig_mod.generate(
  libraries: [r_parse],
  subdirs: 'libr',
  version: r2_version,
  name: 'r_parse',
  filebase: 'r_parse',
  requires: [
    'r_util',
    'r_flag',
    'r_syscall',
    'r_reg'
  ],
  description: 'radare foundation libraries'
)
