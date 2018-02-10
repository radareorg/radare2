files = [
  'code.c',
  'parse.c',
  'p/parse_6502_pseudo.c',
  'p/parse_arm_pseudo.c',
  'p/parse_att2intel.c',
  'p/parse_dalvik_pseudo.c',
  'p/parse_m68k_pseudo.c',
  'p/parse_mips_pseudo.c',
  'p/parse_mreplace.c',
  'p/parse_ppc_pseudo.c',
  'p/parse_x86_pseudo.c',
  'p/parse_z80_pseudo.c',
  'p/parse_sh_pseudo.c',
  'p/parse_avr_pseudo.c',
  'p/parse_mreplace/mreplace.c',
  'p/parse_mreplace/mmemory.c'
]

r_parse = library('r_parse', files,
  include_directories: [
    platform_inc,
    include_directories([
      '../../shlr/tcc',
    ])
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [r_util, r_flag, r_syscall, r_reg, libr_shlr],
  install: true,
  implicit_include_directories: false
)
