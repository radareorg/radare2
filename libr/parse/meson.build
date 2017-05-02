files=[
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
'p/parse_mreplace/mreplace.c',
'p/parse_mreplace/mmemory.c'
]

tcc = static_library('tcc', [
'../../shlr/tcc/libtcc.c',
'../../shlr/tcc/tccgen.c',
'../../shlr/tcc/tccpp.c'
],
include_directories: include_directories(['../include', '../../shlr/tcc']),
)

r_parse = shared_library('r_parse', files,
  include_directories: include_directories(['../include', '../../shlr/tcc']),
  c_args: ['-DCORELIB'],
  link_with: [r_util, r_flag, r_syscall, r_reg, tcc],
  install: true
)

