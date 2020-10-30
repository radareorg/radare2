r_parse_sources = [
  'code.c',
  'filter.c',
  'parse.c',
  'ctype.c',
  'p/parse_6502_pseudo.c',
  'p/parse_arm_pseudo.c',
  'p/parse_att2intel.c',
  'p/parse_avr_pseudo.c',
  'p/parse_chip8_pseudo.c',
  'p/parse_dalvik_pseudo.c',
  'p/parse_m68k_pseudo.c',
  'p/parse_mips_pseudo.c',
  'p/parse_ppc_pseudo.c',
  'p/parse_sh_pseudo.c',
  'p/parse_tms320_pseudo.c',
  'p/parse_v850_pseudo.c',
  'p/parse_wasm_pseudo.c',
  'p/parse_x86_pseudo.c',
  'p/parse_riscv_pseudo.c',
  'p/parse_z80_pseudo.c'
]

r_parse = library('r_parse', r_parse_sources,
  include_directories: platform_inc,
  c_args: library_cflags,
  dependencies: [
    r_util_dep,
    r_flag_dep,
    r_syscall_dep,
    r_reg_dep,
    r_cons_dep,
    tcc_dep,
    mpc_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_parse_dep = declare_dependency(link_with: r_parse,
                                 include_directories: platform_inc)

pkgconfig_mod.generate(r_parse,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_parse',
  filebase: 'r_parse',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util',
    'r_flag',
    'r_cons',
    'r_syscall',
    'r_reg'
  ],
  description: 'radare foundation libraries'
)
