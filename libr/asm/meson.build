subdir('d')

r_asm_sources = [
  'asm.c',
  'aop.c',
  'acode.c',
  'parse.c',
  'filter.c',
  'agperf.c',
  '../arch/p/pseudo/z80_pseudo.c',
  '../arch/p/pseudo/wasm_pseudo.c',
  '../arch/p/pseudo/v850_pseudo.c',
  '../arch/p/pseudo/tms320_pseudo.c',
  '../arch/p/pseudo/sh_pseudo.c',
  '../arch/p/pseudo/riscv_pseudo.c',
  '../arch/p/pseudo/ppc_pseudo.c',
  '../arch/p/pseudo/mips_pseudo.c',
  '../arch/p/pseudo/m68k_pseudo.c',
  '../arch/p/pseudo/evm_pseudo.c',
  '../arch/p/pseudo/dalvik_pseudo.c',
  '../arch/p/pseudo/chip8_pseudo.c',
  '../arch/p/pseudo/bpf_pseudo.c',
  '../arch/p/pseudo/6502_pseudo.c',
  '../arch/p/arm/pseudo.c',
  '../arch/p/x86_nz/pseudo.c',
  '../arch/p/pseudo/avr_pseudo.c',
  '../arch/p/pseudo/att2intel.c',
]

r_asm_inc = [
  platform_inc,
  include_directories(
    join_paths('../../shlr'),
  )
]

if get_option('sdb_cgen')
  r_asm_sources += r_asm_d_sources
endif

r_asm = library('r_asm', r_asm_sources,
  include_directories: r_asm_inc,
  c_args: library_cflags,
  dependencies: [
    r_util_dep,
    r_syscall_dep,
    r_arch_dep,
    r_reg_dep,
    r_flag_dep,
    r_socket_dep,
    r_esil_dep,
    r_crypto_dep,
    capstone_dep,
    java_dep,
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_asm_dep = declare_dependency(link_with: r_asm, include_directories: r_asm_inc)

if get_option('blob')
r_asm_static = static_library('r_asm_static', r_asm_sources,
  include_directories: r_asm_inc,
  c_args: library_cflags,
  dependencies: [
    r_util_static_dep,
    r_reg_static_dep,
    r_arch_static_dep,
    r_syscall_static_dep,
    r_flag_static_dep,
    r_socket_static_dep,
    r_esil_static_dep,
    r_crypto_static_dep,
    capstone_dep,
    java_static_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
)

r_asm_static_dep = declare_dependency(link_with: r_asm_static,
                               include_directories: r_asm_inc)
endif

pkgconfig_mod.generate(r_asm,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_asm',
  filebase: 'r_asm',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util',
    'r_syscall',
    'r_reg',
    'r_flag',
    'r_arch',
    'r_socket',
    'r_esil',
    'r_crypto',
  ],
  description: 'radare foundation libraries'
)
