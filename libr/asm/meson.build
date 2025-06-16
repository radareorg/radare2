subdir('d')

r_asm_sources = [
  'asm.c',
  'aop.c',
  'acode.c',
  'parse.c',
  'filter.c',
  'agperf.c',
  '../arch/p/null/pseudo.c',
  '../arch/p/tricore/pseudo.c',
  '../arch/p/z80/pseudo.c',
  '../arch/p/cosmac/pseudo.c',
  '../arch/p/gb/pseudo.c',
  '../arch/p/wasm/pseudo.c',
  '../arch/p/v850/pseudo.c',
  '../arch/p/tms320/pseudo.c',
  '../arch/p/java/pseudo.c',
  '../arch/p/sh/pseudo.c',
  '../arch/p/riscv/pseudo.c',
  '../arch/p/ppc/pseudo.c',
  '../arch/p/mips/pseudo.c',
  '../arch/p/sparc/pseudo.c',
  '../arch/p/m68k_cs/pseudo.c',
  '../arch/p/evm/pseudo.c',
  '../arch/p/dalvik/pseudo.c',
  '../arch/p/chip8/pseudo.c',
  '../arch/p/bpf/pseudo.c',
  '../arch/p/6502/pseudo.c',
  '../arch/p/arm/pseudo.c',
  '../arch/p/x86_nz/pseudo.c',
  '../arch/p/x86_nz/att2intel.c',
  '../arch/p/avr/pseudo.c',
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
    r_muta_dep,
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
    r_muta_static_dep,
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
    'r_muta',
  ],
  description: 'radare foundation libraries'
)
