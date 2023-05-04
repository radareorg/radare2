subdir('d')

r_anal_sources = [
  'anal.c',
  'anplugs.c',
  'bb.c',
  'block.c',
  'function.c',
  'jmptbl.c',
  'cc.c',
  'class.c',
  'tid.c',
  'cond.c',
  'cparse.c',
  'codemeta.c',
  'cycles.c',
  'data.c',
  'diff.c',
  'esil_cfg.c',
  'esil_dfg.c',
  'fcn.c',
  'flirt.c',
  'global.c',
  'hint.c',
  'labels.c',
  'meta.c',
  'op.c',
  'pin.c',
  'reflines.c',
  'rtti.c',
  'rtti_msvc.c',
  'rtti_itanium.c',
  'sign.c',
  'switch.c',
  'type.c',
  'type_pdb.c',
  'dwarf_process.c',
  'value.c',
  'var.c',
  'vtable.c',
  'xrefs.c',
  '../arch/p/6502_cs/plugin.c',
  'p/anal_8051.c',

  'p/anal_arm_cs.c',
  'p/anal_arm_gnu.c',
  'p/anal_avr.c',
  'p/anal_dalvik.c',
  '../arch/p/ebc/plugin.c',
  '../arch/p/ebc/ebc_disas.c',
  'p/anal_gb.c',
  '../arch/p/h8300/plugin.c',
  '../arch/p/h8300/h8300_disas.c',
  'p/anal_java.c',
  '../arch/p/lh5801/plugin.c',
  '../arch/p/m68k_cs/plugin.c',
  '../arch/p/m680x_cs/plugin.c',
  '../arch/p/m68k_gnu/plugin.c',
  '../arch/p/m68k_gnu/m68k-dis.c',
  '../arch/p/m68k_gnu/m68k-opc.c',
  'p/anal_mips_cs.c',
  '../asm/arch/mips/mipsasm.c',
  '../asm/arch/mips/gnu/mips-dis.c',
  '../asm/arch/mips/gnu/mips16-opc.c',
  '../asm/arch/mips/gnu/micromips-opc.c',
  '../asm/arch/mips/gnu/mips-opc.c',
  'p/anal_mips_gnu.c',
  '../arch/p/loongarch/plugin.c',
  '../arch/p/loongarch/loongarch-coder.c',
  '../arch/p/loongarch/loongarch-dis.c',
  '../arch/p/loongarch/loongarch-opc.c',
  'p/anal_null.c',
  'p/anal_ppc_cs.c',
  'p/anal_sparc_cs.c',
  'p/anal_tms320.c',
  # join_paths('arch/whitespace/wsdis.c'),
  'p/anal_x86_cs.c',
  '../arch/p/xcore_cs/plugin.c',
  #join_paths('arch','gb','meta_gb_cmt.c'),
  '../arch/p/msp430/plugin.c',
  '../arch/p/msp430/msp430_disas.c',
  '../asm/arch/amd29k/amd29k.c',
  '../arch/p/arm/winedbg/be_arm.c',
  '../arch/p/arm/gnu/floatformat.c',
  '../arch/p/arm/gnu/arm-dis.c',
  '../arch/p/arm/aarch64/aarch64-dis.c',
  '../arch/p/arm/aarch64/aarch64-dis-2.c',
  '../arch/p/arm/aarch64/aarch64-opc.c',
  '../arch/p/arm/aarch64/aarch64-opc-2.c',
  '../asm/arch/avr/avr_disasm.c',
  '../asm/arch/avr/format.c',
  '../asm/arch/avr/disasm.c',
  '../asm/arch/avr/assemble.c',
  '../arch/p/ppc/libvle/vle.c',
  '../arch/p/ppc/libps/libps.c',
  '../asm/arch/tms320/tms320_dasm.c',
  '../asm/arch/tms320/c55x_plus/ins.c',
  '../asm/arch/tms320/c55x_plus/c55plus.c',
  '../asm/arch/tms320/c55x_plus/c55plus_decode.c',
  '../asm/arch/tms320/c55x_plus/decode_funcs.c',
  '../asm/arch/tms320/c55x_plus/hashtable.c',
  '../asm/arch/tms320/c55x_plus/utils.c',
]
incdirs = [
    'arch'
]

r_anal_sources += r_anal_d_sources

# tcc
tcc_files = [
  'c/libtcc.c',
  'c/tccgen.c',
  'c/tccpp.c'
]

r_anal_inc = [
  platform_inc,
  include_directories(incdirs)
]

r_anal = library('r_anal', r_anal_sources,
  include_directories: r_anal_inc,
  c_args: library_cflags,
  dependencies: [
    r_util_dep,
    r_reg_dep,
    r_asm_dep,
    r_arch_dep,
    r_esil_dep,
    r_crypto_dep,
    r_search_dep,
    r_cons_dep,
    r_syscall_dep,
    r_flag_dep,
    java_dep,
    capstone_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_anal_dep = declare_dependency(link_with: r_anal,
  include_directories: r_anal_inc)

if get_option('blob')
r_anal_static = static_library('r_anal_static', r_anal_sources,
  include_directories: r_anal_inc,
  c_args: library_cflags,
  dependencies: [
    capstone_dep,
    java_static_dep,
    r_arch_static_dep,
    r_asm_static_dep,
    r_cons_static_dep,
    r_crypto_static_dep,
    r_esil_static_dep,
    r_flag_static_dep,
    r_reg_static_dep,
    r_search_static_dep,
    r_syscall_static_dep,
    r_util_static_dep,
  ],
  install: true,
  implicit_include_directories: false,
)

r_anal_static_dep = declare_dependency(link_with: r_anal_static,
  include_directories: r_anal_inc)
endif

pkgconfig_mod.generate(r_anal,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_anal',
  filebase: 'r_anal',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util',
    'r_reg',
    'r_asm',
    'r_crypto',
    'r_syscall',
    'r_arch',
    'r_search',
    'r_cons',
    'r_flag'
  ],
  description: 'radare foundation libraries'
)
