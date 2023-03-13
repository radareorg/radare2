r_arch_sources = [
  'arch.c',
  'arch_op.c',
  'arch_config.c',
  'arch_switch.c',
  'arch_session.c',
  'arch_cond.c',
  'arch_value.c',
  'p/pic/plugin.c',
  'p/pic/pic_midrange.c',
  'p/pic/pic_baseline.c',
  'p/pic/pic_pic18.c',
  'p/alpha/plugin.c',
  'p/alpha/alpha-dis.c',
  'p/alpha/alpha-opc.c',
  'p/bpf/plugin.c',
  'p/bpf_cs/plugin.c',
  'p/null/plugin.c',
  'p/lm32/plugin.c',
  'p/mcs96/plugin.c',
  'p/xtensa/plugin.c',
  'p/lanai/plugin.c',
  'p/lanai/gnu/lanai-dis.c',
  'p/lanai/gnu/lanai-opc.c',
  'p/xtensa/gnu/elf32-xtensa.c',
  'p/xtensa/gnu/xtensa-dis.c',
  'p/xtensa/gnu/xtensa-isa.c',
  'p/xtensa/gnu/xtensa-modules.c',
  'p/dis/plugin.c',
  'p/evm/plugin.c',
  'p/propeller/plugin.c',
  'p/propeller/propeller_disas.c',
  'p/ws/plugin.c',
  'p/arm/plugin.c',
  'p/arm/armass.c',
  'p/arm/armass64.c',
  'p/any_as/plugin.c',
  'p/any_vasm/plugin.c',
  'p/i4004/plugin.c',
  'p/z80/plugin.c',
  'p/amd29k/plugin.c',
  'p/jdh8/plugin.c',
  'p/kvx/plugin.c',
  'p/kvx/kvx-dis.c',
  'p/kvx/kvx-reg.c',
  'p/pickle/plugin.c',
  'p/mcore/plugin.c',
  'p/mcore/mcore.c',
  'p/wasm/plugin.c',
  'p/rsp/plugin.c',
  'p/rsp/rsp_idec.c',
  'p/riscv/plugin.c',
  'p/riscv_cs/plugin.c',
  'p/xap/plugin.c',
  'p/6502/plugin.c',
  'p/snes/plugin.c',
  'p/sh/plugin.c',
  'p/sh/gnu/sh-dis.c',
  'p/v810/plugin.c',
  'p/v810/v810_disas.c',
  'p/v850/plugin.c',
  'p/v850/v850dis.c',
  'p/v850/v850e0.c',
  'p/or1k/plugin.c',
  'p/or1k/or1k_disas.c',
  'p/nios2/plugin.c',
  'p/nios2/nios2-opc.c',
  'p/nios2/nios2-dis.c',
  'p/vax/vax.c',
  'p/vax/vax-dis.c',
  'p/tricore/tricore.c',
  'p/tricore/gnu/cpu-tricore.c',
  'p/tricore/gnu/tricore-dis.c',
  'p/tricore/gnu/tricore-opc.c',
  'p/cris/plugin.c',
  'p/cris/gnu/cris-dis.c',
  'p/cris/gnu/cris-opc.c',
  'p/cr16/plugin.c',
  'p/cr16/cr16_disas.c',
]

if arch_plugins.contains('x86_nz')
  r_arch_sources += [
    'p/x86_nz/plugin.c'
  ]
endif

#if get_option('use_v35')
r_arch_sources += [
  join_paths('p/arm/plugin_v35.c'),
  join_paths('p/arm/v35/arch-arm64/disassembler/decode.c'),
  join_paths('p/arm/v35/arch-arm64/disassembler/decode0.c'),
  join_paths('p/arm/v35/arch-arm64/disassembler/decode1.c'),
  join_paths('p/arm/v35/arch-arm64/disassembler/decode2.c'),
  join_paths('p/arm/v35/arch-arm64/disassembler/decode_fields32.c'),
  join_paths('p/arm/v35/arch-arm64/disassembler/decode_scratchpad.c'),
  join_paths('p/arm/v35/arch-arm64/disassembler/encodings_dec.c'),
  join_paths('p/arm/v35/arch-arm64/disassembler/encodings_fmt.c'),
  join_paths('p/arm/v35/arch-arm64/disassembler/format.c'),
  join_paths('p/arm/v35/arch-arm64/disassembler/gofer.c'),
  join_paths('p/arm/v35/arch-arm64/disassembler/operations.c'),
  join_paths('p/arm/v35/arch-arm64/disassembler/pcode.c'),
  join_paths('p/arm/v35/arch-arm64/disassembler/regs.c'),
  join_paths('p/arm/v35/arch-arm64/disassembler/sysregs.c')
]
#incdirs += [
##  join_paths('p/arm/v35/arch-arm64/disassembler'),
#]
# endif
# must be deleted when anal refactor is done
arch_inc = include_directories('../asm/arch/include')

r_arch = library('r_arch', r_arch_sources,
  include_directories: [platform_inc, arch_inc],
  c_args: library_cflags,
  dependencies: [
    r_util_dep,
    r_reg_dep,
    capstone_dep,
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_arch_dep = declare_dependency(link_with: r_arch,
                              include_directories: [platform_inc])

if get_option('blob')
r_arch_static = static_library('r_arch_static', r_arch_sources,
  include_directories: [platform_inc, arch_inc],
  c_args: library_cflags,
  dependencies: [
    r_util_static_dep,
    capstone_dep,
  ],
  install: true,
  implicit_include_directories: false,
)

r_arch_static_dep = declare_dependency(link_with: r_arch_static,
  include_directories: [platform_inc])
endif

pkgconfig_mod.generate(r_arch,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_arch',
  filebase: 'r_arch',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util',
    'r_reg',
  ],
  description: 'radare foundation libraries'
)
