subdir('d')

r_arch_sources = [
  'arch.c',
  'arch_op.c',
  'arch_config.c',
  'arch_platform.c',
  'arch_switch.c',
  'arch_session.c',
  'arch_cond.c',
  'arch_value.c',
  'p/bf/plugin.c',
  'p/pic/plugin.c',
  'p/pic/pic_midrange.c',
  'p/pic/pic_baseline.c',
  'p/pic/pic_pic18.c',
  'p/chip8/plugin.c',
  'p/alpha/plugin.c',
  'p/alpha/alpha-dis.c',
  'p/alpha/alpha-opc.c',
  'p/bpf/plugin.c',
  'p/bpf_cs/plugin.c',
  'p/ppc/plugin_gnu.c',
  'p/ppc/gnu/ppc-dis.c',
  'p/ppc/gnu/ppc-opc.c',
  'p/ppc/libvle/vle.c',
  'p/stm8/plugin.c',
  'p/ppc/libps/libps.c',
  'p/ppc_cs/plugin.c',
  'p/null/plugin.c',
  'p/lm32/plugin.c',
  'p/s390/plugin.c',
  'p/mcs96/plugin.c',
  'p/lanai/plugin.c',
  'p/lanai/gnu/lanai-dis.c',
  'p/lanai/gnu/lanai-opc.c',
  'p/sparc/plugin_gnu.c',
  'p/sparc/gnu/sparc-dis.c',
  'p/sparc/gnu/sparc-opc.c',
  'p/sparc_cs/plugin.c',
  'p/s390_gnu/plugin.c',
  'p/s390_gnu/s390-dis.c',
  'p/s390_gnu/s390-opc.c',
  'p/m68k_gnu/plugin.c',
  'p/m68k_gnu/m68k-dis.c',
  'p/m68k_gnu/m68k-opc.c',
  'p/m68k_cs/plugin.c',
# 'p/m68k_cs/m68kass.c',
  'p/m680x_cs/plugin.c',
  'p/nds32/plugin.c',
  'p/arm/gnu/floatformat.c',
  'p/tms320/plugin.c',
  'p/tms320/tms320_dasm.c',
  'p/tms320/c55x_plus/ins.c',
  'p/tms320/c55x_plus/c55plus.c',
  'p/tms320/c55x_plus/c55plus_decode.c',
  'p/tms320/c55x_plus/decode_funcs.c',
  'p/tms320/c55x_plus/hashtable.c',
  'p/tms320/c55x_plus/utils.c',
  'p/java/plugin.c',
# fails on windows
# error LNK2005: SocketNotificationRetrieveEvents already defined in p_hppa_gnu_hppa-dis.c.obj
  'p/hppa/plugin_gnu.c',
  'p/hppa/gnu/hppa-dis.c',
  'p/dis/plugin.c',
  'p/evm/plugin.c',
  'p/propeller/plugin.c',
  'p/propeller/propeller_disas.c',
  'p/ws/plugin.c',
  'p/x86/plugin_cs.c',
  'p/arm/plugin.c',
  'p/arm/armass.c',
  'p/arm/armass64.c',
  'p/arm/plugin_cs.c',
  'p/arm/cs/arm.c',
  'p/arm/cs/arm64.c',

  'p/arm/plugin_gnu.c',
  'p/arm/winedbg/be_arm.c',
  'p/arm/gnu/arm-dis.c',
  'p/arm/aarch64/aarch64-dis.c',
  'p/arm/aarch64/aarch64-dis-2.c',
  'p/arm/aarch64/aarch64-opc.c',
  'p/arm/aarch64/aarch64-opc-2.c',

  'p/arc/plugin.c',
  'p/arc/gnu/arc-dis.c',
  'p/arc/gnu/arc-ext.c',
  'p/arc/gnu/arc-opc.c',
  'p/arc/gnu/arcompact-dis.c',

  'p/any_as/plugin.c',
  'p/any_vasm/plugin.c',
  'p/i4004/plugin.c',
  'p/z80/plugin.c',
  'p/amd29k/plugin.c',
  'p/jdh8/plugin.c',
  'p/kvx/plugin.c',
  'p/kvx/kvx-dis.c',
  'p/kvx/kvx-reg.c',
  'p/mcore/plugin.c',
  'p/mcore/mcore.c',
  'p/wasm/plugin.c',
  'p/rsp/plugin.c',
  'p/rsp/rsp_idec.c',
  'p/riscv/plugin.c',
  'p/riscv_cs/plugin.c',
  'p/xap/plugin.c',
  'p/6502/plugin.c',
  'p/6502_cs/plugin.c',
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
  'p/pdp11/plugin.c',
  'p/pdp11/pdp11-dis.c',
  'p/pdp11/pdp11-opc.c',
  'p/lh5801/plugin.c',
  'p/loongarch/plugin.c',
  'p/loongarch/loongarch-coder.c',
  'p/loongarch/loongarch-dis.c',
  'p/loongarch/loongarch-opc.c',
  'p/ebc/plugin.c',
  'p/ebc/ebc_disas.c',
  'p/msp430/plugin.c',
  'p/msp430/msp430_disas.c',
  'p/h8300/plugin.c',
  'p/h8300/h8300_disas.c',
  'p/xcore_cs/plugin.c',
  'p/mips/plugin_cs.c',
  'p/mips/mipsasm.c',
  'p/mips_gnu/plugin.c',
  'p/mips_gnu/mips-dis.c',
  'p/mips_gnu/mips16-opc.c',
  'p/mips_gnu/micromips-opc.c',
  'p/mips_gnu/mips-opc.c',
  'p/sh_cs/plugin.c',
  'p/sm5xx/plugin.c',
  'p/sm5xx/sm5xx.c',
  'p/tricore_cs/plugin.c',
  'p/i8080/i8080.c',
  'p/i8080/plugin.c',
  'p/gb/plugin.c',
  'p/avr/plugin.c',
  'p/avr/avr_disasm.c',
  'p/avr/format.c',
  'p/avr/disasm.c',
  'p/avr/assemble.c',
  'p/8051/plugin.c',
  'p/dalvik/plugin.c',
  'p/dalvik_ns/plugin.c',
  'p/fslsp/plugin.c',
]

if arch_plugins.contains('python') or arch_plugins.contains('pyc') or arch_plugins.contains('pickle')
  r_arch_sources += [
    # python
    'p/pyc/plugin.c',
    'p/pyc/opcode_all.c',
    'p/pyc/opcode_anal.c',
    'p/pyc/opcode_arg_fmt.c',
    'p/pyc/opcode.c',
    'p/pyc/pyc_dis.c',
    'p/pickle/plugin.c'
  ]
endif

if arch_plugins.contains('x86_nz')
  r_arch_sources += [
    'p/x86_nz/plugin.c'
  ]
endif

if arch_plugins.contains('xtensa')
r_arch_sources += [
  'p/xtensa/plugin.c',
  'p/xtensa/gnu/elf32-xtensa.c',
  'p/xtensa/gnu/xtensa-dis.c',
  'p/xtensa/gnu/xtensa-isa.c',
  'p/xtensa/gnu/xtensa-modules.c',
]
endif

deps =  [
    r_util_dep,
    r_esil_dep,
    r_reg_dep,
    r_muta_dep,
    java_dep,
    capstone_dep,
  ]

links = []
incs = [platform_inc]
if get_option('use_v35')
r_arch_sources += 'p/arm/plugin_v35.c'
binaryninja = subproject('binaryninja')
incs += binaryninja.get_variable('incs_arm64')
links += binaryninja.get_variable('libs_arm64').get_static_lib()
incs += binaryninja.get_variable('incs_armv7')
links += binaryninja.get_variable('libs_armv7').get_static_lib()
endif

# must be deleted when anal refactor is done

r_arch = library('r_arch', r_arch_sources,
  include_directories: [incs],
  c_args: library_cflags,
  dependencies: deps,
  link_with: links,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_arch_dep = declare_dependency(link_with: r_arch, include_directories: [incs])

if get_option('blob')
r_arch_static = static_library('r_arch_static', r_arch_sources,
  include_directories: [incs],
  c_args: library_cflags,
  dependencies: [
    r_util_static_dep,
    capstone_dep,
  ],
  install: true,
  implicit_include_directories: false,
)

r_arch_static_dep = declare_dependency(link_with: r_arch_static,
  include_directories: [incs])
endif

pkgconfig_mod.generate(r_arch,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_arch',
  filebase: 'r_arch',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util',
    'r_esil',
    'r_muta',
    'r_reg',
  ],
  description: 'radare foundation libraries'
)
