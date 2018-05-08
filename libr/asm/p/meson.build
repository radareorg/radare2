asm_plugin_inc = [
  platform_inc,
  include_directories(
    '../../../shlr',
    '../arch/include',
    '../arch'
  )
]

asm_plugin_link_with = [
  r_flag,
  r_util
]

capstone_inc = include_directories('../../../shlr/capstone/include')

files = [
  'asm_6502.c',
  '../arch/6502/6502dis.c'
]

r_asm_plugin_6502 = static_library('r_asm_plugin_6502', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_8051.c',
  '../arch/8051/8051_disas.c'
]

r_asm_plugin_8051 = static_library('r_asm_plugin_8051', files,
  include_directories: [
    asm_plugin_inc,
    include_directories('../arch/8051')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_arc.c',
  '../arch/arc/gnu/arc-dis.c',
  '../arch/arc/gnu/arc-ext.c',
  '../arch/arc/gnu/arc-opc.c',
  '../arch/arc/gnu/arcompact-dis.c'
]

r_asm_plugin_arc = static_library('r_asm_plugin_arc', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_avr.c',
  #'../arch/avr/avr_disasm.c',
  #'../arch/avr/disasm.c'
]

r_asm_plugin_avr = static_library('r_asm_plugin_avr', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_arm_as.c']
r_asm_plugin_arm_as = static_library('r_asm_plugin_arm_as', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_arm_cs.c',
  '../arch/arm/armass.c',
  '../arch/arm/armass64.c'
]

r_asm_plugin_arm_cs = static_library('r_asm_plugin_arm_cs', files,
  include_directories: [
    asm_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    asm_plugin_link_with,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = [
  'asm_arm_gnu.c',
  '../arch/arm/aarch64/aarch64-dis-2.c',
  '../arch/arm/aarch64/aarch64-dis.c',
  '../arch/arm/aarch64/aarch64-opc-2.c',
  '../arch/arm/aarch64/aarch64-opc.c',
  '../arch/arm/gnu/arm-dis.c',
  '../arch/arm/gnu/floatformat.c'
]

r_asm_plugin_arm_gnu = static_library('r_asm_plugin_arm_gnu', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_arm_winedbg.c',
  '../arch/arm/winedbg/be_arm.c'
]

r_asm_plugin_arm_winedbg = static_library('r_asm_plugin_arm_winedbg', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_bf.c']

r_asm_plugin_bf = static_library('r_asm_plugin_bf', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_chip8.c']

r_asm_plugin_chip8 = static_library('r_asm_plugin_chip8', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_cr16.c',
  '../arch/cr16/cr16_disas.c'
]

r_asm_plugin_cr16 = static_library('r_asm_plugin_cr16', files,
  include_directories: [
    asm_plugin_inc,
    include_directories('../arch/cr16')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_cris_gnu.c',
  '../arch/cris/gnu/cris-dis.c',
  '../arch/cris/gnu/cris-opc.c'
]

r_asm_plugin_cris_gnu = static_library('r_asm_plugin_cris_gnu', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_dalvik.c']

r_asm_plugin_dalvik = static_library('r_asm_plugin_dalvik', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_dcpu16.c',
  #'../arch/dcpu16/asm.c',
  #'../arch/dcpu16/dis.c',
  #'../arch/dcpu16/main.c'
]

r_asm_plugin_dcpu16 = static_library('r_asm_plugin_dcpu16', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_gas.c']

r_asm_plugin_gas = static_library('r_asm_plugin_gas', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_gb.c',
  '../arch/gb/gbasm.c',
  '../arch/gb/gbdis.c'
]

r_asm_plugin_gb = static_library('r_asm_plugin_gb', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_ebc.c',
  '../arch/ebc/ebc_disas.c'
]

r_asm_plugin_ebc = static_library('r_asm_plugin_ebc', files,
  include_directories: [
    asm_plugin_inc,
    include_directories('../arch/ebc')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_h8300.c',
  '../arch/h8300/h8300_disas.c'
]

r_asm_plugin_h8300 = static_library('r_asm_plugin_h8300', files,
  include_directories: [
    asm_plugin_inc,
    include_directories('../arch/h8300')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_hexagon_gnu.c']

r_asm_plugin_hexagon_gnu = static_library('r_asm_plugin_hexagon_gnu', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_hexagon.c',
  '../arch/hexagon/hexagon.c',
  '../arch/hexagon/hexagon_disas.c',
]

r_asm_plugin_hexagon = static_library('r_asm_plugin_hexagon', files,
  include_directories: [
    asm_plugin_inc,
    include_directories('../arch/hexagon')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_hppa_gnu.c',
  '../arch/hppa/gnu/hppa-dis.c'
]

r_asm_plugin_hppa_gnu = static_library('r_asm_plugin_hppa_gnu', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_i4004.c',
  '../arch/i4004/i4004dis.c'
]

r_asm_plugin_i4004 = static_library('r_asm_plugin_i4004', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_i8080.c',
  '../arch/i8080/i8080dis.c'
]

r_asm_plugin_i8080 = static_library('r_asm_plugin_i8080', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_java.c']

r_asm_plugin_java = static_library('r_asm_plugin_java', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [
    asm_plugin_link_with,
    libr2java,
    libr2sdb
  ],
  implicit_include_directories: false
)

files = [
  'asm_lanai_gnu.c',
  '../arch/lanai/gnu/lanai-dis.c',
  '../arch/lanai/gnu/lanai-opc.c'
]

r_asm_plugin_lanai_gnu = static_library('r_asm_plugin_lanai_gnu', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_lh5801.c']

r_asm_plugin_lh5801 = static_library('r_asm_plugin_lh5801', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_lm32.c']

r_asm_plugin_lm32 = static_library('r_asm_plugin_lm32', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_m68k_cs.c']

r_asm_plugin_m68k_cs = static_library('r_asm_plugin_m68k_cs', files,
  include_directories: [
    asm_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    asm_plugin_link_with,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = ['asm_malbolge.c']

r_asm_plugin_malbolge = static_library('r_asm_plugin_malbolge', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_mcs96.c']

r_asm_plugin_mcs96 = static_library('r_asm_plugin_mcs96', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_mips_cs.c']

r_asm_plugin_mips_cs = static_library('r_asm_plugin_mips_cs', files,
  include_directories: [
    asm_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    asm_plugin_link_with,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = [
  'asm_mips_gnu.c',
  '../arch/mips/gnu/mips-dis.c',
  '../arch/mips/gnu/mips-opc.c',
  '../arch/mips/gnu/mips16-opc.c',
  '../arch/mips/mipsasm.c'
]

r_asm_plugin_mips_gnu = static_library('r_asm_plugin_mips_gnu', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_msp430.c',
  '../arch/msp430/msp430_disas.c'
]

r_asm_plugin_msp430 = static_library('r_asm_plugin_msp430', files,
  include_directories: [
    asm_plugin_inc,
    include_directories('../arch/msp430')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_nios2.c',
  '../arch/nios/gnu/nios2-dis.c',
  '../arch/nios/gnu/nios2-opc.c'
]

r_asm_plugin_nios2 = static_library('r_asm_plugin_nios2', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_pic.c',
  '../arch/pic/pic_baseline.c',
  '../arch/pic/pic_pic18.c'
]

r_asm_plugin_pic = static_library('r_asm_plugin_pic', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_ppc_cs.c',
  '../arch/ppc/libvle/vle.c',
  '../arch/ppc/libps/libps.c'
]

r_asm_plugin_ppc_cs = static_library('r_asm_plugin_ppc_cs', files,
  include_directories: [
    asm_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    asm_plugin_link_with,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = [
  'asm_ppc_gnu.c',
  '../arch/ppc/gnu/ppc-dis.c',
  '../arch/ppc/gnu/ppc-opc.c'
]

r_asm_plugin_ppc_gnu = static_library('r_asm_plugin_ppc_gnu', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_propeller.c',
  '../arch/propeller/propeller_disas.c'
]

r_asm_plugin_propeller = static_library('r_asm_plugin_propeller', files,
  include_directories: [
    asm_plugin_inc,
    include_directories('../arch/propeller')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_riscv.c',
  #'../arch/riscv/riscv-opc.c',
  #'../arch/riscv/riscv.c'
]

r_asm_plugin_riscv = static_library('r_asm_plugin_riscv', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_rsp.c',
  '../arch/rsp/rsp_idec.c'
]

r_asm_plugin_rsp = static_library('r_asm_plugin_rsp', files,
  include_directories: [
    asm_plugin_inc,
    include_directories('../arch/rsp')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_sh.c',
  '../arch/sh/gnu/sh-dis.c'
]

r_asm_plugin_sh = static_library('r_asm_plugin_sh', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_snes.c',
  '../arch/snes/snesdis.c'
]

r_asm_plugin_snes = static_library('r_asm_plugin_snes', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_sparc_cs.c']

r_asm_plugin_sparc_cs = static_library('r_asm_plugin_sparc_cs', files,
  include_directories: [
    asm_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    asm_plugin_link_with,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = [
  'asm_sparc_gnu.c',
  '../arch/sparc/gnu/sparc-dis.c',
  '../arch/sparc/gnu/sparc-opc.c'
]

r_asm_plugin_sparc_gnu = static_library('r_asm_plugin_sparc_gnu', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_spc700.c',
  '../arch/spc700/spc700dis.c'
]

r_asm_plugin_spc700 = static_library('r_asm_plugin_spc700', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_sysz.c']

r_asm_plugin_sysz = static_library('r_asm_plugin_sysz', files,
  include_directories: [
    asm_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_tms320.c',
  '../arch/tms320/c55x_plus/c55plus.c',
  '../arch/tms320/c55x_plus/c55plus_decode.c',
  '../arch/tms320/c55x_plus/decode_funcs.c',
  '../arch/tms320/c55x_plus/hashtable.c',
  '../arch/tms320/c55x_plus/hashvector.c',
  '../arch/tms320/c55x_plus/ins.c',
  '../arch/tms320/c55x_plus/utils.c',
  '../arch/tms320/tms320_dasm.c'
]

r_asm_plugin_tms320 = static_library('r_asm_plugin_tms320', files,
  include_directories: [
    asm_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    asm_plugin_link_with,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = [
  'asm_tricore.c',
  '../arch/tricore/gnu/cpu-tricore.c',
  '../arch/tricore/gnu/tricore-dis.c',
  '../arch/tricore/gnu/tricore-opc.c'
]

r_asm_plugin_tricore = static_library('r_asm_plugin_tricore', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_v810.c',
  '../arch/v810/v810_disas.c'
]

r_asm_plugin_v810 = static_library('r_asm_plugin_v810', files,
  include_directories: [
    asm_plugin_inc,
    include_directories('../arch/v810')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_v850.c',
  '../arch/v850/v850_disas.c'
]

r_asm_plugin_v850 = static_library('r_asm_plugin_v850', files,
  include_directories: [
    asm_plugin_inc,
    include_directories('../arch/v850')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_vax.c',
  '../arch/vax/vax-dis.c'
]

r_asm_plugin_vax = static_library('r_asm_plugin_vax', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_wasm.c',
  '../arch/wasm/wasm.c'
]

r_asm_plugin_wasm = static_library('r_asm_plugin_wasm', files,
  include_directories: [
    asm_plugin_inc,
    include_directories('../arch/wasm')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_ws.c']

r_asm_plugin_ws = static_library('r_asm_plugin_ws', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_x86_as.c']

r_asm_plugin_x86_as = static_library('r_asm_plugin_x86_as', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_x86_cs.c']

r_asm_plugin_x86_cs = static_library('r_asm_plugin_x86_cs', files,
  include_directories: [
    asm_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    asm_plugin_link_with,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = ['asm_x86_nasm.c']

r_asm_plugin_x86_nasm = static_library('r_asm_plugin_x86_nasm', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_x86_nz.c']

r_asm_plugin_x86_nz = static_library('r_asm_plugin_x86_nz', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_xap.c',
  '../arch/xap/dis.c'
]

r_asm_plugin_xap = static_library('r_asm_plugin_xap', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = ['asm_xcore_cs.c']

r_asm_plugin_xcore_cs = static_library('r_asm_plugin_xcore_cs', files,
  include_directories: [
    asm_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    asm_plugin_link_with,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = [
  'asm_xtensa.c',
  '../arch/xtensa/gnu/elf32-xtensa.c',
  '../arch/xtensa/gnu/xtensa-dis.c',
  '../arch/xtensa/gnu/xtensa-isa.c',
  '../arch/xtensa/gnu/xtensa-modules.c'
]

r_asm_plugin_xtensa = static_library('r_asm_plugin_xtensa', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

files = [
  'asm_z80.c',
  '../arch/z80/z80.c',
  #'../arch/z80/expressions.c',
  #'../arch/z80/z80asm.c'
]

r_asm_plugin_z80 = static_library('r_asm_plugin_z80', files,
  include_directories: [asm_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [asm_plugin_link_with],
  implicit_include_directories: false
)

r_asm_plugins = [
  r_asm_plugin_6502,
  r_asm_plugin_8051,
  r_asm_plugin_arc,
  r_asm_plugin_avr,
  r_asm_plugin_arm_as,
  r_asm_plugin_arm_cs,
  r_asm_plugin_arm_gnu,
  r_asm_plugin_arm_winedbg,
  r_asm_plugin_bf,
  r_asm_plugin_chip8,
  r_asm_plugin_cr16,
  r_asm_plugin_cris_gnu,
  r_asm_plugin_dalvik,
  r_asm_plugin_dcpu16,
  r_asm_plugin_gas,
  r_asm_plugin_gb,
  r_asm_plugin_ebc,
  r_asm_plugin_h8300,
  r_asm_plugin_hexagon_gnu,
  r_asm_plugin_hexagon,
  r_asm_plugin_hppa_gnu,
  r_asm_plugin_i4004,
  r_asm_plugin_i8080,
  r_asm_plugin_java,
  r_asm_plugin_lanai_gnu,
  r_asm_plugin_lh5801,
  r_asm_plugin_lm32,
  r_asm_plugin_m68k_cs,
  r_asm_plugin_malbolge,
  r_asm_plugin_mcs96,
  r_asm_plugin_mips_cs,
  r_asm_plugin_mips_gnu,
  r_asm_plugin_msp430,
  r_asm_plugin_nios2,
  r_asm_plugin_pic,
  r_asm_plugin_ppc_cs,
  r_asm_plugin_ppc_gnu,
  r_asm_plugin_propeller,
  r_asm_plugin_riscv,
  r_asm_plugin_rsp,
  r_asm_plugin_sh,
  r_asm_plugin_snes,
  r_asm_plugin_sparc_cs,
  r_asm_plugin_sparc_gnu,
  r_asm_plugin_spc700,
  r_asm_plugin_sysz,
  r_asm_plugin_tms320,
  r_asm_plugin_tricore,
  r_asm_plugin_v810,
  r_asm_plugin_v850,
  r_asm_plugin_vax,
  r_asm_plugin_wasm,
  r_asm_plugin_ws,
  r_asm_plugin_x86_as,
  r_asm_plugin_x86_cs,
  r_asm_plugin_x86_nasm,
  r_asm_plugin_x86_nz,
  r_asm_plugin_xap,
  r_asm_plugin_xcore_cs,
  r_asm_plugin_xtensa,
  r_asm_plugin_z80,
]
