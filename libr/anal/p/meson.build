anal_plugin_inc = [
  platform_inc,
  include_directories(
    '../arch'
  )
]

anal_plugin_link_with = [
  r_reg,
  r_util
]

capstone_inc = include_directories('../../../shlr/capstone/include')

files = ['anal_6502.c']

r_anal_plugin_6502 = static_library('r_anal_plugin_6502', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_8051.c']

r_anal_plugin_8051 = static_library('r_anal_plugin_8051', files,
  include_directories: [
    anal_plugin_inc,
    include_directories('../../asm/arch/8051')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    #r_asm_plugin_8051
  ],
  implicit_include_directories: false
)

files = ['anal_arc.c']

r_anal_plugin_arc = static_library('r_anal_plugin_arc', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_arm_cs.c']

r_anal_plugin_arm_cs = static_library('r_anal_plugin_arm_cs', files,
  include_directories: [
    anal_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = ['anal_arm_gnu.c']

r_anal_plugin_arm_gnu = static_library('r_anal_plugin_arm_gnu', files,
  include_directories: [
    anal_plugin_inc,
    include_directories('../../asm/arch/include')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    r_asm_plugin_arm_winedbg
  ],
  implicit_include_directories: false
)

files = ['anal_avr.c']

r_anal_plugin_avr = static_library('r_anal_plugin_avr', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_bf.c']

r_anal_plugin_bf = static_library('r_anal_plugin_bf', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_chip8.c']

r_anal_plugin_chip8 = static_library('r_anal_plugin_chip8', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_cr16.c']

r_anal_plugin_cr16 = static_library('r_anal_plugin_cr16', files,
  include_directories: [
    anal_plugin_inc,
    include_directories('../../asm/arch/cr16')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    r_asm_plugin_cr16
  ],
  implicit_include_directories: false
)

files = ['anal_cris.c']

r_anal_plugin_cris = static_library('r_anal_plugin_cris', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_dalvik.c']

r_anal_plugin_dalvik = static_library('r_anal_plugin_dalvik', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_ebc.c']

r_anal_plugin_ebc = static_library('r_anal_plugin_ebc', files,
  include_directories: [
    anal_plugin_inc,
    include_directories('../../asm/arch/ebc')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    r_asm_plugin_ebc
  ],
  implicit_include_directories: false
)

files = [
  'anal_gb.c',
  #'../arch/gb/meta_gb_cmt.c'
]

r_anal_plugin_gb = static_library('r_anal_plugin_gb', files,
  include_directories: [
    anal_plugin_inc,
    include_directories('../arch/gb')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_h8300.c']

r_anal_plugin_h8300 = static_library('r_anal_plugin_h8300', files,
  include_directories: [
    anal_plugin_inc,
    include_directories('../../asm/arch/h8300')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    r_asm_plugin_h8300
  ],
  implicit_include_directories: false
)

files = [
  'anal_hexagon.c',
  '../arch/hexagon/hexagon_anal.c'
]

r_anal_plugin_hexagon = static_library('r_anal_plugin_hexagon', files,
  include_directories: [
    anal_plugin_inc,
    include_directories('../arch/hexagon'),
    include_directories('../../asm/arch/hexagon')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    r_asm_plugin_hexagon
  ],
  implicit_include_directories: false
)

files = ['anal_i4004.c']

r_anal_plugin_i4004 = static_library('r_anal_plugin_i4004', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_i8080.c']

r_anal_plugin_i8080 = static_library('r_anal_plugin_i8080', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_java.c']

r_anal_plugin_java = static_library('r_anal_plugin_java', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    libr2java,
    libr2sdb
  ],
  implicit_include_directories: false
)

files = ['anal_m68k_cs.c']

r_anal_plugin_m68k_cs = static_library('r_anal_plugin_m68k_cs', files,
  include_directories: [
    anal_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = ['anal_malbolge.c']

r_anal_plugin_malbolge = static_library('r_anal_plugin_malbolge', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_mips_cs.c']

r_anal_plugin_mips_cs = static_library('r_anal_plugin_mips_cs', files,
  include_directories: [
    anal_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = ['anal_mips_gnu.c']

r_anal_plugin_mips_gnu = static_library('r_anal_plugin_mips_gnu', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_msp430.c']

r_anal_plugin_msp430 = static_library('r_anal_plugin_msp430', files,
  include_directories: [
    anal_plugin_inc,
    include_directories('../../asm/arch/msp430')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    r_asm_plugin_msp430
  ],
  implicit_include_directories: false
)

files = ['anal_nios2.c']

r_anal_plugin_nios2 = static_library('r_anal_plugin_nios2', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_null.c']

r_anal_plugin_null = static_library('r_anal_plugin_null', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_pic.c']

r_anal_plugin_pic = static_library('r_anal_plugin_pic', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_ppc_cs.c']

r_anal_plugin_ppc_cs = static_library('r_anal_plugin_ppc_cs', files,
  include_directories: [
    anal_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    libr2capstone,
    r_asm_plugin_ppc_cs
  ],
  implicit_include_directories: false
)

files = ['anal_ppc_gnu.c']

r_anal_plugin_ppc_gnu = static_library('r_anal_plugin_ppc_gnu', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_propeller.c']

r_anal_plugin_propeller = static_library('r_anal_plugin_propeller', files,
  include_directories: [
    anal_plugin_inc,
    include_directories('../../asm/arch/propeller')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    r_asm_plugin_propeller
  ],
  implicit_include_directories: false
)

files = ['anal_riscv.c']

r_anal_plugin_riscv = static_library('r_anal_plugin_riscv', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_rsp.c']

r_anal_plugin_rsp = static_library('r_anal_plugin_rsp', files,
  include_directories: [
    anal_plugin_inc,
    include_directories('../../asm/arch/rsp')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    r_asm_plugin_rsp
  ],
  implicit_include_directories: false
)

files = ['anal_sh.c']

r_anal_plugin_sh = static_library('r_anal_plugin_sh', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_snes.c']

r_anal_plugin_snes = static_library('r_anal_plugin_snes', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_sparc_cs.c']

r_anal_plugin_sparc_cs = static_library('r_anal_plugin_sparc_cs', files,
  include_directories: [
    anal_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = ['anal_sparc_gnu.c']

r_anal_plugin_sparc_gnu = static_library('r_anal_plugin_sparc_gnu', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_sysz.c']

r_anal_plugin_sysz = static_library('r_anal_plugin_sysz', files,
  include_directories: [
    anal_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = [
  'anal_tms320.c',
  'anal_tms320_c55x_plus.c'
]

r_anal_plugin_tms320 = static_library('r_anal_plugin_tms320', files,
  include_directories: [
    anal_plugin_inc,
    capstone_inc,
    include_directories('../../asm/arch/tms320')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    r_asm_plugin_tms320,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = ['anal_tms320c64x.c']

r_anal_plugin_tms320c64x = static_library('r_anal_plugin_tms320c64x', files,
  include_directories: [
    anal_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = ['anal_vax.c']

r_anal_plugin_vax = static_library('r_anal_plugin_vax', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_v810.c']

r_anal_plugin_v810 = static_library('r_anal_plugin_v810', files,
  include_directories: [
    anal_plugin_inc,
    include_directories('../../asm/arch/v810')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    r_asm_plugin_v810
  ],
  implicit_include_directories: false
)

files = ['anal_v850.c']

r_anal_plugin_v850 = static_library('r_anal_plugin_v850', files,
  include_directories: [
    anal_plugin_inc,
    include_directories('../../asm/arch/v850')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    r_asm_plugin_v850
  ],
  implicit_include_directories: false
)

files = ['anal_wasm.c']

r_anal_plugin_wasm = static_library('r_anal_plugin_wasm', files,
  include_directories: [
    anal_plugin_inc,
    include_directories('../../asm/arch/wasm')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_ws.c']

r_anal_plugin_ws = static_library('r_anal_plugin_ws', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_x86_cs.c']

r_anal_plugin_x86_cs = static_library('r_anal_plugin_x86_cs', files,
  include_directories: [
    anal_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = ['anal_xap.c']

r_anal_plugin_xap = static_library('r_anal_plugin_xap', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

files = ['anal_xcore_cs.c']

r_anal_plugin_xcore_cs = static_library('r_anal_plugin_xcore_cs', files,
  include_directories: [
    anal_plugin_inc,
    capstone_inc
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    libr2capstone
  ],
  implicit_include_directories: false
)

files = ['anal_xtensa.c']

r_anal_plugin_xtensa = static_library('r_anal_plugin_xtensa', files,
  include_directories: [
    anal_plugin_inc,
    include_directories('../../asm/arch/include')
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    anal_plugin_link_with,
    r_asm_plugin_xtensa
  ],
  implicit_include_directories: false
)

files = ['anal_z80.c']

r_anal_plugin_z80 = static_library('r_anal_plugin_z80', files,
  include_directories: [anal_plugin_inc],
  c_args: ['-DCORELIB=1'],
  link_with: [anal_plugin_link_with],
  implicit_include_directories: false
)

r_anal_plugins = [
  r_anal_plugin_6502,
  r_anal_plugin_8051,
  r_anal_plugin_arc,
  r_anal_plugin_arm_cs,
  r_anal_plugin_arm_gnu,
  r_anal_plugin_avr,
  r_anal_plugin_bf,
  r_anal_plugin_chip8,
  r_anal_plugin_cr16,
  r_anal_plugin_cris,
  r_anal_plugin_dalvik,
  r_anal_plugin_ebc,
  r_anal_plugin_gb,
  r_anal_plugin_h8300,
  r_anal_plugin_hexagon,
  r_anal_plugin_i4004,
  r_anal_plugin_i8080,
  r_anal_plugin_java,
  r_anal_plugin_m68k_cs,
  r_anal_plugin_malbolge,
  r_anal_plugin_mips_cs,
  r_anal_plugin_mips_gnu,
  r_anal_plugin_msp430,
  r_anal_plugin_nios2,
  r_anal_plugin_null,
  r_anal_plugin_pic,
  r_anal_plugin_ppc_cs,
  r_anal_plugin_ppc_gnu,
  r_anal_plugin_propeller,
  r_anal_plugin_riscv,
  r_anal_plugin_rsp,
  r_anal_plugin_sh,
  r_anal_plugin_snes,
  r_anal_plugin_sparc_cs,
  r_anal_plugin_sparc_gnu,
  r_anal_plugin_sysz,
  r_anal_plugin_tms320,
  r_anal_plugin_tms320c64x,
  r_anal_plugin_vax,
  r_anal_plugin_v810,
  r_anal_plugin_v850,
  r_anal_plugin_wasm,
  r_anal_plugin_ws,
  r_anal_plugin_x86_cs,
  r_anal_plugin_xap,
  r_anal_plugin_xcore_cs,
  r_anal_plugin_xtensa,
  r_anal_plugin_z80
]
