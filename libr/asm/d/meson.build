sdb_files = [
  '6502',
  '8051',
  'LH5801', ## todo lowercase
  'stm8',
  'arc',
  'arm',
  'avr',
  'bf',
  'bpf',
  'chip8',
  'dalvik',
  'evm',
  'gb',
  'i4004',
  'i8080',
  'java',
  'lm32',
  'm68k',
  'mips',
  'msp430',
  'pic18c',
  'pickle',
  'ppc',
  'propeller',
  'riscv',
  's390',
  'sh',
  'sparc',
  'tms320',
  'tricore',
  'v810',
  'v850',
  'x86',
  'xtensa',
  'z80',
]

# Build all sdb files at once using 'sdb -r .'
opcodes_sdb_files = []
foreach file : sdb_files
  opcodes_sdb_files += '@0@.sdb'.format(file)
  if get_option('sdb_cgen')
    opcodes_sdb_files += '@0@.c'.format(file)
  endif
endforeach

# Create opcodes directory in build dir
opcodes_build_dir = join_paths(meson.current_build_dir())

# Create environment with output directory set
sdb_env = environment()
sdb_env.set('SDB_OUTPUT_DIR', opcodes_build_dir)

r_asm_d_sources = custom_target('opcodes-sdb',
  input: [],
  output: opcodes_sdb_files,
  command: [sdb_exe, '-r', meson.current_source_dir()],
  env: sdb_env,
  depends: sdb_exe,
  build_by_default: true,
  install: true,
  install_dir: join_paths(r2_sdb, 'opcodes')
)
