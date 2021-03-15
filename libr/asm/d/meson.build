sdb_files = [
  '6502',
  '8051',
  'arc',
  'arm',
  'avr',
  'dalvik',
  'i4004',
  'i8080',
  'java',
  'LH5801',
  'lm32',
  'm68k',
  'malbolge',
  'mips',
  'msp430',
  'pic18c',
  'ppc',
  'propeller',
  'riscv',
  'sh',
  'sparc',
  'sysz',
  'tms320',
  'tricore',
  'v810',
  'v850',
  'x86',
  'xtensa',
  'z80',
]

foreach file : sdb_files
  outfile = '@0@.sdb'.format(file)
  custom_target(outfile,
    input: '@0@.sdb.txt'.format(file),
    output: outfile,
    command: sdb_gen_cmd,
    depends: sdb_exe,
    build_by_default: true,
    install: true,
    install_dir: join_paths(r2_sdb, 'opcodes')
  )
endforeach
