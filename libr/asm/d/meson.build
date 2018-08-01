sdb_files = [
  '6502',
  '8051',
  'm68k',
  'x86',
  'arc',
  'arm',
  'avr',
  'LH5801',
  'ppc',
  'z80',
  'mips',
  'sparc',
  'sh',
  'malbolge',
  'xtensa',
  'i8080',
  'java',
  'i4004',
  'dalvik',
  'msp430',
  'lm32',
  'sysz',
  'tms320',
  'riscv',
  'propeller',
  'v810',
  'pic18c'
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
