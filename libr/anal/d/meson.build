sdb_files = [
  'types',
  'types-16',
  'types-32',
  'types-64',
  'types-windows',
  'types-x86-windows-32',
  'types-x86-windows-64',
  'types-linux',
  'types-x86-macos-64',
  'types-arm-ios-16',
  'types-arm-ios-32',
  'types-arm-ios-64',
  'spec',
  'cc-x86-64',
  'cc-x86-32',
  'cc-mips-32',
  'cc-m68k-32',
  'cc-sparc-32',
  'cc-arm-64',
  'cc-arm-32',
  'cc-avr-8',
  'cc-powerpc-32',
  'cc-powerpc-64',
  'cc-xtensa-32',
  'cc-riscv-64'
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
    install_dir: join_paths(r2_sdb, 'fcnsign')
  )
endforeach
