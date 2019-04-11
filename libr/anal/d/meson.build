sdb_files = [
  'cc-arm-32',
  'cc-arm-64',
  'cc-avr-8',
  'cc-m68k-32',
  'cc-mips-32',
  'cc-mips-64',
  'cc-powerpc-32',
  'cc-powerpc-64',
  'cc-riscv-64',
  'cc-sparc-32',
  'cc-x86-32',
  'cc-x86-64',
  'cc-xtensa-32',
  'spec',
  'types-16',
  'types-32',
  'types-64',
  'types-arm-ios-16',
  'types-arm-ios-32',
  'types-arm-ios-64',
  'types-android',
  'types-darwin',
  'types-linux',
  'types',
  'types-windows',
  'types-x86-macos-64',
  'types-x86-windows-32',
  'types-x86-windows-64'
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
