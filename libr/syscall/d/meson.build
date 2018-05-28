sdb_files = [
  'dos-x86-16',
  'ios-x86-32',
  'ios-arm-32',
  'ios-arm-64',
  'linux-x86-32',
  'linux-x86-64',
  'linux-arm-32',
  'linux-arm-64',
  'linux-mips-32',
  'linux-sparc-32',
  'darwin-x86-32',
  'darwin-x86-64',
  'darwin-arm-32',
  'darwin-arm-64',
  'netbsd-x86-32',
  'freebsd-x86-32',
  'openbsd-x86-32',
  'openbsd-x86-64',
  'windows-x86-32',
  'windows-x86-64'
]

foreach file : sdb_files
  outfile = '@0@.sdb'.format(file)
  custom_target(outfile,
    input: '@0@.sdb.txt'.format(file),
    output: outfile,
    command: sdb_gen_cmd,
    depends: sdb_exe,
    build_by_default: true,
    build_always: false,
    install: true,
    install_dir: join_paths(r2_sdb, 'syscall')
  )
endforeach
