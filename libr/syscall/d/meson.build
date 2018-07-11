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

sdbtmp_gen_path = '@0@/@1@'.format(meson.current_source_dir(), 'gen.sh')
sdbtmp_gen_cmd = [
  py3_exe,
  '-c',
  'from sys import argv; __import__("os").system("@0@ <%s >%s" % (argv[1], argv[2]))'.format(sdbtmp_gen_path),
  '@INPUT@',
  '@OUTPUT@'
]

foreach file : sdb_files
  outfile_tmp = '@0@.sdb.txt.tmp'.format(file)
  outfile_tmp_dep = custom_target(outfile_tmp,
    input: '@0@.sdb.txt'.format(file),
    output: outfile_tmp,
    command: sdbtmp_gen_cmd,
    build_by_default: true,
    build_always: false,
    install: false
  )

  outfile = '@0@.sdb'.format(file)
  custom_target(outfile,
    input: [outfile_tmp_dep],
    output: outfile,
    command: sdb_gen_cmd,
    depends: sdb_exe,
    build_by_default: true,
    build_always: false,
    install: true,
    install_dir: join_paths(r2_sdb, 'syscall')
  )
endforeach
