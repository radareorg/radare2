sdb_files = [
  'pokered',
  'ebcdic37',
  'ascii'
]

d_pokered_c = custom_target(
  'pokered.c',
  output: 'pokered.c',
  command: sdb_gen_cmd_cgen,
  input: 'pokered.sdb.txt',
  depends: sdb_exe,
  build_by_default: true,
)

d_ascii_c = custom_target(
  'ascii.c',
  output: 'ascii.c',
  command: sdb_gen_cmd_cgen,
  input: 'ascii.sdb.txt',
  depends: sdb_exe,
  build_by_default: true,
)

d_ebcdic37_c = custom_target(
  'ebcdic37.c',
  output: 'ebcdic37.c',
  command: sdb_gen_cmd_cgen,
  input: 'ebcdic37.sdb.txt',
  depends: sdb_exe,
  build_by_default: true,
)

if not get_option('sdb_cgen')
  foreach file : sdb_files
    if get_option('sdb_cgen')
      outfile = '@0@.c'.format(file)
      gen_cmd = sdb_gen_cmd_cgen
    else
      outfile = '@0@.sdb'.format(file)
      gen_cmd = sdb_gen_cmd
    endif
    infiles = ['@0@.sdb.txt'.format(file)]
    custom_target(outfile,
      input: infiles,
      output: outfile,
      command: gen_cmd,
      depends: sdb_exe,
      build_by_default: true,
      install: true,
      install_dir: join_paths(r2_sdb, 'charsets')
    )
  endforeach
endif
