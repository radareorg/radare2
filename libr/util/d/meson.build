sdb_files = [
  'pokered',
  'ebcdic37',
  'ascii',
  'iso8859_1'
]

r_util_d_sources = []

foreach file : sdb_files
  if get_option('sdb_cgen')
    outfile = '@0@.c'.format(file)
    gen_cmd = sdb_gen_cmd_cgen
  else
    outfile = '@0@.sdb'.format(file)
    gen_cmd = sdb_gen_cmd
  endif
  infiles = ['@0@.sdb.txt'.format(file)]
  r_util_d_sources += custom_target(outfile,
    input: infiles,
    output: outfile,
    command: gen_cmd,
    depends: sdb_exe,
    build_by_default: true,
    install: true,
    install_dir: join_paths(r2_sdb, 'charsets')
  )
endforeach
