sdb_files = [
  'pokered',
  'ascii'
]

foreach file : sdb_files
  outfile = '@0@.sdb'.format(file)
  infiles = ['@0@.sdb.txt'.format(file)]
  custom_target(outfile,
    input: infiles,
    output: outfile,
    command: sdb_gen_cmd,
    depends: sdb_exe,
    build_by_default: true,
    install: true,
    install_dir: join_paths(r2_sdb, 'charsets')
  )
endforeach
