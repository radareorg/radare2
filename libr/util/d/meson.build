sdb_files = [
  'arabic_iso',
  'arabic_windows',
  'ascii',
  'ascii_ansi',
  'ascii_oem',
  'big5',
  'cyrillic_iso',
  'cyrillic_windows',
  'ebcdic37',
  'greek_iso',
  'greek_windows',
  'hebrew_iso',
  'hebrew_windows',
  'hiragana',
  'iso8859_1',
  'iso_646',
  'katakana',
  'macintosh',
  'pokered'
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
