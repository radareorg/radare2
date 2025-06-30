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

# Build all sdb files at once using 'sdb -r .'
charsets_sdb_files = []
foreach file : sdb_files
  charsets_sdb_files += '@0@.sdb'.format(file)
  if get_option('sdb_cgen')
    charsets_sdb_files += '@0@.c'.format(file)
  endif
endforeach

# Create environment with output directory set
sdb_env = environment()
sdb_env.set('SDB_OUTPUT_DIR', meson.current_build_dir())

r_util_d_sources = custom_target('charsets-sdb',
  input: [],
  output: charsets_sdb_files,
  command: [sdb_exe, '-r', meson.current_source_dir()],
  env: sdb_env,
  depends: sdb_exe,
  build_by_default: true,
  install: true,
  install_dir: join_paths(r2_sdb, 'charsets')
)
