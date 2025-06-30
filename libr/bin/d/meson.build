subdir('dll')

r_bin_d_sources = []
if get_option('sdb_cgen')
  r_bin_d_sources += r_bin_d_dll_sources
endif

# Build format SDB files
sdb_files = [ 'symclass' ]

# Build all format SDB files at once using 'sdb -r .'
format_sdb_files = []
foreach file : sdb_files
  format_sdb_files += '@0@.sdb'.format(file)
  if get_option('sdb_cgen')
    format_sdb_files += '@0@.c'.format(file)
  endif
endforeach

# Create environment with output directory set
format_sdb_env = environment()
format_sdb_env.set('SDB_OUTPUT_DIR', meson.current_build_dir())

r_bin_d_format_sources = custom_target('format-sdb',
  input: [],
  output: format_sdb_files,
  command: [sdb_exe, '-r', meson.current_source_dir()],
  env: format_sdb_env,
  depends: sdb_exe,
  build_by_default: true,
  install: true,
  install_dir: join_paths(r2_sdb, join_paths('format'))
)

if get_option('sdb_cgen')
  r_bin_d_sources += r_bin_d_format_sources
endif

format_files = [
  'cdex.h',
  'dex.h',
  'jni.h',
  'bios.r2',
  'dex.r2',
  'elf32.r2',
  'elf64.r2',
  'elf_enums.r2',
  'fatmacho.r2',
  'macho.r2',
  'mz.r2',
  'ntfs.r2',
  'pe32.r2',
  'trx.r2',
  'zip.r2',
]

install_data(format_files,
  install_dir: join_paths(r2_sdb, 'format')
)
