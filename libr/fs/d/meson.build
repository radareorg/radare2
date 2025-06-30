sdb_files = [
  'dospart'
]

# Build all sdb files at once using 'sdb -r .'
fs_sdb_files = []
foreach file : sdb_files
  fs_sdb_files += '@0@.sdb'.format(file)
  if get_option('sdb_cgen')
    fs_sdb_files += '@0@.c'.format(file)
  endif
endforeach

# Create environment with output directory set
sdb_env = environment()
sdb_env.set('SDB_OUTPUT_DIR', meson.current_build_dir())

r_fs_d_sources = custom_target('fs-sdb',
  input: [],
  output: fs_sdb_files,
  command: [sdb_exe, '-r', meson.current_source_dir()],
  env: sdb_env,
  depends: sdb_exe,
  build_by_default: true,
  install: true,
  install_dir: join_paths(r2_sdb, 'fs')
)