tags_r2_sources = [
  'dylib',
  'alloc',
  'time',
  'env',
  'fs',
  'network',
  'threads',
  'process',
  'stdout',
  'string'
]

custom_target('tags.r2',
  input: tags_r2_sources,
  output: 'tags.r2',
  command: [py3_exe, join_paths(meson.current_source_dir(),'tags.py'), '@INPUT@'],
  capture: true,
  build_by_default: true,
  install: true,
  install_dir: r2_flags
)
