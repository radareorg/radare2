files=[
'callback.c',
'config.c',
]

r_config = shared_library('r_config', files,
  include_directories: include_directories([
  '../include',
  platform_librinc
  ]),
  link_with: [r_util],
  objects: [
    r_sdb.extract_all_objects()
  ],
  install: true
)
