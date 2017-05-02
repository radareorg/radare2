files=[
'callback.c',
'config.c',
]

r_config = shared_library('r_config', files,
  include_directories: include_directories(['../include']),
  link_with: [r_util],
  install: true
)
