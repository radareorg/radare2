files = [
  'callback.c',
  'config.c',
]

r_config = library('r_config', files,
  include_directories: [platform_inc],
  link_with: [r_util, libr_shlr],
  install: true,
  implicit_include_directories: false
)
