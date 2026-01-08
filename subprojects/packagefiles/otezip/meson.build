project('otezip', 'c',
  version : '0.2.0',
  default_options : ['c_std=c99', 'warning_level=2'])

otezip_src = files('src/lib/otezip.c')
otezip_inc = include_directories('src/include')

otezip_lib = static_library('otezip',
  otezip_src,
  include_directories: otezip_inc,
  install: false
)

otezip_dep = declare_dependency(
  link_with: otezip_lib,
  include_directories: otezip_inc
)

# For subproject usage
otezip_subproject = true