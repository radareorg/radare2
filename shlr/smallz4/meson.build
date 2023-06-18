lz4_dep = dependency('liblz4', required: false)
if lz4_dep.found() and get_option('use_sys_lz4')
  message('Using system-provided lz4 library')
else
  message('Using smallz4')
  smallz4_files = [
    'smallz4cat.c',
    ]
  smallz4_inc = [include_directories('.')]

  libr2smallz4 = static_library('r2smallz4', smallz4_files,
    include_directories: smallz4_inc,
    implicit_include_directories: false
    )
  lz4_dep = declare_dependency(
    link_with: libr2smallz4,
    include_directories: smallz4_inc
    )
endif
