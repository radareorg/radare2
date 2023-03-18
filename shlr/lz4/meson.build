lz4_dep = dependency('liblz4', required: false)
if lz4_dep.found() and get_option('use_sys_lz4')
  message('Using system-provided lz4 library')
elif not get_option('use_smallz4')
  message('Using bundled lz4')
  lz4_files = [
    'lz4.c',
  ]

  lz4_inc = [platform_inc, include_directories('.')]

  libr2lz4 = static_library('r2lz4', lz4_files,
    include_directories: lz4_inc,
    implicit_include_directories: false
  )

  lz4_dep = declare_dependency(
    link_with: libr2lz4,
    include_directories: lz4_inc
  )
else
  message('But using smallz4 instead')
endif
