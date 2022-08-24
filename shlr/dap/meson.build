dap_files = [
  'src/dap_client.c',
  'src/libdapr.c'
]

dap_inc = [
  platform_inc,
  include_directories(
    './include',
  )
]

libr2dap = static_library('r2dap', dap_files,
  include_directories: dap_inc,
  dependencies: [r_util_dep, r_cons_dep],
  implicit_include_directories: false
)

dap_dep = declare_dependency(
  link_with: libr2dap,
  include_directories: dap_inc
)

if get_option('blob')
libr2dap_static = static_library('r2dap_static', dap_files,
  include_directories: dap_inc,
  dependencies: [r_util_static_dep, r_cons_static_dep],
  implicit_include_directories: false
)

dap_static_dep = declare_dependency(
  link_with: libr2dap_static,
  include_directories: dap_inc
)
endif