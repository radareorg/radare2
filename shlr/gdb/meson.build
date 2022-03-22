# handle gdb dependency
gdb_files = [
  'src/arch.c',
  'src/common.c',
  'src/packet.c',
  'src/utils.c',
  'src/libgdbr.c',

  'src/gdbclient/core.c',
  'src/gdbclient/responses.c',
  'src/gdbclient/xml.c',

  'src/gdbserver/core.c',
]

gdb_inc = [
  platform_inc,
  include_directories(
    './include',
    './include/gdbclient',
    './include/gdbserver'
  )
]

libr2gdb = static_library('r2gdb', gdb_files,
  include_directories: gdb_inc,
  dependencies: [r_util_dep, r_cons_dep],
  implicit_include_directories: false
)

gdb_dep = declare_dependency(
  link_with: libr2gdb,
  include_directories: gdb_inc
)

if get_option('blob')
libr2gdb_static = static_library('r2gdb_static', gdb_files,
  include_directories: gdb_inc,
  dependencies: [r_util_static_dep, r_cons_static_dep],
  implicit_include_directories: false
)

gdb_static_dep = declare_dependency(
  link_with: libr2gdb_static,
  include_directories: gdb_inc
)
endif
