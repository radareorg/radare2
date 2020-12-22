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
