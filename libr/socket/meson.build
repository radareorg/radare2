files = [
  'http.c',
  'http_server.c',
  'proc.c',
  'r2pipe.c',
  'rap_server.c',
  'run.c',
  'socket.c',
  'serial.c',
]

r_socket = library('r_socket', files,
  include_directories: [platform_inc],
  dependencies: [utl, platform_deps],
  link_with: [r_util],
  c_args: ['-DCORELIB=1'],
  install: true,
  implicit_include_directories: false,
  soversion: r2_libversion
)

pkgconfig_mod.generate(
  libraries: [r_socket],
  subdirs: 'libr',
  version: r2_version,
  name: 'r_socket',
  filebase: 'r_socket',
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
