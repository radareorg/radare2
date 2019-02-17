r_socket_sources = [
  'http.c',
  'http_server.c',
  'proc.c',
  'r2pipe.c',
  'rap_server.c',
  'run.c',
  'socket.c',
  'serial.c',
]

dependencies = [utl, r_util_dep, platform_deps]

if use_sys_openssl
  dependencies += [sys_openssl]
endif

r_socket = library('r_socket', r_socket_sources,
  include_directories: [platform_inc],
  dependencies: dependencies,
  c_args: library_cflags,
  install: true,
  implicit_include_directories: false,
  soversion: r2_libversion
)

r_socket_dep = declare_dependency(link_with: r_socket,
                                  include_directories: [platform_inc])

pkgconfig_mod.generate(r_socket,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_socket',
  filebase: 'r_socket',
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
