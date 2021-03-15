r_socket_sources = [
  'socket.c',
  'socket_http.c',
  'socket_http_server.c',
  'socket_serial.c',
  'socket_proc.c',
  'r2pipe.c',
  'socket_rap_client.c',
  'socket_rap_server.c',
  'run.c',
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
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_socket_dep = declare_dependency(link_with: r_socket,
  dependencies: [r_util_dep],
  include_directories: [platform_inc])

pkgconfig_mod.generate(r_socket,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_socket',
  filebase: 'r_socket',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
