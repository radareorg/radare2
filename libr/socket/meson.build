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

r_socket_deps = [r_util_dep, platform_deps]
if get_option('blob')
  r_socket_static_deps = [r_util_static_dep, platform_deps]
  if use_sys_openssl
    r_socket_static_deps += [sys_openssl]
  endif
endif

if host_machine.system() == 'haiku'
  r_socket_deps += [
    cc.find_library('network')
  ]
endif

if use_sys_openssl
  r_socket_deps += [sys_openssl]
endif

r_socket = library('r_socket', r_socket_sources,
  include_directories: [platform_inc],
  dependencies: r_socket_deps,
  c_args: library_cflags,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_socket_dep = declare_dependency(link_with: r_socket, dependencies: r_socket_deps, include_directories: [platform_inc])

if get_option('blob')
r_socket_static = static_library('r_socket_static', r_socket_sources,
  include_directories: [platform_inc],
  dependencies: r_socket_static_deps,
  c_args: library_cflags,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
)

r_socket_static_dep = declare_dependency(link_with: r_socket_static, include_directories: [platform_inc])
endif

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
