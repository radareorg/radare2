files=[
'http.c',
'http_server.c',
'proc.c',
'r2pipe.c',
'rap_server.c',
'run.c',
'socket.c',
]

r_socket = shared_library('r_socket', files,
  include_directories: include_directories([
  '../include',
  platform_librinc
  ]),
  dependencies: [utl],
  link_with: [r_util],
  c_args : '-DCORELIB=1',
  install: true
)
