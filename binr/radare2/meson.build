executable('radare2', 'radare2.c',
  include_directories: include_directories([
    '../../libr/include',
	platform_binrinc
  ]),
  link_with: [r_util, r_socket, r_core],
  install: true
)
