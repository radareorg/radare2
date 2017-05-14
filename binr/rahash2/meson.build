
executable('rahash2', 'rahash2.c',
  include_directories: include_directories([
    '../../libr/include',
	platform_binrinc
  ]),
  link_with: [r_util, r_hash, r_io, r_crypto],
  install: true
)
