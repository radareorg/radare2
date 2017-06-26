files=[
'apprentice.c',
'ascmagic.c',
'fsmagic.c',
'funcs.c',
'is_tar.c',
'magic.c',
# XXX not used? 'print.c',
'softmagic.c'
]
if buildstatic == true
	r_magic = static_library('r_magic', files,
	  include_directories: [platform_inc],
	  c_args: ['-DCORELIB'],
	  link_with: [r_util],
	  install: true
	)
else
	r_magic = shared_library('r_magic', files,
	  include_directories: [platform_inc],
	  c_args: ['-DCORELIB'],
	  link_with: [r_util],
	  install: true
	)
endif