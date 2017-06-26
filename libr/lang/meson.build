files=[
'lang.c',
'p/c.c',
# 'p/cpipe.c',
'p/lib.c',
'p/pipe.c',
'p/rust.c',
'p/vala.c'
]

if buildstatic == true
	r_lang = static_library('r_lang', files,
	  include_directories: [platform_inc],
	  c_args: ['-DCORELIB'],
	  link_with: [r_util, r_cons],
	  install: true
	)
else
	r_lang = shared_library('r_lang', files,
	  include_directories: [platform_inc],
	  c_args: ['-DCORELIB'],
	  link_with: [r_util, r_cons],
	  install: true
	)
endif
