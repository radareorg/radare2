files=[
'arena.c',
'cond.c',
'double.c',
'profile.c',
'reg.c',
'value.c',
]

if buildstatic == true
	r_reg = static_library('r_reg', files,
	  include_directories: [platform_inc],
	  link_with: [r_util],
	  install: true
	)
else
	r_reg = shared_library('r_reg', files,
	  include_directories: [platform_inc],
	  link_with: [r_util],
	  install: true
	)
endif
