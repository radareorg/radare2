
files=[
'flag.c',
'sort.c',
'spaces.c',
'zones.c'
]

if buildstatic == true
	r_flag = static_library('r_flag', files,
	  include_directories: [platform_inc],
	  link_with: [r_util],
	  objects: [
		libr2sdb.extract_all_objects()
	  ],  
	  install: true
	)
else
	r_flag = shared_library('r_flag', files,
	  include_directories: [platform_inc],
	  link_with: [r_util],
	  objects: [
		libr2sdb.extract_all_objects()
	  ],  
	  install: true
	)
endif
