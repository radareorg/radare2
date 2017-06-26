files=[
'callback.c',
'config.c',
]

if buildstatic == true
	r_config = static_library('r_config', files,
	  include_directories: [platform_inc],
	  link_with: [r_util],
	  objects: [
		libr2sdb.extract_all_objects()
	  ],
	  install: true
	)
else
	r_config = shared_library('r_config', files,
	  include_directories: [platform_inc],
	  link_with: [r_util],
	  objects: [
		libr2sdb.extract_all_objects()
	  ],
	  install: true
	)
endif