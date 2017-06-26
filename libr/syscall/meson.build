files=[
'syscall.c',
'ioports.c'
]

if buildstatic == true
	r_syscall = static_library('r_syscall', files,
	  include_directories: [platform_inc],
	  link_with: [r_util],
	  objects: [
		libr2sdb.extract_all_objects()
	  ],
	  install: true
	)
else
	r_syscall = shared_library('r_syscall', files,
	  include_directories: [platform_inc],
	  link_with: [r_util],
	  objects: [
		libr2sdb.extract_all_objects()
	  ],
	  install: true
	)
endif