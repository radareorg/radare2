files=[
'arena.c',
'cond.c',
'double.c',
'profile.c',
'reg.c',
'value.c',
]

r_reg = shared_library('r_reg', files,
  include_directories: [platform_inc],
  link_with: [r_util],
  install: true
)

