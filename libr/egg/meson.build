files=[
'egg.c',
'egg_lang.c',
'emit_arm.c',
'emit_trace.c',
'emit_x64.c',
'emit_x86.c',

#'p/egg_bind.c',
#'p/egg_cb.c',
'p/egg_exec.c',
#'p/egg_reverse.c',
#'p/egg_shya.c',
'p/egg_xor.c'
]
r_egg = library('r_egg', files,
  include_directories: [platform_inc],
  c_args : ['-DCORELIB=1', '-I' + meson.current_build_dir() + '/../..'],
  link_with: [r_util, r_asm, r_syscall],
  objects: [
	libr2sdb.extract_all_objects(),
  ],
  install: true
)
