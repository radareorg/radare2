files=[
	'bp.c',
	'bp_io.c',
	'bp_plugin.c',
	'bp_traptrace.c',
	'bp_watch.c',
	'p/bp_arm.c',
	'p/bp_bf.c',
	'p/bp_mips.c',
	'p/bp_ppc.c',
	'p/bp_sh.c',
	'p/bp_x86.c'
]

r_bp = shared_library('r_bp', files,
	include_directories: [platform_inc],
	c_args: ['-DCORELIB'],
	link_with: [r_util],
	install: true
)
