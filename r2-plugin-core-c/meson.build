project('core-hello', 'c', license : 'MIT', meson_version : '>=1.00', version : '0.1.0')

r2_plugdir = run_command('r2', '-H', 'R2_USER_PLUGINS', check: true).stdout().strip()

sources = [ 'src/core_hello.c' ]
lib = library('corehello', sources,
	dependencies : [
		dependency('r_core')
	],
	install_dir: r2_plugdir,
	install: true
)
