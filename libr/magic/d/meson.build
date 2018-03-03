#FIXME: replace it after meson 0.45.0 release
#install_subdir('default',
#  install_dir: join_paths(get_option('prefix'), get_option('datadir'), 'radare2', r2version, 'magic'),
#  split_directory: true
#)

magic_files = run_command('python', '-c', 'print(";".join(__import__("glob").glob("default/*")))').stdout().strip().split(';')
install_data(magic_files,
  install_dir: join_paths(get_option('datadir'), 'radare2', r2version, 'magic')
)