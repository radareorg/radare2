project('sdb', 'c', meson_version: '>=0.47.0')
py3_exe = import('python').find_installation('python3')
pkgconfig_mod = import('pkgconfig')

version_cmd = '''from sys import argv
with open(argv[1]) as fd:
  for line in fd:
    if line.startswith('SDBVER='):
      version_tuple = line.split('=')[1]
      print(version_tuple)
      break
'''
sdb_version = '0.0.1'
config_mk = files('config.mk')[0]
r = run_command(py3_exe, '-c', version_cmd, config_mk)
if r.returncode() == 0
  sdb_version = r.stdout().strip()
else
  warning('Cannot determine SDB version')
endif
message('SDB version = ' + sdb_version)
sdb_libversion = host_machine.system() == 'windows' ? '' : sdb_version

# Create sdb_version.h
conf_data = configuration_data()
conf_data.set_quoted('SDB_VERSION', sdb_version, description : 'From config.mk')
configure_file(
  output : 'sdb_version.h',
  configuration : conf_data,
  install_dir : join_paths(get_option('includedir'), 'sdb')
)

libsdb_sources = [
  join_paths('src','array.c'),
  join_paths('src','set.c'),
  join_paths('src','base64.c'),
  join_paths('src','buffer.c'),
  join_paths('src','cdb.c'),
  join_paths('src','cdb_make.c'),
  join_paths('src','dict.c'),
  join_paths('src','diff.c'),
  join_paths('src','disk.c'),
  join_paths('src','fmt.c'),
  join_paths('src','ht_uu.c'),
  join_paths('src','ht_up.c'),
  join_paths('src','ht_pp.c'),
  join_paths('src','ht_pu.c'),
  join_paths('src','journal.c'),
  join_paths('src','json.c'),
  join_paths('src','lock.c'),
  join_paths('src','ls.c'),
  join_paths('src','match.c'),
  join_paths('src','ns.c'),
  join_paths('src','num.c'),
  join_paths('src','query.c'),
  join_paths('src','sdb.c'),
  join_paths('src','sdbht.c'),
  join_paths('src','util.c'),
  join_paths('src','text.c')
]

sdb_inc = include_directories(['.', 'src'])
rpath_lib = ''
rpath_exe = ''
if get_option('local') and get_option('default_library') == 'shared'
  rpath_lib = '$ORIGIN'
  rpath_exe = '$ORIGIN/../' + get_option('libdir')
endif

libsdb = both_libraries('sdb', libsdb_sources,
  include_directories: sdb_inc,
  implicit_include_directories: false,
  soversion: sdb_libversion,
  install: not meson.is_subproject(),
  install_rpath: rpath_lib
)

sdb_dep = declare_dependency(
  link_with: libsdb.get_static_lib(),
  include_directories: sdb_inc
)

if not meson.is_subproject()
  include_files = [
    join_paths('src','buffer.h'),
    join_paths('src','cdb.h'),
    join_paths('src','cdb_make.h'),
    join_paths('src','config.h'),
    join_paths('src','dict.h'),
    join_paths('src','ht_inc.h'),
    join_paths('src','ht_pp.h'),
    join_paths('src','ht_up.h'),
    join_paths('src','ht_uu.h'),
    join_paths('src','ht_up.h'),
    join_paths('src','ls.h'),
    join_paths('src','sdb.h'),
    join_paths('src','sdbht.h'),
    join_paths('src','set.h'),
    join_paths('src','types.h')
  ]
  install_headers(include_files, subdir: 'sdb')
endif

if host_machine.system() == 'windows'
  link_with = libsdb.get_static_lib()
else
  link_with = libsdb.get_shared_lib()
endif

sdb_exe = executable('sdb', join_paths('src','main.c'),
  include_directories: sdb_inc,
  link_with: [link_with],
  install: not meson.is_subproject(),
  install_rpath: rpath_exe,
  implicit_include_directories: false
)

if meson.is_cross_build()
  sdb_native_exe = executable('sdb_native', join_paths('src','main.c'),
    include_directories: sdb_inc,
    link_with: [link_with],
    install: false,
    implicit_include_directories: false
  )
else
  sdb_native_exe = sdb_exe
endif

if not meson.is_subproject()
  install_man([join_paths('src','sdb.1')])
endif

pkgconfig_mod.generate(
  name: 'sdb',
  filebase: 'sdb',
  libraries: [libsdb.get_shared_lib()],
  description: 'Simple DataBase',
  subdirs: ['sdb'],
  version: sdb_version,
  url: 'https://github.com/radareorg/sdb'
)

if not meson.is_subproject()
  make_exe = find_program('make', required: false)
  if make_exe.found()
    test('run tests', make_exe,
      args: 'test',
      env: ['BASEDIR=' + meson.current_build_dir()],
      workdir: join_paths(meson.current_build_dir(), '..'),
      depends: [sdb_exe, libsdb]
    )
  endif

  subdir(join_paths('test','bench'))
  subdir(join_paths('test','unit'))
endif
