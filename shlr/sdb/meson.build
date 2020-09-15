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
  'src/array.c',
  'src/set.c',
  'src/base64.c',
  'src/buffer.c',
  'src/cdb.c',
  'src/cdb_make.c',
  'src/dict.c',
  'src/diff.c',
  'src/disk.c',
  'src/fmt.c',
  'src/ht_uu.c',
  'src/ht_pp.c',
  'src/ht_up.c',
  'src/journal.c',
  'src/json.c',
  #'src/json/api.c',
  #'src/json/indent.c',
  #'src/json/js0n.c',
  #'src/json/path.c',
  #'src/json/rangstr.c',
  'src/lock.c',
  'src/ls.c',
  'src/match.c',
  'src/ns.c',
  'src/num.c',
  'src/query.c',
  'src/sdb.c',
  'src/sdbht.c',
  'src/util.c',
]

sdb_inc = include_directories(['.', 'src'])

libsdb = both_libraries('sdb', libsdb_sources,
  include_directories: sdb_inc,
  implicit_include_directories: false,
  soversion: sdb_libversion,
  install: not meson.is_subproject()
)

if meson.is_subproject()
  sdb_dep = declare_dependency(
    link_with: libsdb.get_static_lib(),
    include_directories: sdb_inc
  )
else
  include_files = [
    'src/buffer.h',
    'src/cdb.h',
    'src/cdb_make.h',
    'src/config.h',
    'src/dict.h',
    'src/ht_inc.h',
    'src/ht_pp.h',
    'src/ht_up.h',
    'src/ht_uu.h',
    'src/ls.h',
    'src/sdb.h',
    'src/sdbht.h',
    'src/set.h',
    'src/types.h'
  ]
  install_headers(include_files, subdir: 'sdb')
endif

if host_machine.system() == 'windows'
  link_with = libsdb.get_static_lib()
else
  link_with = libsdb.get_shared_lib()
endif

sdb_exe = executable('sdb', 'src/main.c',
  include_directories: sdb_inc,
  link_with: [link_with],
  install: not meson.is_subproject(),
  implicit_include_directories: false
)

if not meson.is_subproject()
  install_man(['src/sdb.1'])
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

  subdir('test/bench')
endif
