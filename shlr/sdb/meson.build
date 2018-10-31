project('sdb', 'c', meson_version: '>=0.46.0')
py3_exe = import('python3').find_python()

version_cmd = 'import sys; l=open("config.mk").read().split("\\n"); print(next(filter(lambda x: "SDBVER=" in x, l)).split("=")[1])'
sdb_version = run_command(py3_exe, '-c', version_cmd)
if sdb_version.returncode() == 0
  sdb_version = sdb_version.stdout().strip()
else
  sdb_version = '0.0.1'
endif
message('SDB version = ' + sdb_version)
sdb_libversion = host_machine.system() == 'windows' ? '' : sdb_version

sdb_platform_inc = []
if host_machine.system() == 'windows'
  sdb_platform_inc = include_directories('msvc')
endif

# Create sdb_version.h
sdb_version_path = join_paths(meson.current_build_dir(), 'sdb_version.h')
run_command(py3_exe, '-c', 'with open("@0@", "w") as f: f.write("#define SDB_VERSION \"@1@\"")'.format(sdb_version_path, sdb_version))

glob_cmd = [py3_exe, '-c', 'from sys import argv; print(";".join(__import__("glob").glob(argv[1])))']

files = [
  'src/array.c',
  'src/base64.c',
  'src/buffer.c',
  'src/cdb.c',
  'src/cdb_make.c',
  'src/dict.c',
  'src/disk.c',
  'src/fmt.c',
  'src/ht.c',
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

sdb_inc = [
  sdb_platform_inc,
  include_directories(['.', 'src'])
]

libsdb = both_libraries('sdb', files,
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
  include_files = run_command(glob_cmd + ['src/*.h']).stdout().strip().split(';') + [sdb_version_path]
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

sdb_gen_cmd = [
  py3_exe,
  '-c',
  'from sys import argv; __import__("os").system("@0@ %s = <%s" % (argv[1], argv[2]))'.format(sdb_exe.full_path()),
  '@OUTPUT@',
  '@INPUT@'
]

pkgconfig_mod = import('pkgconfig')
pkgconfig_mod.generate(
  libraries: [libsdb.get_shared_lib()],
  subdirs: ['sdb', '.'],
  version: sdb_version,
  name: 'sdb',
  filebase: 'sdb',
  description: 'Simple DataBase'
)

make_test_executable = find_program('make')
test('run tests', make_test_executable,
  args: 'test',
  env: ['BASEDIR=' + meson.current_build_dir()],
  workdir: join_paths(meson.current_build_dir(), '..'),
  depends: [sdb_exe, libsdb]
)
