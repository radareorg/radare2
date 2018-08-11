sdb_version = '1.0.0'

sdb_platform_inc = []
if host_machine.system() == 'windows'
  sdb_platform_inc = include_directories('msvc')
endif

# Create sdb_version.h
run_command(py3_exe, '-c', 'with open("src/sdb_version.h", "w") as f: f.write("#define SDB_VERSION \"' + sdb_version + '\"")')

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
  'src/json/js0n.c',
  'src/json/path.c',
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

libsdb = static_library('sdb', files,
  include_directories: [
    platform_inc,
    include_directories([
      'src'
    ])
  ],
  implicit_include_directories: false
)

sdb_exe = executable('sdb', 'src/main.c',
  include_directories: [
    sdb_platform_inc,
    include_directories([
      'src'
    ])
  ],
  link_with: [libsdb],
  install: true,
  implicit_include_directories: false
)

sdb_gen_cmd = [
  py3_exe,
  '-c',
  'from sys import argv; __import__("os").system("@0@ %s = <%s" % (argv[1], argv[2]))'.format(sdb_exe.full_path()),
  '@OUTPUT@',
  '@INPUT@'
]
