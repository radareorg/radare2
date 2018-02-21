project('sdb', 'c')
version = '1.0.0'

if host_machine.system() == 'windows'
  platform_inc = include_directories(['.', './msvc'])
else
  platform_inc = include_directories(['.'])
endif

# Create sdb_version.h
run_command('python', '-c', 'with open("src/sdb_version.h", "w") as f: f.write("#define SDB_VERSION \"' + version + '\"")')

files = [
  'src/array.c',
  'src/base64.c',
  'src/buffer.c',
  'src/cdb.c',
  'src/cdb_make.c',
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

executable('sdb', 'src/main.c',
  include_directories: [
    platform_inc,
    include_directories([
      'src'
    ])
  ],
  link_with: [libsdb],
  install: true,
  implicit_include_directories: false
)
