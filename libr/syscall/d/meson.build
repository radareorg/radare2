sdb_files = [
  'darwin-arm-32',
  'darwin-arm-64',
  'darwin-x86-32',
  'darwin-x86-64',
  'dos-x86-16',
  'freebsd-x86-32',
  'ios-arm-32',
  'ios-arm-64',
  'ios-x86-32',
  'linux-arm-32',
  'linux-arm-64',
  'linux-mips-32',
  'linux-sparc-32',
  'linux-x86-32',
  'linux-x86-64',
  'netbsd-x86-32',
  'openbsd-x86-32',
  'openbsd-x86-64',
  's110-arm-16',
  'windows-x86-32',
  'windows-x86-64',
]

# Build all SDB files at once using 'sdb -r -r .'
syscall_sdb_files = []
foreach file : sdb_files
  syscall_sdb_files += '@0@.sdb'.format(file)
  if get_option('sdb_cgen')
    syscall_sdb_files += '@0@.c'.format(file)
  endif
endforeach

# Create environment with output directory set
sdb_env = environment()
sdb_env.set('SDB_OUTPUT_DIR', meson.current_build_dir())

if host_machine.system() != 'uefi'
  r_syscall_d_sources = custom_target('syscall-sdb',
    input: [],
    output: syscall_sdb_files,
    command: [sdb_exe, '-r', '-r', meson.current_source_dir()],
    env: sdb_env,
    depends: sdb_exe,
    build_by_default: true,
    install: true,
    install_dir: join_paths(r2_sdb, 'syscall')
  )
else
  r_syscall_d_sources = []
endif

