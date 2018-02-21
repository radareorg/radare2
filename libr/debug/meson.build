files = [
  'arg.c',
  'ddesc.c',
  'debug.c',
  'dreg.c',
  'esil.c',
  'map.c',
  'p/bfvm.c',
  'p/debug_bf.c',
  #'p/debug_bochs.c',
  'p/debug_esil.c',
  'p/debug_gdb.c',
  'p/debug_io.c',
  'p/debug_native.c',
  #'p/debug_qnx.c',
  'p/debug_rap.c',
  'p/debug_windbg.c',
  #'p/native/arm.c',
  #'p/native/bt/fuzzy-all.c',
  #'p/native/bt/generic-x64.c',
  #'p/native/bt/generic-x86.c',
  #'p/native/bt.c',
  #'p/native/darwin.c',
  #'p/native/drx.c',
  #'p/native/maps/darwin.c',
  'pid.c',
  'plugin.c',
  'session.c',
  'signal.c',
  'snap.c',
  'trace.c',
]

if host_os == 'linux'
  files += [
    'p/native/linux/linux_debug.c',
    'p/native/linux/linux_coredump.c'
  ]
endif
if host_os != 'windows'
 files += [
  'p/native/procfs.c'
 ]
endif

if host_os == 'darwin'
  files += [
    'p/native/xnu/xnu_debug.c',
    #'p/native/xnu/trap_arm.c',
    #'p/native/xnu/trap_x86.c',
    #'p/native/xnu/xnu_excthreads.c',
    #'p/native/xnu/xnu_threads.c',
  ]
endif

r_debug = library('r_debug', files,
  include_directories: [
    platform_inc,
    include_directories([
      '../bin/format/elf',
      '../../shlr/gdb/include',
      '../../shlr/windbg'
    ])
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [
    r_util, r_hash, r_reg, r_syscall, r_anal, r_flag, r_io, r_bp, r_search,
    r_cons, r_lang, r_egg, r_socket, libr_shlr
  ],
  install: true,
  implicit_include_directories: false
)
