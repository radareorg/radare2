r_debug_sources = [
  'arg.c',
  'ddesc.c',
  'debug.c',
  'dreg.c',
  'desil.c',
  'dmap.c',
  'pid.c',
  'plugin.c',
  'dsession.c',
  'dsignal.c',
  'snap.c',
  'trace.c',
  'p/bfvm.c',
  'p/debug_bf.c',
  'p/debug_bochs.c',
  'p/debug_esil.c',
  'p/debug_gdb.c',
  'p/debug_io.c',
  'p/debug_native.c',
  'p/debug_null.c',
  'p/debug_qnx.c',
  'p/debug_rap.c',
  'p/debug_winkd.c',
  #'p/native/arm.c',
  #'p/native/bt/fuzzy-all.c',
  #'p/native/bt/generic-x64.c',
  #'p/native/bt/generic-x86.c',
  #'p/native/bt.c',
  #'p/native/darwin.c',
  #'p/native/drx.c',
  #'p/native/maps/darwin.c',
]

r_debug_deps = [
  r_util_dep,
  r_hash_dep,
  r_reg_dep,
  r_syscall_dep,
  r_anal_dep,
  r_flag_dep,
  r_io_dep,
  r_bp_dep,
  r_search_dep,
  r_cons_dep,
  r_lang_dep,
  r_egg_dep,
  winkd_dep,
  qnx_dep,
  gdb_dep,
  bochs_dep,
  r_socket_dep
]

if host_machine.system() == 'linux' or host_machine.system() == 'android'
  r_debug_sources += ['p/native/linux/linux_debug.c']
endif
if host_machine.system() == 'linux'
  r_debug_sources += ['p/native/linux/linux_coredump.c']
endif

if host_machine.system() == 'windows'
  r_debug_sources += [
    'p/debug_windbg.c',
    'p/native/maps/windows_maps.c',
    'p/native/windows/windows_debug.c',
    'p/native/windows/windows_message.c',
  ]
  r_debug_deps += w32dbg_wrap_dep
endif

if host_machine.system() != 'windows'
  r_debug_sources += [
    'p/native/procfs.c'
  ]
endif

if host_machine.system() == 'darwin'
  r_debug_sources += [
    'p/native/xnu/xnu_debug.c',
    #'p/native/xnu/trap_arm.c',
    #'p/native/xnu/trap_x86.c',
    #'p/native/xnu/xnu_excthreads.c',
    #'p/native/xnu/xnu_threads.c',
  ]
endif

if ['netbsd', 'openbsd', 'freebsd', 'dragonfly'].contains(host_machine.system())
  r_debug_deps += cc.find_library('kvm', required: true)
  r_debug_sources += [
    'p/native/bsd/bsd_debug.c',
  ]
endif

r_debug_inc = [
  platform_inc,
  include_directories(
    '../bin/format/elf'
  )
]

r_debug = library('r_debug', r_debug_sources,
  include_directories: r_debug_inc,
  c_args: library_cflags,
  dependencies: r_debug_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_debug_dep = declare_dependency(link_with: r_debug,
                                 include_directories: r_debug_inc)

pkgconfig_mod.generate(r_debug,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_debug',
  filebase: 'r_debug',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util',
    'r_hash',
    'r_reg',
    'r_syscall',
    'r_anal',
    'r_flag',
    'r_io',
    'r_bp',
    'r_search',
    'r_cons',
    'r_lang',
    'r_egg',
    'r_socket'
  ],
  description: 'radare foundation libraries'
)
