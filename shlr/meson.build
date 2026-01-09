# handle capstone dependency
capstone_dep = dependency('capstone', version: '>=4.0.0', required: false)
if capstone_dep.found() and get_option('use_sys_capstone')
  message('Use system-provided capstone library')
else
  if get_option('capstone_in_builddir')
    capstone_path = join_paths(meson.current_build_dir(), 'capstone')
  else
    capstone_path = join_paths(meson.project_source_root(), 'subprojects/capstone-' + capstone_version)
  endif

  message('capstone path:' + capstone_path)
  capstone_version = get_option('use_capstone_version')
  message('Use bundled capstone: ' + capstone_version)

  fs = import('fs')
  if fs.is_file('../subprojects/capstone-' + capstone_version + '.wrap')
    cs = subproject('capstone-' + capstone_version)
  else
    error('Wrong capstone version selected. Please use one of the supported versions.')
  endif

  capstone_dep = cs.get_variable('capstone_dep')
endif

# handle bochs dependency
bochs_files = [
  join_paths('bochs','src','libbochs.c')
]

bochs_inc = [platform_inc, include_directories(join_paths('bochs','include'))]

libr2bochs = static_library('r2bochs', bochs_files,
  dependencies: [r_util_dep],
  include_directories: bochs_inc,
  implicit_include_directories: false
)

bochs_dep = declare_dependency(
  link_with: libr2bochs,
  include_directories: bochs_inc
)

if get_option('blob')
libr2bochs_static = static_library('r2bochs_static', bochs_files,
  dependencies: [r_util_static_dep],
  include_directories: bochs_inc,
  implicit_include_directories: false
)
bochs_static_dep = declare_dependency(
  link_with: libr2bochs_static,
  include_directories: bochs_inc
)
endif


# handle java dependency
java_files = [
  'java/class.c',
  'java/code.c',
  'java/ops.c',
  #'java/main.c',
]

java_inc = [platform_inc, include_directories('java')]

libr2java = static_library('r2java', java_files,
  dependencies: [r_util_dep],
  include_directories: java_inc,
  implicit_include_directories: false
)

java_dep = declare_dependency(
  link_with: libr2java,
  include_directories: java_inc
)

if get_option('blob')
libr2java_static = static_library('r2java_static', java_files,
  dependencies: [r_util_static_dep],
  include_directories: java_inc,
  implicit_include_directories: false
)

java_static_dep = declare_dependency(
  link_with: libr2java_static,
  include_directories: java_inc
)
endif

# handle qnx dependency
qnx_files = [
  'qnx/src/core.c',
  'qnx/src/libqnxr.c',
  'qnx/src/packet.c',
  'qnx/src/sigutil.c',
  'qnx/src/utils.c',
]

qnx_inc = [platform_inc, libsdb_includes, include_directories('qnx/include')]

libr2qnx = static_library('r2qnx', qnx_files,
  dependencies: [r_socket_dep],
  include_directories: qnx_inc,
  implicit_include_directories: false
)

qnx_dep = declare_dependency(
  link_with: libr2qnx,
  include_directories: qnx_inc
)

if get_option('blob')
libr2qnx_static = static_library('r2qnx_static', qnx_files,
  dependencies: [r_socket_static_dep],
  include_directories: qnx_inc,
  implicit_include_directories: false
)

qnx_static_dep = declare_dependency(
  link_with: libr2qnx_static,
  include_directories: qnx_inc
)
endif


# grub is now part of libr/fs (see libr/fs/meson.build)

# handle winkd dependency
if cc.get_define('__wasi__') == ''
winkd_files = [
  'winkd/iob_pipe.c',
  'winkd/iob_net.c',
  'winkd/kd.c',
  'winkd/transport.c',
  'winkd/winkd.c',
]

winkd_inc = [platform_inc, include_directories('winkd')]

libr2winkd = static_library('r2winkd', winkd_files,
  dependencies: [r_muta_dep, r_socket_dep, r_util_dep],
  include_directories: winkd_inc,
  implicit_include_directories: false
)

winkd_dep = declare_dependency(
  link_with: libr2winkd,
  include_directories: winkd_inc
)

if get_option('blob')
libr2winkd_static = static_library('r2winkd_static', winkd_files,
  dependencies: [r_muta_static_dep, r_socket_static_dep, r_util_static_dep],
  include_directories: winkd_inc,
  implicit_include_directories: false
)

winkd_static_dep = declare_dependency(
  link_with: libr2winkd_static,
  include_directories: winkd_inc
)
endif
else
winkd_dep = declare_dependency()
winkd_static_dep = declare_dependency()
endif

# handle ar dependency
ar_files = [
  'ar/ar.c'
]

ar_inc = [platform_inc, include_directories(['ar'])]

libr2ar = static_library('r2ar', ar_files,
  dependencies: [r_util_dep],
  include_directories: ar_inc,
  implicit_include_directories: false
)

ar_dep = declare_dependency(
  link_with: libr2ar,
  include_directories: ar_inc
)

if get_option('blob')
libr2ar_static = static_library('r2ar_static', ar_files,
  dependencies: [r_util_static_dep],
  include_directories: ar_inc,
  implicit_include_directories: false
)

ar_static_dep = declare_dependency(
  link_with: libr2ar_static,
  include_directories: ar_inc
)
endif
