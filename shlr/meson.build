# handle capstone dependency
capstone_dep = dependency('capstone', version: '>=4.0.0', required: false)
if capstone_dep.found() and get_option('use_sys_capstone')
  message('Use system-provided capstone library')
else
  if get_option('capstone_in_builddir')
    capstone_path = join_paths(meson.current_build_dir(), 'capstone')
  else
    capstone_path = join_paths(meson.source_root(), 'subprojects/capstone-' + capstone_version)
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

qnx_inc = [platform_inc, include_directories('qnx/include')]

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


# handle grub dependency
grub_files = [
  #'grub/fs/affs.c',
  #'grub/fs/afs.c',
  #'grub/fs/afs_be.c',
  #'grub/fs/befs.c',
  #'grub/fs/befs_be.c',
  #'grub/fs/btrfs.c',
  'grub/fs/cpio.c',
  'grub/fs/ext2.c',
  'grub/fs/fat.c',
  'grub/fs/fb.c',
  'grub/fs/fshelp.c',
  'grub/fs/hfs.c',
  'grub/fs/hfsplus.c',
  'grub/fs/iso9660.c',
  'grub/fs/jfs.c',
  'grub/fs/minix.c',
  #'grub/fs/minix2.c',
  #'grub/fs/nilfs2.c',
  'grub/fs/ntfs.c',
  'grub/fs/ntfscomp.c',
  'grub/fs/reiserfs.c',
  'grub/fs/sfs.c',
  'grub/fs/tar.c',
  'grub/fs/udf.c',
  'grub/fs/ufs.c',
  'grub/fs/ufs2.c',
  'grub/fs/xfs.c',
  'grub/grubfs.c',
  'grub/kern/device.c',
  'grub/kern/disk.c',
  'grub/kern/env.c',
  'grub/kern/err.c',
  'grub/kern/file.c',
  'grub/kern/fs.c',
  'grub/kern/list.c',
  'grub/kern/misc.c',
  'grub/kern/mm.c',
  'grub/kern/partition.c',
  'grub/kern/term.c',
  'grub/kern/time.c',
  #'grub/main.c',
  #'grub/partmap/acorn.c',
  'grub/partmap/amiga.c',
  'grub/partmap/apple.c',
  'grub/partmap/bsdlabel.c',
  'grub/partmap/gpt.c',
  'grub/partmap/msdos.c',
  'grub/partmap/sun.c',
  'grub/partmap/sunpc.c',
]

grub_inc = [platform_inc, include_directories('grub', 'grub/include')]

libr2grub = static_library('r2grub', grub_files,
  dependencies: [r_util_dep],
  include_directories: grub_inc,
  implicit_include_directories: false
)

grub_dep = declare_dependency(
  link_with: libr2grub,
  include_directories: grub_inc
)

if get_option('blob')
libr2grub_static = static_library('r2grub_static', grub_files,
  dependencies: [r_util_static_dep],
  include_directories: grub_inc,
  implicit_include_directories: false
)

grub_static_dep = declare_dependency(
  link_with: libr2grub_static,
  include_directories: grub_inc
)
endif

# handle winkd dependency
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
