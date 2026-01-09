r_fs_sources = [
  'fs.c',
  'fs_file.c',
  'fs_shell.c',
  'p/fs_io.c',
  'p/fs_posix.c',
  'p/fs_r2.c',
  'p/fs_tmp.c',
  'p/fs_ubifs.c',
  'p/fs_bfs.c',
]

if get_option('use_zip')
  r_fs_sources += [ 'p/fs_zip.c' ]
endif

r_fs_deps = [ r_util_dep ]
r_fs_cflags = [ library_cflags ]
if get_option('blob')
  r_fs_static_deps = [ r_util_static_dep ]
endif

grub_inc = []
if not user_plugins.contains('nogrub') and not get_option('nogpl')
  grub_inc = [include_directories('p/grub', 'p/grub/include')]
  r_fs_sources += [
    'p/fs_cpio.c',
    'p/fs_ext2.c',
    'p/fs_fat.c',
    'p/fs_fb.c',
    'p/fs_hfs.c',
    'p/fs_hfsplus.c',
    'p/fs_iso9660.c',
    'p/fs_jfs.c',
    'p/fs_minix.c',
    'p/fs_ntfs.c',
    'p/fs_reiserfs.c',
    'p/fs_sfs.c',
    'p/fs_tar.c',
    'p/fs_udf.c',
    'p/fs_ufs.c',
    'p/fs_ufs2.c',
    'p/fs_xfs.c',
    #'p/part_dos.c'
    # grub sources (now integrated directly)
    'p/grub/fs/cpio.c',
    'p/grub/fs/ext2.c',
    'p/grub/fs/fat.c',
    'p/grub/fs/fb.c',
    'p/grub/fs/fshelp.c',
    'p/grub/fs/hfs.c',
    'p/grub/fs/hfsplus.c',
    'p/grub/fs/iso9660.c',
    'p/grub/fs/jfs.c',
    'p/grub/fs/minix.c',
    'p/grub/fs/ntfs.c',
    'p/grub/fs/ntfscomp.c',
    'p/grub/fs/reiserfs.c',
    'p/grub/fs/sfs.c',
    'p/grub/fs/tar.c',
    'p/grub/fs/udf.c',
    'p/grub/fs/ufs.c',
    'p/grub/fs/ufs2.c',
    'p/grub/fs/xfs.c',
    'p/grub/grubfs.c',
    'p/grub/kern/device.c',
    'p/grub/kern/disk.c',
    'p/grub/kern/env.c',
    'p/grub/kern/err.c',
    'p/grub/kern/file.c',
    'p/grub/kern/fs.c',
    'p/grub/kern/list.c',
    'p/grub/kern/misc.c',
    'p/grub/kern/mm.c',
    'p/grub/kern/partition.c',
    'p/grub/kern/term.c',
    'p/grub/kern/time.c',
    'p/grub/partmap/amiga.c',
    'p/grub/partmap/apple.c',
    'p/grub/partmap/bsdlabel.c',
    'p/grub/partmap/gpt.c',
    'p/grub/partmap/msdos.c',
    'p/grub/partmap/sun.c',
    'p/grub/partmap/sunpc.c',
  ]
  r_fs_cflags += [
    '-DUSE_GRUB=1'
  ]
else
  r_fs_cflags += [
    '-DUSE_GRUB=0'
  ]
endif

if get_option('use_libsqsh')
  libsqsh_dep = dependency('libsqsh', version: '>=1.4.0', required: false)
  if libsqsh_dep.found()
    r_fs_sources += [
      'p/fs_squashfs.c'
    ]
    r_fs_deps += [ libsqsh_dep ]
    if get_option('blob')
      r_fs_static_deps += [ libsqsh_static_dep ]
    endif
  endif
endif

if get_option('use_zip')
  r_fs_deps += [ zip_dep ]
  if get_option('blob')
    r_fs_static_deps += [ zip_dep ]
  endif
endif

r_fs = library('r_fs', r_fs_sources,
  include_directories: [platform_inc, grub_inc],
  c_args: r_fs_cflags,
  dependencies: r_fs_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_fs_dep = declare_dependency(link_with: r_fs,
  include_directories: [platform_inc, grub_inc])

if get_option('blob')
r_fs_static = static_library('r_fs_static', r_fs_sources,
  include_directories: [platform_inc, grub_inc],
  c_args: r_fs_cflags,
  dependencies: r_fs_static_deps,
  install: true,
  implicit_include_directories: false,
)

r_fs_static_dep = declare_dependency(link_with: r_fs_static,
  include_directories: [platform_inc, grub_inc])
endif

pkgconfig_mod.generate(r_fs,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_fs',
  filebase: 'r_fs',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
