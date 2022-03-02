r_fs_sources = [
  'fs_file.c',
  'fs.c',
  'shell.c',
  'p/fs_io.c',
  'p/fs_posix.c',
  'p/fs_r2.c',
]

r_fs_deps = [ r_util_dep ]
r_fs_cflags = [ library_cflags ]

if not user_plugins.contains('nogrub') and not get_option('nogpl')
  r_fs_deps += [ grub_dep ]
  r_fs_sources += [
    'p/fs_cpio.c',
    'p/fs_ext2.c',
    'p/fs_fat.c',
    'p/fs_fb.c',
    #'p/fs_grub_base.c',
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
  ]
  r_fs_cflags += [
    '-DUSE_GRUB=1'
  ]
else
  r_fs_cflags += [
    '-DUSE_GRUB=0'
  ]
endif

r_fs = library('r_fs', r_fs_sources,
  include_directories: platform_inc,
  c_args: r_fs_cflags,
  dependencies: r_fs_deps,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_fs_dep = declare_dependency(link_with: r_fs,
  include_directories: platform_inc)

r_fs_static = static_library('r_fs_static', r_fs_sources,
  include_directories: platform_inc,
  c_args: r_fs_cflags,
  dependencies: r_fs_deps,
  install: true,
  implicit_include_directories: false,
)

r_fs_static_dep = declare_dependency(link_with: r_fs_static,
  include_directories: platform_inc)

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
