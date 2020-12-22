r_fs_sources = [
  'fs_file.c',
  'fs.c',
  'shell.c',
  'p/fs_cpio.c',
  'p/fs_ext2.c',
  'p/fs_fat.c',
  'p/fs_fb.c',
  #'p/fs_grub_base.c',
  'p/fs_hfs.c',
  'p/fs_hfsplus.c',
  'p/fs_io.c',
  'p/fs_iso9660.c',
  'p/fs_jfs.c',
  'p/fs_minix.c',
  'p/fs_ntfs.c',
  'p/fs_posix.c',
  'p/fs_r2.c',
  'p/fs_reiserfs.c',
  'p/fs_sfs.c',
  'p/fs_tar.c',
  'p/fs_udf.c',
  'p/fs_ufs.c',
  'p/fs_ufs2.c',
  'p/fs_xfs.c',
  #'p/part_dos.c'
]

r_fs = library('r_fs', r_fs_sources,
  include_directories: platform_inc,
  c_args: library_cflags,
  dependencies: [
    r_util_dep,
    grub_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

r_fs_dep = declare_dependency(link_with: r_fs,
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
