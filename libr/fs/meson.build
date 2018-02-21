files = [
  'file.c',
  'fs.c',
  #'p/fs_cpio.c',
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
  'p/fs_posix.c',
  'p/fs_reiserfs.c',
  'p/fs_sfs.c',
  'p/fs_tar.c',
  'p/fs_udf.c',
  'p/fs_ufs.c',
  'p/fs_ufs2.c',
  'p/fs_xfs.c',
  'p/part_dos.c'
]

r_fs = library('r_fs', files,
  include_directories: [
    platform_inc,
    include_directories([
      '../../shlr/grub/include'
    ])
  ],
  c_args: ['-DCORELIB=1'],
  link_with: [r_util, libr_shlr],
  install: true,
  implicit_include_directories: false
)
