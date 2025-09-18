r_fs_sources = [
  'fs.c',
  'fs_file.c',
  'fs_shell.c',
  'p/fs_io.c',
  'p/fs_posix.c',
  'p/fs_r2.c',
]

if get_option('use_zip')
  r_fs_sources += [ 'p/fs_zip.c' ]
endif

r_fs_deps = [ r_util_dep ]
r_fs_cflags = [ library_cflags ]
if get_option('blob')
  r_fs_static_deps = [ r_util_static_dep ]
endif

if not user_plugins.contains('nogrub') and not get_option('nogpl')
  r_fs_deps += [ grub_dep ]
  if get_option('blob')
    r_fs_static_deps += [ grub_static_dep ]
  endif
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

if get_option('blob')
r_fs_static = static_library('r_fs_static', r_fs_sources,
  include_directories: platform_inc,
  c_args: r_fs_cflags,
  dependencies: r_fs_static_deps,
  install: true,
  implicit_include_directories: false,
)

r_fs_static_dep = declare_dependency(link_with: r_fs_static,
  include_directories: platform_inc)
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
