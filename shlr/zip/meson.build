# handle zlib dependency
zlib_dep = dependency('zlib', required: false)
if not zlib_dep.found() or not get_option('use_sys_zlib')
  message('Use bundled zlib')

  zlib_files = [
    join_paths('zlib','adler32.c'),
    join_paths('zlib','compress.c'),
    join_paths('zlib','crc32.c'),
    join_paths('zlib','deflate.c'),
    join_paths('zlib','gzclose.c'),
    join_paths('zlib','gzlib.c'),
    join_paths('zlib','gzread.c'),
    join_paths('zlib','gzwrite.c'),
    join_paths('zlib','infback.c'),
    join_paths('zlib','inffast.c'),
    join_paths('zlib','inflate.c'),
    join_paths('zlib','inftrees.c'),
    join_paths('zlib','trees.c'),
    join_paths('zlib','uncompr.c'),
    join_paths('zlib','zutil.c')
  ]

  zlib_inc = [platform_inc, include_directories(join_paths('zlib'))]

  libr2zlib = static_library('r2zlib', zlib_files,
    include_directories: zlib_inc,
    implicit_include_directories: false
  )

  zlib_dep = declare_dependency(
    link_with: libr2zlib,
    include_directories: zlib_inc
  )
else
  message('Use system-provided zlib library')
endif

# handle zip dependency
zip_dep = dependency('libzip', required: false)
if not zip_dep.found() or not get_option('use_sys_zip')
  message('Use bundled zip')

  zip_files = [
    join_paths('zip','zip_add.c'),
    join_paths('zip','zip_add_dir.c'),
    join_paths('zip','zip_add_entry.c'),
    join_paths('zip','zip_close.c'),
    join_paths('zip','zip_delete.c'),
    join_paths('zip','zip_dir_add.c'),
    join_paths('zip','zip_dirent.c'),
    join_paths('zip','zip_discard.c'),
    join_paths('zip','zip_entry.c'),
    join_paths('zip','zip_err_str.c'),
    join_paths('zip','zip_error.c'),
    #join_paths('zip','zip_error_clear.c'),
    join_paths('zip','zip_error_get.c'),
    join_paths('zip','zip_error_get_sys_type.c'),
    join_paths('zip','zip_error_strerror.c'),
    join_paths('zip','zip_error_to_str.c'),
    join_paths('zip','zip_extra_field.c'),
    join_paths('zip','zip_extra_field_api.c'),
    join_paths('zip','zip_fclose.c'),
    join_paths('zip','zip_fdopen.c'),
    join_paths('zip','zip_file_add.c'),
    #join_paths('zip','zip_file_error_clear.c'),
    join_paths('zip','zip_file_error_get.c'),
    join_paths('zip','zip_file_get_comment.c'),
    join_paths('zip','zip_file_get_offset.c'),
    join_paths('zip','zip_file_rename.c'),
    join_paths('zip','zip_file_replace.c'),
    join_paths('zip','zip_file_set_comment.c'),
    join_paths('zip','zip_file_strerror.c'),
    join_paths('zip','zip_filerange_crc.c'),
    join_paths('zip','zip_fopen.c'),
    join_paths('zip','zip_fopen_encrypted.c'),
    join_paths('zip','zip_fopen_index.c'),
    join_paths('zip','zip_fopen_index_encrypted.c'),
    join_paths('zip','zip_fread.c'),
    join_paths('zip','zip_get_archive_comment.c'),
    join_paths('zip','zip_get_archive_flag.c'),
    join_paths('zip','zip_get_compression_implementation.c'),
    join_paths('zip','zip_get_encryption_implementation.c'),
    join_paths('zip','zip_get_file_comment.c'),
    join_paths('zip','zip_get_name.c'),
    join_paths('zip','zip_get_num_entries.c'),
    join_paths('zip','zip_get_num_files.c'),
    join_paths('zip','zip_name_locate.c'),
    join_paths('zip','zip_new.c'),
    join_paths('zip','zip_open.c'),
    join_paths('zip','zip_rename.c'),
    join_paths('zip','zip_replace.c'),
    join_paths('zip','zip_set_archive_comment.c'),
    join_paths('zip','zip_set_archive_flag.c'),
    join_paths('zip','zip_set_default_password.c'),
    join_paths('zip','zip_set_file_comment.c'),
    join_paths('zip','zip_set_file_compression.c'),
    join_paths('zip','zip_set_name.c'),
    join_paths('zip','zip_source_buffer.c'),
    join_paths('zip','zip_source_close.c'),
    join_paths('zip','zip_source_crc.c'),
    join_paths('zip','zip_source_deflate.c'),
    join_paths('zip','zip_source_error.c'),
    join_paths('zip','zip_source_file.c'),
    join_paths('zip','zip_source_filep.c'),
    join_paths('zip','zip_source_free.c'),
    join_paths('zip','zip_source_function.c'),
    join_paths('zip','zip_source_layered.c'),
    join_paths('zip','zip_source_open.c'),
    join_paths('zip','zip_source_pkware.c'),
    join_paths('zip','zip_source_pop.c'),
    join_paths('zip','zip_source_read.c'),
    join_paths('zip','zip_source_stat.c'),
    join_paths('zip','zip_source_window.c'),
    join_paths('zip','zip_source_zip.c'),
    join_paths('zip','zip_source_zip_new.c'),
    join_paths('zip','zip_stat.c'),
    join_paths('zip','zip_stat_index.c'),
    join_paths('zip','zip_stat_init.c'),
    join_paths('zip','zip_strerror.c'),
    join_paths('zip','zip_string.c'),
    join_paths('zip','zip_unchange.c'),
    join_paths('zip','zip_unchange_all.c'),
    join_paths('zip','zip_unchange_archive.c'),
    join_paths('zip','zip_unchange_data.c'),
    join_paths('zip','zip_utf-8.c')
  ]

  zip_inc = [platform_inc, include_directories('include')]

  libr2zip = static_library('r2zip', zip_files,
    include_directories: zip_inc,
    implicit_include_directories: false,
    dependencies: zlib_dep
  )

  zip_dep = declare_dependency(
    link_with: libr2zip,
    include_directories: zip_inc
  )
else
  message('Use system-provided zip library')
endif

