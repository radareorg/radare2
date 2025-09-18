# handle zlib dependency
zlib_dep = dependency('zlib', required: false)
if not zlib_dep.found() or not get_option('use_sys_zlib')
  message('Use bundled zlib')

  zlib_files = [
    join_paths('zlib','adler32.c'),
    join_paths('zlib','compress.c'),
    join_paths('zlib','crc32.c'),
    join_paths('zlib','deflate.c'),
    join_paths('zlib','infback.c'),
    join_paths('zlib','inffast.c'),
    join_paths('zlib','inflate.c'),
    join_paths('zlib','inftrees.c'),
    join_paths('zlib','trees.c'),
    join_paths('zlib','uncompr.c'),
    join_paths('zlib','zutil.c')
  ]

  if host_machine.system() != 'uefi'
    zlib_files += [
      join_paths('zlib','gzclose.c'),
      join_paths('zlib','gzlib.c'),
      join_paths('zlib','gzread.c'),
      join_paths('zlib','gzwrite.c'),
    ]
  endif

  zlib_inc = [platform_inc, include_directories(join_paths('zlib'))]
  zlib_cargs = []
  if host_machine.system() == 'uefi'
    zlib_cargs += ['-DZ_SOLO=1']
  endif

  libr2zlib = static_library('r2zlib', zlib_files,
    include_directories: zlib_inc,
    c_args: zlib_cargs,
    implicit_include_directories: false
  )

  zlib_dep = declare_dependency(
    link_with: libr2zlib,
    include_directories: zlib_inc
  )
else
  message('Use system-provided zlib library')
endif

# handle zip dependency (optional)
if get_option('use_zip')
  zip_dep = dependency('libzip', required: false)
  if not zip_dep.found() or not get_option('use_sys_zip')
    message('Use bundled zip')
    zip_files = [
      'zip/zip_add.c',
      'zip/zip_add_dir.c',
      'zip/zip_add_entry.c',
      'zip/zip_close.c',
      'zip/zip_delete.c',
      'zip/zip_dir_add.c',
      'zip/zip_dirent.c',
      'zip/zip_discard.c',
      'zip/zip_entry.c',
      'zip/zip_error.c',
      'zip/zip_error_clear.c',
      'zip/zip_error_get.c',
      'zip/zip_error_get_sys_type.c',
      'zip/zip_extra_field.c',
      'zip/zip_fdopen.c',
      'zip/zip_file_get_comment.c',
      'zip/zip_file_get_external_attributes.c',
      'zip/zip_file_get_offset.c',
      'zip/zip_file_rename.c',
      'zip/zip_file_set_comment.c',
      'zip/zip_file_strerror.c',
      'zip/zip_fopen_index.c',
      'zip/zip_fread.c',
      'zip/zip_ftell.c',
      'zip/zip_get_archive_flag.c',
      'zip/zip_get_file_comment.c',
      'zip/zip_get_name.c',
      'zip/zip_get_num_entries.c',
      'zip/zip_get_num_files.c',
      'zip/zip_libzip_version.c',
      'zip/zip_new.c',
      'zip/zip_progress.c',
      'zip/zip_random_unix.c',
      'zip/zip_set_archive_comment.c',
      'zip/zip_set_default_password.c',
      'zip/zip_set_file_compression.c',
      'zip/zip_set_name.c',
      'zip/zip_source_begin_write.c',
      'zip/zip_source_close.c',
      'zip/zip_source_commit_write.c',
      'zip/zip_source_compress.c',
      'zip/zip_source_file_common.c',
      'zip/zip_source_function.c',
      'zip/zip_source_layered.c',
      'zip/zip_source_open.c',
      'zip/zip_source_pkware.c',
      'zip/zip_source_pkware_encode.c',
      'zip/zip_source_pop.c',
      'zip/zip_source_read.c',
      'zip/zip_source_remove.c',
      'zip/zip_source_rollback_write.c',
      'zip/zip_source_seek.c',
      'zip/zip_source_seek_write.c',
      'zip/zip_source_supports.c',
      'zip/zip_source_tell_write.c',
      'zip/zip_source_window.c',
      'zip/zip_source_write.c',
      'zip/zip_source_zip.c',
      'zip/zip_source_zip_new.c',
      'zip/zip_stat.c',
      'zip/zip_stat_index.c',
      'zip/zip_stat_init.c',
      'zip/zip_strerror.c',
      'zip/zip_string.c',
      # Added missing sources to satisfy unresolved symbols
      'zip/zip_algorithm_deflate.c',
      'zip/zip_buffer.c',
      'zip/zip_err_str.c',
      'zip/zip_error_strerror.c',
      'zip/zip_error_to_str.c',
      'zip/zip_extra_field_api.c',
      'zip/zip_fclose.c',
      'zip/zip_file_add.c',
      'zip/zip_file_error_clear.c',
      'zip/zip_file_error_get.c',
      'zip/zip_file_replace.c',
      'zip/zip_file_set_external_attributes.c',
      'zip/zip_file_set_mtime.c',
      'zip/zip_filerange_crc.c',
      'zip/zip_fopen.c',
      'zip/zip_fopen_index_encrypted.c',
      'zip/zip_fseek.c',
      'zip/zip_get_archive_comment.c',
      'zip/zip_hash.c',
      'zip/zip_io_util.c',
      'zip/zip_memdup.c',
      'zip/zip_name_locate.c',
      'zip/zip_open.c',
      'zip/zip_pkware.c',
      'zip/zip_rename.c',
      'zip/zip_replace.c',
      'zip/zip_set_archive_flag.c',
      'zip/zip_set_file_comment.c',
      'zip/zip_source_accept_empty.c',
      'zip/zip_source_begin_write_cloning.c',
      'zip/zip_source_buffer.c',
      'zip/zip_source_call.c',
      'zip/zip_source_crc.c',
      'zip/zip_source_deflate.c',
      'zip/zip_source_error.c',
      'zip/zip_source_file_stdio.c',
      'zip/zip_source_file_stdio_named.c',
      'zip/zip_source_free.c',
      'zip/zip_source_get_file_attributes.c',
      'zip/zip_source_is_deleted.c',
      'zip/zip_source_pkware_decode.c',
      'zip/zip_source_stat.c',
      'zip/zip_source_tell.c',
      'zip/zip_unchange.c',
      'zip/zip_unchange_all.c',
      'zip/zip_unchange_archive.c',
      'zip/zip_unchange_data.c',
      'zip/zip_utf-8.c',
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
else
  zip_dep = declare_dependency() # empty when disabled
endif
