project(
  'zip',
  'c',
  version: 'dd450e6ed6faa446518ff6017305b62fd7d55a17',
  meson_version: '>=0.60.0',
)

# handle zlib dependency
zlib_dep = dependency('zlib', required: false, static: get_option('static_runtime'))
if not zlib_dep.found() or not get_option('use_sys_zlib')
  message('Use subprojected zlib')

  zlib_proj = subproject('zlib', default_options: ['default_library=static'])
  zlib_dep = zlib_proj.get_variable('zlib_dep')
else
  message('Use system-provided zlib library')
endif

libzip_deps = [zlib_dep]

zip_files = [
  'lib/zip_add.c',
  'lib/zip_add_dir.c',
  'lib/zip_add_entry.c',
  'lib/zip_algorithm_deflate.c',
  'lib/zip_buffer.c',
  'lib/zip_close.c',
  'lib/zip_delete.c',
  'lib/zip_dir_add.c',
  'lib/zip_dirent.c',
  'lib/zip_discard.c',
  'lib/zip_entry.c',
  # 'lib/zip_realloc.c',
  'lib/zip_error.c',
  'lib/zip_error_clear.c',
  'lib/zip_error_get.c',
  'lib/zip_error_get_sys_type.c',
  'lib/zip_error_strerror.c',
  'lib/zip_error_to_str.c',
  'lib/zip_extra_field.c',
  'lib/zip_extra_field_api.c',
  'lib/zip_fclose.c',
  'lib/zip_fdopen.c',
  'lib/zip_file_add.c',
  'lib/zip_file_error_clear.c',
  'lib/zip_file_error_get.c',
  'lib/zip_file_get_comment.c',
  'lib/zip_file_get_external_attributes.c',
  'lib/zip_file_get_offset.c',
  'lib/zip_file_rename.c',
  'lib/zip_file_replace.c',
  'lib/zip_file_set_comment.c',
  'lib/zip_file_set_encryption.c',
  'lib/zip_file_set_external_attributes.c',
  'lib/zip_file_set_mtime.c',
  'lib/zip_file_strerror.c',
  'lib/zip_fopen.c',
  'lib/zip_fopen_encrypted.c',
  'lib/zip_fopen_index.c',
  'lib/zip_fopen_index_encrypted.c',
  'lib/zip_fread.c',
  'lib/zip_fseek.c',
  'lib/zip_ftell.c',
  'lib/zip_get_archive_comment.c',
  'lib/zip_get_archive_flag.c',
  'lib/zip_get_encryption_implementation.c',
  'lib/zip_get_file_comment.c',
  'lib/zip_get_name.c',
  'lib/zip_get_num_entries.c',
  'lib/zip_hash.c',
  'lib/zip_io_util.c',
  'lib/zip_libzip_version.c',
  'lib/zip_memdup.c',
  'lib/zip_name_locate.c',
  'lib/zip_new.c',
  'lib/zip_open.c',
  'lib/zip_pkware.c',
  'lib/zip_progress.c',
  'lib/zip_rename.c',
  'lib/zip_replace.c',
  'lib/zip_set_archive_comment.c',
  'lib/zip_set_archive_flag.c',
  'lib/zip_set_default_password.c',
  'lib/zip_set_file_comment.c',
  'lib/zip_set_file_compression.c',
  'lib/zip_set_name.c',
  'lib/zip_source_accept_empty.c',
  'lib/zip_source_begin_write.c',
  'lib/zip_source_begin_write_cloning.c',
  'lib/zip_source_buffer.c',
  'lib/zip_source_call.c',
  'lib/zip_source_close.c',
  'lib/zip_source_commit_write.c',
  'lib/zip_source_compress.c',
  'lib/zip_source_crc.c',
  'lib/zip_source_error.c',
  'lib/zip_source_file_common.c',
  'lib/zip_source_file_stdio.c',
  'lib/zip_source_free.c',
  'lib/zip_source_function.c',
  'lib/zip_source_get_dostime.c',
  'lib/zip_source_get_file_attributes.c',
  'lib/zip_source_is_deleted.c',
  'lib/zip_source_layered.c',
  'lib/zip_source_open.c',
  'lib/zip_source_pass_to_lower_layer.c',
  'lib/zip_source_pkware_decode.c',
  'lib/zip_source_pkware_encode.c',
  'lib/zip_source_read.c',
  'lib/zip_source_remove.c',
  'lib/zip_source_rollback_write.c',
  'lib/zip_source_seek.c',
  'lib/zip_source_seek_write.c',
  'lib/zip_source_stat.c',
  'lib/zip_source_supports.c',
  'lib/zip_source_tell.c',
  'lib/zip_source_tell_write.c',
  'lib/zip_source_window.c',
  'lib/zip_source_write.c',
  'lib/zip_source_zip.c',
  'lib/zip_source_zip_new.c',
  'lib/zip_stat.c',
  'lib/zip_stat_index.c',
  'lib/zip_stat_init.c',
  'lib/zip_strerror.c',
  'lib/zip_string.c',
  'lib/zip_unchange.c',
  'lib/zip_unchange_all.c',
  'lib/zip_unchange_archive.c',
  'lib/zip_unchange_data.c',
  'lib/zip_utf-8.c',
]

if host_machine.system() == 'windows'
  cc = meson.get_compiler('c')
  zip_files += [
    'lib/zip_source_file_win32.c',
    'lib/zip_source_file_win32_named.c',
    'lib/zip_source_file_win32_utf16.c',
    'lib/zip_source_file_win32_utf8.c',
    'lib/zip_source_file_win32_ansi.c',
    'lib/zip_random_win32.c',
  ]
  libzip_deps += cc.find_library('advapi32')
else
  zip_files += [
    'lib/zip_source_file_stdio_named.c',
    'lib/zip_random_unix.c'
  ]
endif

zip_files += ['lib/zip_err_str.c']

zip_inc = [include_directories('lib', '.')]

libzip = library('libzip', zip_files,
  dependencies: libzip_deps,
  include_directories: zip_inc
)

zip_dep = declare_dependency(
  link_with: libzip,
  include_directories: zip_inc,
  dependencies: libzip_deps
)

