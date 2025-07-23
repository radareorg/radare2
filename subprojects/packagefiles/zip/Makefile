include ../../config-user.mk
include ../../libr/config.mk
include ../../mk/platform.mk
include ../../mk/${COMPILER}.mk

ifneq (,$(findstring cygwin,${OSTYPE}))
CFLAGS+=-D__CYGWIN__=1
EXT_SO=dll
SOVER=${EXT_SO}
LDFLAGS+=-shared
LDFLAGS_SHARED?=-shared
else
ifneq (,$(findstring mingw,${OSTYPE})$(findstring msys,${OSTYPE}))
CFLAGS+=-DMINGW32=1
EXT_SO=dll
SOVER=${EXT_SO}
LDFLAGS+=-shared
LDFLAGS_SHARED?=-shared
else
CFLAGS+=-fPIC
endif
endif
ifeq (${OSTYPE},windows)
EXT_SO=dll
CFLAGS+=-D_WIN32=1
SOVER=${EXT_SO}
LDFLAGS+=-shared
LDFLAGS_SHARED?=-shared
else
ifeq (${OSTYPE},darwin)
EXT_SO=dylib
SOVER=${EXT_SO}
LDFLAGS+=-dynamic
LDFLAGS_SHARED?=-fPIC -dynamiclib
# ifeq (${ARCH},i386)
   #CC+=-arch i386
#   CC+=-arch x86_64
# endif
else
SOVERSION=0
EXT_SO=so
SOVER=${EXT_SO}
LDFLAGS_SHARED?=-fPIC -shared
LDFLAGS_SHARED+=-Wl,-soname,libr_z.${EXT_SO}
endif
endif
EXT_SO?=dylib

#####

OBJS=
OBJS+=lib/zip_add_dir.o
OBJS+=lib/zip_add_entry.o
OBJS+=lib/zip_algorithm_deflate.o
OBJS+=lib/zip_buffer.o
OBJS+=lib/zip_close.o
OBJS+=lib/zip_delete.o
OBJS+=lib/zip_dir_add.o
OBJS+=lib/zip_dirent.o
OBJS+=lib/zip_discard.o
OBJS+=lib/zip_entry.o
OBJS+=lib/zip_realloc.o
OBJS+=lib/zip_error.o
OBJS+=lib/zip_error_clear.o
OBJS+=lib/zip_error_get.o
OBJS+=lib/zip_error_get_sys_type.o
OBJS+=lib/zip_error_strerror.o
OBJS+=lib/zip_error_to_str.o
OBJS+=lib/zip_extra_field.o
OBJS+=lib/zip_extra_field_api.o
OBJS+=lib/zip_fclose.o
OBJS+=lib/zip_fdopen.o
OBJS+=lib/zip_file_add.o
OBJS+=lib/zip_file_error_clear.o
OBJS+=lib/zip_file_error_get.o
OBJS+=lib/zip_file_get_comment.o
OBJS+=lib/zip_file_get_external_attributes.o
OBJS+=lib/zip_file_get_offset.o
OBJS+=lib/zip_file_rename.o
OBJS+=lib/zip_file_replace.o
OBJS+=lib/zip_file_set_comment.o
OBJS+=lib/zip_file_set_encryption.o
OBJS+=lib/zip_file_set_external_attributes.o
OBJS+=lib/zip_file_set_mtime.o
OBJS+=lib/zip_file_strerror.o
OBJS+=lib/zip_fopen.o
OBJS+=lib/zip_fopen_encrypted.o
OBJS+=lib/zip_fopen_index.o
OBJS+=lib/zip_fopen_index_encrypted.o
OBJS+=lib/zip_fread.o
OBJS+=lib/zip_fseek.o
OBJS+=lib/zip_ftell.o
OBJS+=lib/zip_get_archive_comment.o
OBJS+=lib/zip_get_archive_flag.o
OBJS+=lib/zip_get_encryption_implementation.o
OBJS+=lib/zip_get_file_comment.o
OBJS+=lib/zip_get_name.o
OBJS+=lib/zip_get_num_entries.o
OBJS+=lib/zip_hash.o
OBJS+=lib/zip_io_util.o
OBJS+=lib/zip_libzip_version.o
OBJS+=lib/zip_memdup.o
OBJS+=lib/zip_name_locate.o
OBJS+=lib/zip_new.o
OBJS+=lib/zip_open.o
OBJS+=lib/zip_pkware.o
OBJS+=lib/zip_progress.o
OBJS+=lib/zip_random_unix.o
OBJS+=lib/zip_rename.o
OBJS+=lib/zip_replace.o
OBJS+=lib/zip_set_archive_comment.o
OBJS+=lib/zip_set_archive_flag.o
OBJS+=lib/zip_set_default_password.o
OBJS+=lib/zip_set_file_comment.o
OBJS+=lib/zip_set_file_compression.o
OBJS+=lib/zip_set_name.o
OBJS+=lib/zip_err_str.o
OBJS+=lib/zip_source_accept_empty.o
OBJS+=lib/zip_source_begin_write.o
OBJS+=lib/zip_source_begin_write_cloning.o
OBJS+=lib/zip_source_buffer.o
OBJS+=lib/zip_source_call.o
OBJS+=lib/zip_source_close.o
OBJS+=lib/zip_source_commit_write.o
OBJS+=lib/zip_source_compress.o
OBJS+=lib/zip_source_crc.o
OBJS+=lib/zip_source_error.o
OBJS+=lib/zip_source_file_common.o
OBJS+=lib/zip_source_file_stdio.o
OBJS+=lib/zip_source_file_stdio_named.o
OBJS+=lib/zip_source_free.o
OBJS+=lib/zip_source_function.o
OBJS+=lib/zip_source_get_dostime.o
OBJS+=lib/zip_source_get_file_attributes.o
OBJS+=lib/zip_source_is_deleted.o
OBJS+=lib/zip_source_layered.o
OBJS+=lib/zip_source_open.o
OBJS+=lib/zip_source_pass_to_lower_layer.o
OBJS+=lib/zip_source_pkware_decode.o
OBJS+=lib/zip_source_pkware_encode.o
OBJS+=lib/zip_source_read.o
OBJS+=lib/zip_source_remove.o
OBJS+=lib/zip_source_rollback_write.o
OBJS+=lib/zip_source_seek.o
OBJS+=lib/zip_source_seek_write.o
OBJS+=lib/zip_source_stat.o
OBJS+=lib/zip_source_supports.o
OBJS+=lib/zip_source_tell.o
OBJS+=lib/zip_source_tell_write.o
OBJS+=lib/zip_source_window.o
OBJS+=lib/zip_source_write.o
OBJS+=lib/zip_source_zip.o
OBJS+=lib/zip_source_zip_new.o
OBJS+=lib/zip_stat.o
OBJS+=lib/zip_stat_index.o
OBJS+=lib/zip_stat_init.o
OBJS+=lib/zip_strerror.o
OBJS+=lib/zip_string.o
OBJS+=lib/zip_unchange.o
OBJS+=lib/zip_unchange_all.o
OBJS+=lib/zip_unchange_archive.o
OBJS+=lib/zip_unchange_data.o
OBJS+=lib/zip_utf-8.o

#####

################ COMMENT
# OBJS=
# OBJS+=lib/zip_add.o
# OBJS+=lib/zip_add_dir.o
# OBJS+=lib/zip_add_entry.o
# # OBJS+=zip_algorithm_bzip2.o
# OBJS+=lib/zip_algorithm_deflate.o
# # OBJS+=zip_algorithm_xz.o
# # OBJS+=zip_algorithm_zstd.o
# OBJS+=lib/zip_buffer.o
# OBJS+=lib/zip_close.o
# OBJS+=lib/zip_delete.o
# OBJS+=lib/zip_dir_add.o
# OBJS+=lib/zip_dirent.o
# OBJS+=lib/zip_discard.o
# OBJS+=lib/zip_entry.o
# OBJS+=lib/zip_err_str.o
# OBJS+=lib/zip_error.o
# OBJS+=lib/zip_error_clear.o
# OBJS+=lib/zip_error_get.o
# OBJS+=lib/zip_error_get_sys_type.o
# OBJS+=lib/zip_error_strerror.o
# OBJS+=lib/zip_error_to_str.o
# OBJS+=lib/zip_extra_field.o
# OBJS+=lib/zip_extra_field_api.o
# OBJS+=lib/zip_fclose.o
# OBJS+=lib/zip_fdopen.o
# OBJS+=lib/zip_file_add.o
# OBJS+=lib/zip_file_error_clear.o
# OBJS+=lib/zip_file_error_get.o
# OBJS+=lib/zip_file_get_comment.o
# OBJS+=lib/zip_file_get_external_attributes.o
# OBJS+=lib/zip_file_get_offset.o
# OBJS+=lib/zip_file_rename.o
# OBJS+=lib/zip_file_replace.o
# OBJS+=lib/zip_file_set_comment.o
# OBJS+=lib/zip_file_set_external_attributes.o
# OBJS+=lib/zip_file_set_mtime.o
# OBJS+=lib/zip_file_strerror.o
# OBJS+=lib/zip_fopen.o
# OBJS+=lib/zip_fopen_index.o
# OBJS+=lib/zip_fopen_index_encrypted.o
# OBJS+=lib/zip_fread.o
# OBJS+=lib/zip_fseek.o
# OBJS+=lib/zip_ftell.o
# OBJS+=lib/zip_get_archive_comment.o
# OBJS+=lib/zip_get_archive_flag.o
# OBJS+=lib/zip_get_file_comment.o
# OBJS+=lib/zip_get_name.o
# OBJS+=lib/zip_get_num_entries.o
# OBJS+=lib/zip_get_num_files.o
# OBJS+=lib/zip_hash.o
# OBJS+=lib/zip_io_util.o
# OBJS+=lib/zip_libzip_version.o
# OBJS+=lib/zip_memdup.o
# OBJS+=lib/zip_name_locate.o
# OBJS+=lib/zip_new.o
# OBJS+=lib/zip_open.o
# OBJS+=lib/zip_pkware.o
# OBJS+=lib/zip_progress.o
# OBJS+=lib/zip_random_unix.o
# OBJS+=lib/zip_rename.o
# OBJS+=lib/zip_replace.o
# OBJS+=lib/zip_set_archive_comment.o
# OBJS+=lib/zip_set_archive_flag.o
# OBJS+=lib/zip_set_default_password.o
# OBJS+=lib/zip_set_file_comment.o
# OBJS+=lib/zip_set_file_compression.o
# OBJS+=lib/zip_set_name.o
# OBJS+=lib/zip_source_accept_empty.o
# OBJS+=lib/zip_source_begin_write.o
# OBJS+=lib/zip_source_begin_write_cloning.o
# OBJS+=lib/zip_source_buffer.o
# OBJS+=lib/zip_source_call.o
# OBJS+=lib/zip_source_close.o
# OBJS+=lib/zip_source_commit_write.o
# OBJS+=lib/zip_source_compress.o
# OBJS+=lib/zip_source_crc.o
# OBJS+=lib/zip_source_error.o
# OBJS+=lib/zip_source_file_common.o
# OBJS+=lib/zip_source_file_stdio.o
# OBJS+=lib/zip_source_file_stdio_named.o
# OBJS+=lib/zip_source_free.o
# OBJS+=lib/zip_source_function.o
# OBJS+=lib/zip_source_get_file_attributes.o
# OBJS+=lib/zip_source_is_deleted.o
# OBJS+=lib/zip_source_layered.o
# OBJS+=lib/zip_source_open.o
# OBJS+=lib/zip_source_pkware_decode.o
# OBJS+=lib/zip_source_pkware_encode.o
# OBJS+=lib/zip_source_read.o
# OBJS+=lib/zip_source_remove.o
# OBJS+=lib/zip_source_rollback_write.o
# OBJS+=lib/zip_source_seek.o
# OBJS+=lib/zip_source_seek_write.o
# OBJS+=lib/zip_source_stat.o
# OBJS+=lib/zip_source_supports.o
# OBJS+=lib/zip_source_tell.o
# OBJS+=lib/zip_source_tell_write.o
# OBJS+=lib/zip_source_window.o
# OBJS+=lib/zip_source_write.o
# OBJS+=lib/zip_source_zip.o
# OBJS+=lib/zip_source_zip_new.o
# OBJS+=lib/zip_realloc.o
# OBJS+=lib/zip_stat.o
# OBJS+=lib/zip_stat_index.o
# OBJS+=lib/zip_stat_init.o
# OBJS+=lib/zip_strerror.o
# OBJS+=lib/zip_string.o
# OBJS+=lib/zip_utf-8.o

#OFILES=libr_zip.$(EXT_AR) $(OBJS)
OFILES=$(OBJS)

#CFLAGS+=-g -fPIC
CFLAGS+=-I../zlib -I../../libr/include -I./lib/ -I.
LDFLAGS+=-L../../libr/util
LINKFLAGS=../zlib/libr_z.$(EXT_AR)
#LDFLAGS=-shared
LIBNAME=libr_zip.${SOVER}

LIBAR=libr_zip.$(EXT_AR)

all:: ${LIBAR}
ifeq ($(WITHPIC),1)
all:: ${LIBNAME}
endif

${LIBNAME}: ${OBJS}
ifneq ($(SILENT),)
	@echo LIB ${LIBNAME}
endif
	${CC} $(CFLAGS) ${LDFLAGS} $(LDFLAGS_SHARED) -o $@ ${OBJS} ${LINKFLAGS}

${LIBAR}: ${OFILES}
	${CC_AR} ${OFILES}
	${RANLIB} ${LIBAR}

clean:
	rm -f ${LIBNAME} *.o *.$(EXT_AR) *.d *.${EXT_SO}

