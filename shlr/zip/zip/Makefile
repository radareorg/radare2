include ../../../config-user.mk
include ../../../libr/config.mk
include ../../../mk/platform.mk
include ../../../mk/${COMPILER}.mk

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

OBJS=
OBJS+=zip_add.o
OBJS+=zip_add_dir.o
OBJS+=zip_add_entry.o
# OBJS+=zip_algorithm_bzip2.o
OBJS+=zip_algorithm_deflate.o
# OBJS+=zip_algorithm_xz.o
# OBJS+=zip_algorithm_zstd.o
OBJS+=zip_buffer.o
OBJS+=zip_close.o
#OBJS+=zip_crypto_commoncrypto.o
#OBJS+=zip_crypto_gnutls.o
#OBJS+=zip_crypto_mbedtls.o
#OBJS+=zip_crypto_openssl.o
#OBJS+=zip_crypto_win.o
OBJS+=zip_delete.o
OBJS+=zip_dir_add.o
OBJS+=zip_dirent.o
OBJS+=zip_discard.o
OBJS+=zip_entry.o
OBJS+=zip_err_str.o
OBJS+=zip_error.o
OBJS+=zip_error_clear.o
OBJS+=zip_error_get.o
OBJS+=zip_error_get_sys_type.o
OBJS+=zip_error_strerror.o
OBJS+=zip_error_to_str.o
OBJS+=zip_extra_field.o
OBJS+=zip_extra_field_api.o
OBJS+=zip_fclose.o
OBJS+=zip_fdopen.o
OBJS+=zip_file_add.o
OBJS+=zip_file_error_clear.o
OBJS+=zip_file_error_get.o
OBJS+=zip_file_get_comment.o
OBJS+=zip_file_get_external_attributes.o
OBJS+=zip_file_get_offset.o
OBJS+=zip_file_rename.o
OBJS+=zip_file_replace.o
OBJS+=zip_file_set_comment.o
#OBJS+=zip_file_set_encryption.o
OBJS+=zip_file_set_external_attributes.o
OBJS+=zip_file_set_mtime.o
OBJS+=zip_file_strerror.o
OBJS+=zip_filerange_crc.o
OBJS+=zip_fopen.o
#OBJS+=zip_fopen_encrypted.o
OBJS+=zip_fopen_index.o
#OBJS+=zip_fopen_index_encrypted.o
OBJS+=zip_fread.o
OBJS+=zip_fseek.o
OBJS+=zip_ftell.o
OBJS+=zip_get_archive_comment.o
OBJS+=zip_get_archive_flag.o
#OBJS+=zip_get_encryption_implementation.o
OBJS+=zip_get_file_comment.o
OBJS+=zip_get_name.o
OBJS+=zip_get_num_entries.o
OBJS+=zip_get_num_files.o
OBJS+=zip_hash.o
OBJS+=zip_io_util.o
OBJS+=zip_libzip_version.o
OBJS+=zip_memdup.o
OBJS+=zip_name_locate.o
OBJS+=zip_new.o
OBJS+=zip_open.o
OBJS+=zip_pkware.o
OBJS+=zip_progress.o
OBJS+=zip_random_unix.o
#OBJS+=zip_random_uwp.o
#OBJS+=zip_random_win32.o
OBJS+=zip_rename.o
OBJS+=zip_replace.o
OBJS+=zip_set_archive_comment.o
OBJS+=zip_set_archive_flag.o
OBJS+=zip_set_default_password.o
OBJS+=zip_set_file_comment.o
OBJS+=zip_set_file_compression.o
OBJS+=zip_set_name.o
OBJS+=zip_source_accept_empty.o
OBJS+=zip_source_begin_write.o
OBJS+=zip_source_begin_write_cloning.o
OBJS+=zip_source_buffer.o
OBJS+=zip_source_call.o
OBJS+=zip_source_close.o
OBJS+=zip_source_commit_write.o
OBJS+=zip_source_compress.o
OBJS+=zip_source_crc.o
OBJS+=zip_source_deflate.o
OBJS+=zip_source_error.o
OBJS+=zip_source_file.o
OBJS+=zip_source_file_common.o
OBJS+=zip_source_file_stdio.o
OBJS+=zip_source_file_stdio_named.o
#OBJS+=zip_source_file_win32.o
#OBJS+=zip_source_file_win32_ansi.o
#OBJS+=zip_source_file_win32_named.o
#OBJS+=zip_source_file_win32_utf16.o
#OBJS+=zip_source_file_win32_utf8.o
OBJS+=zip_source_free.o
OBJS+=zip_source_function.o
OBJS+=zip_source_get_file_attributes.o
OBJS+=zip_source_is_deleted.o
OBJS+=zip_source_layered.o
OBJS+=zip_source_open.o
OBJS+=zip_source_pkware.o
OBJS+=zip_source_pkware_decode.o
OBJS+=zip_source_pkware_encode.o
OBJS+=zip_source_pop.o
OBJS+=zip_source_read.o
OBJS+=zip_source_remove.o
OBJS+=zip_source_rollback_write.o
OBJS+=zip_source_seek.o
OBJS+=zip_source_seek_write.o
OBJS+=zip_source_stat.o
OBJS+=zip_source_supports.o
OBJS+=zip_source_tell.o
OBJS+=zip_source_tell_write.o
OBJS+=zip_source_window.o
#OBJS+=zip_source_winzip_aes_decode.o
#OBJS+=zip_source_winzip_aes_encode.o
OBJS+=zip_source_write.o
OBJS+=zip_source_zip.o
OBJS+=zip_source_zip_new.o
OBJS+=zip_stat.o
OBJS+=zip_stat_index.o
OBJS+=zip_stat_init.o
OBJS+=zip_strerror.o
OBJS+=zip_string.o
OBJS+=zip_unchange.o
OBJS+=zip_unchange_all.o
OBJS+=zip_unchange_archive.o
OBJS+=zip_unchange_data.o
OBJS+=zip_utf-8.o
#OBJS+=zip_winzip_aes.o

#OFILES=libr_zip.$(EXT_AR) $(OBJS)
OFILES=$(OBJS)

#CFLAGS+=-g -fPIC
CFLAGS+=-I../../../libr/include -I../include/
LDFLAGS+=-L../../../libr/util
LINKFLAGS=../zlib/libr_z.$(EXT_AR)
#LDFLAGS=-shared
EXT_SO?=dylib
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
