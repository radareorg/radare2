include ../../../config-user.mk
include ../../../libr/config.mk
include ../../../mk/${COMPILER}.mk

ifneq (,$(findstring cygwin,${OSTYPE}))
CFLAGS+=-D__CYGWIN__=1
EXT_SO=dll
SOVER=${EXT_SO}
LDFLAGS+=-shared
LDFLAGS_SHARED?=-shared
else
ifneq (,$(findstring ming32,${OSTYPE}))
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
LDFLAGS_SHARED?=-fPIC -shared
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

OBJS=	zip_add.o zip_add_dir.o zip_add_entry.o \
	zip_close.o zip_delete.o zip_dir_add.o zip_dirent.o \
	zip_discard.o zip_entry.o zip_err_str.o zip_error.o \
	zip_error_clear.o zip_error_get.o zip_error_get_sys_type.o \
	zip_error_strerror.o zip_error_to_str.o zip_extra_field.o \
	zip_extra_field_api.o zip_fclose.o zip_fdopen.o \
	zip_file_add.o zip_file_error_clear.o zip_file_error_get.o \
	zip_file_get_comment.o zip_file_get_offset.o \
	zip_file_rename.o zip_file_replace.o zip_file_set_comment.o \
	zip_file_strerror.o zip_filerange_crc.o zip_fopen.o \
	zip_fopen_encrypted.o zip_fopen_index.o \
	zip_fopen_index_encrypted.o zip_fread.o \
	zip_get_archive_comment.o zip_get_archive_flag.o \
	zip_get_compression_implementation.o \
	zip_get_encryption_implementation.o zip_get_file_comment.o \
	zip_get_num_entries.o zip_get_num_files.o zip_get_name.o \
	zip_memdup.o zip_name_locate.o zip_new.o zip_open.o \
	zip_rename.o zip_replace.o zip_set_archive_comment.o \
	zip_set_archive_flag.o zip_set_default_password.o \
	zip_set_file_comment.o zip_set_file_compression.o \
	zip_set_name.o zip_source_buffer.o zip_source_close.o \
	zip_source_crc.o zip_source_deflate.o zip_source_error.o \
	zip_source_file.o zip_source_filep.o zip_source_free.o \
	zip_source_function.o zip_source_layered.o \
	zip_source_open.o zip_source_pkware.o zip_source_pop.o \
	zip_source_read.o zip_source_stat.o zip_source_window.o \
	zip_source_zip.o zip_source_zip_new.o zip_stat.o \
	zip_stat_index.o zip_stat_init.o zip_strerror.o \
	zip_string.o zip_unchange.o zip_unchange_all.o \
	zip_unchange_archive.o zip_unchange_data.o zip_utf-8.o

#OFILES=libr_zip.a $(OBJS)
OFILES=$(OBJS)

#CFLAGS+=-g -ggdb -fPIC
CFLAGS+=-I../../libr/include -I../include/
LDFLAGS+=-L../../../libr/util
LINKFLAGS=../zlib/libr_z.a
#LDFLAGS=-shared
EXT_SO?=dylib
LIBNAME=libr_zip.${SOVER}

LIBAR=libr_zip.a

all: ${LIBNAME} ${LIBAR}

${LIBNAME}: ${OBJS}
ifneq ($(SILENT),)
	@echo LIB ${LIBNAME}
endif
	${CC} ${LDFLAGS} $(LDFLAGS_SHARED) -o $@ ${OBJS} ${LINKFLAGS}

${LIBAR}: ${OFILES}
	#${CC_AR} $(LIBAR) ${OFILES}
	${CC_AR} ${OFILES}
	${RANLIB} ${LIBAR}

clean:
	rm -f ${LIBNAME} *.o *.a *.d *.${EXT_SO}
