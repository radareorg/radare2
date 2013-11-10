OBJ_ZIP=io_zip.o

STATIC_OBJ+=${OBJ_ZIP}
TARGET_ZIP=io_zip.${EXT_SO}
ALL_TARGETS+=${TARGET_ZIP}


ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../lib/libr_lib.a
LINKFLAGS+=../../io/libr_io.a
LINKFLAGS+=../../../shlr/zip/libr_zip.a
else
LINKFLAGS+=-L../../lib -lr_lib 
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -L../../lib -lr_lib -lr_io 
LINKFLAGS+=-L../../../shlr/zip/ -lr_zip
endif

ZIPOBJS=${OBJ_ZIP}

ZIPOBJS+= ../../../shlr/zip/zip/zip_add.o ../../../shlr/zip/zip/zip_add_dir.o 
ZIPOBJS+= ../../../shlr/zip/zip/zip_add_entry.o ../../../shlr/zip/zip/zip_close.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_delete.o ../../../shlr/zip/zip/zip_dir_add.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_dirent.o ../../../shlr/zip/zip/zip_discard.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_entry.o ../../../shlr/zip/zip/zip_err_str.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_error.o ../../../shlr/zip/zip/zip_error_clear.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_error_get.o ../../../shlr/zip/zip/zip_error_get_sys_type.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_error_strerror.o ../../../shlr/zip/zip/zip_error_to_str.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_extra_field.o ../../../shlr/zip/zip/zip_extra_field_api.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_fclose.o ../../../shlr/zip/zip/zip_fdopen.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_file_add.o ../../../shlr/zip/zip/zip_file_error_clear.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_file_error_get.o ../../../shlr/zip/zip/zip_file_get_comment.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_file_get_offset.o ../../../shlr/zip/zip/zip_file_rename.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_file_replace.o ../../../shlr/zip/zip/zip_file_set_comment.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_file_strerror.o ../../../shlr/zip/zip/zip_filerange_crc.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_fopen.o ../../../shlr/zip/zip/zip_fopen_encrypted.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_fopen_index.o ../../../shlr/zip/zip/zip_fopen_index_encrypted.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_fread.o ../../../shlr/zip/zip/zip_get_archive_comment.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_get_archive_flag.o ../../../shlr/zip/zip/zip_get_compression_implementation.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_get_encryption_implementation.o ../../../shlr/zip/zip/zip_get_file_comment.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_get_num_entries.o ../../../shlr/zip/zip/zip_get_num_files.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_get_name.o ../../../shlr/zip/zip/zip_memdup.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_name_locate.o ../../../shlr/zip/zip/zip_new.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_open.o ../../../shlr/zip/zip/zip_rename.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_replace.o ../../../shlr/zip/zip/zip_set_archive_comment.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_set_archive_flag.o ../../../shlr/zip/zip/zip_set_default_password.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_set_file_comment.o ../../../shlr/zip/zip/zip_set_file_compression.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_set_name.o ../../../shlr/zip/zip/zip_source_buffer.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_source_close.o ../../../shlr/zip/zip/zip_source_crc.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_source_deflate.o ../../../shlr/zip/zip/zip_source_error.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_source_file.o ../../../shlr/zip/zip/zip_source_filep.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_source_free.o ../../../shlr/zip/zip/zip_source_function.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_source_layered.o ../../../shlr/zip/zip/zip_source_open.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_source_pkware.o ../../../shlr/zip/zip/zip_source_pop.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_source_read.o ../../../shlr/zip/zip/zip_source_stat.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_source_window.o ../../../shlr/zip/zip/zip_source_zip.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_source_zip_new.o ../../../shlr/zip/zip/zip_stat.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_stat_index.o ../../../shlr/zip/zip/zip_stat_init.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_strerror.o ../../../shlr/zip/zip/zip_string.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_unchange.o ../../../shlr/zip/zip/zip_unchange_all.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_unchange_archive.o ../../../shlr/zip/zip/zip_unchange_data.o 
ZIPOBJS+=../../../shlr/zip/zip/zip_utf-8.o




${TARGET_ZIP}: ${OBJ_ZIP}
	@echo ${LINKFLAGS}
	${CC_LIB} $(call libname,io_zip) ${CFLAGS} -o ${TARGET_ZIP} ${OBJS} ${LINKFLAGS}
