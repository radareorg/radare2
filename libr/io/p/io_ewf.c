/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

// XXX: not yet tested

#if HAVE_LIB_EWF
#include "r_io.h"
#include "r_lib.h"
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/ewf.h>

#define EWF_FD 0x19b19b
static int ewf_fd = -1;
static LIBEWF_HANDLE *ewf_h = NULL;

static int ewf__write(struct r_io_t *io, int fd, const ut8 *buf, int count) {
	return libewf_write_buffer(ewf_h, buf, count);
}

static int ewf__read(struct r_io_t *io, int fd, ut8 *buf, int count) {
	return libewf_read_buffer(ewf_h, buf, count);
}

static int ewf__close(struct r_io_t *io, int fd) {
	if (fd == ewf_fd) {
		libewf_close(ewf_h);
		ewf_fd = -1;
		return 0;
	}
}

static ut64 ewf__lseek(struct r_io_t *io, int fildes, ut64 offset, int whence) {
	size64_t media_size;

	if (fildes == ewf_fd) {
		switch(whence) {
			case SEEK_SET:
				/* ignore */
				break;
			case SEEK_CUR:
				offset += io->seek;
				break;
			case SEEK_END:
				libewf_get_media_size(ewf_h, &media_size);
				offset = media_size - offset;
				break;
		}
		libewf_seek_offset(ewf_h, offset);
		return offset;
	}

	return lseek(fildes, offset, whence);
}

static int ewf__handle_fd(struct r_io_t *io, int fd) {
	return fd == ewf_fd;
}

static int ewf__handle_open(struct r_io_t *io, const char *pathname)
{
	if ((!memcmp(file, "ewf://", 6))
	||  (!memcmp(file, "els://", 6)))
		return 1;
	return 0;
}

static int ewf__open(struct r_io_t *io, const char *pathname, int flags, int mode) {
	// XXX filename list should be dynamic. 1024 limit is ugly
	const char *filenames[1024];
	char *ptr,*optr;
	char hash[1024];
	size64_t media_size;
	uint32_t bytes_per_sector;
	uint32_t amount_of_sectors;
	uint32_t error_granularity;
	uint32_t amount_of_acquiry_errors;
	int8_t compression_level;
	int8_t media_type;
	int8_t media_flags;
	int8_t volume_type;
	uint8_t compress_empty_block;
	uint8_t format;
	int i;

	if (!memcmp(pathname, "els://", 6)) {
		FILE *fd = fopen(pathname+6, "r");
		ut64 len;
		char *buf;

		if (fd == NULL)
			return -1;
		fseek(fd, 0, SEEK_END);
		len = ftell(fd);
		fseek(fd, 0, SEEK_SET);
		buf = (char *)malloc(len);
		fread(buf, len, 1, fd);
		
		ptr = strchr(buf, '\n');
		for(i=0,optr = buf;ptr&&(ptr=strchr(ptr, '\n'));optr=ptr) {
			ptr[0] = '\0';
			ptr = ptr + 1;
			filenames[i++] = optr;
		}
		filenames[i] = NULL;

		free(buf);
		fclose(fd);

		for(i=0;filenames[i];i++)
			printf("%02x: %s)\n", i, filenames[i]);
	} else {
		filenames[0] = pathname + 6;
		filenames[1] = NULL;
	}
	
	ewf_h = libewf_open(&filenames, 1, 
		(((int)config_get("file.write"))==0)?
		LIBEWF_OPEN_READ_WRITE:LIBEWF_OPEN_READ);


	if (ewf_h == NULL)
		ewf_fd = -1;
	else {
		ewf_fd = EWF_FD;
#if 0
		if( ((libewf_internal_handle_t*)ewf_h)->header_values == NULL ) {
			fprintf( stream, "\tNo information found in file.\n" );
		} else {
			libewf_get_header_value_examiner_name(ewf_h, hash, 128);
			eprintf("ExaminerName:     %s\n", hash);
			libewf_get_header_value_case_number(ewf_h, hash, 128);
			eprintf("CaseNumber:       %s\n", hash);
#endif
			libewf_get_format(ewf_h, &format);
			eprintf("FormatVersion:    %d\n", format);
			libewf_get_compression_values(ewf_h, &compression_level, &compress_empty_block);
			eprintf("CompressionLevel: %d\n", compression_level);
			libewf_get_error_granularity(ewf_h, &error_granularity);
			eprintf("ErrorGranurality: %d\n", error_granularity);
			libewf_get_amount_of_sectors(ewf_h, &amount_of_sectors);
			eprintf("AmountOfSectors:  %d\n", amount_of_sectors);
			libewf_get_bytes_per_sector(ewf_h, &bytes_per_sector);
			eprintf("BytesPerSector:   %d\n", bytes_per_sector);
			libewf_get_volume_type(ewf_h, &volume_type);
			eprintf("VolumeType:       %d\n", volume_type);
			libewf_get_media_size(ewf_h, &media_size);
			eprintf("MediaSize:        %"PFMT64d"\n", media_size);
			libewf_get_media_type(ewf_h, &media_type);
			eprintf("MediaType:        %d\n", media_type);
			libewf_get_media_flags(ewf_h, &media_flags);
			eprintf("MediaFlags:       %d\n", media_flags);
			libewf_get_md5_hash(ewf_h, hash, 128);
			eprintf("CalculatedHash:   %s\n", hash);
#if 0
		}
#endif
	}

	return ewf_fd;
}

static int ewf__init(struct r_io_t *io) {
	return R_TRUE;
}

struct r_io_handle_t r_io_plugin_ewf = {
        //void *handle;
	.name = "ewf",
        .desc = "Forensic file formats (Encase, ..) (ewf://file, els://file)",
        .open = ewf__open,
        .close = ewf__close,
	.read = ewf__read,
        .handle_open = ewf__handle_open,
        .handle_fd = ewf__handle_fd,
	.lseek = ewf__lseek,
	.system = NULL, // ewf__system,
	.init = ewf__init,
	.write = ewf__write,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_ewf
};
#endif
#endif
