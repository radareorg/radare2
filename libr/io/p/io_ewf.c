/* radare - LGPL - Copyright 2007-2011 pancake<nopcode.org> */

// XXX: not yet tested

#if HAVE_LIB_EWF
#include "r_io.h"
#include "r_lib.h"
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/ewf.h>

//#define EWF_FD 0x19b19b
typedef struct {
	int fd;
	LIBEWF_HANDLE *handle;
} RIOEwf;
#define RIOEWF_TO_FD(x) ((int)(size_t)(x))
#define RIOEWF_HANDLE(x) (((RIOEwf*)x->data)->handle)
#define RIOEWF_IS_VALID(x) ((x) && (x->data) && (x->plugin==&r_io_plugin_ewf))

static int ewf__write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	return libewf_write_buffer (RIOEWF_HANDLE (fd), buf, count);
}

static int ewf__read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	return libewf_read_buffer (RIOEWF_HANDLE (fd), buf, count);
}

static int ewf__close(RIODesc *fd) {
	if (RIOEWF_IS_VALID (fd)) {
		libewf_close (RIOEWF_HANDLE (fd));
		return 0;
	}
	return -1;
}

static ut64 ewf__lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	if (RIOEWF_IS_VALID (fd)) {
		size64_t media_size;
		switch (whence) {
		case SEEK_SET:
			/* ignore */
			break;
		case SEEK_CUR:
			offset += io->seek;
			break;
		case SEEK_END:
			libewf_get_media_size (RIOEWF_HANDLE (fd), &media_size);
			offset = media_size - offset;
			break;
		}
		libewf_seek_offset (RIOEWF_HANDLE (fd), offset);
		return offset;
	}
	return (ut64)-1;
}

static int ewf__plugin_open(RIO *io, const char *pathname) {
	if ((!memcmp (file, "ewf://", 6))
	||  (!memcmp (file, "els://", 6)))
		return R_TRUE;
	return R_FALSE;
}

static RIODesc *ewf__open(RIO *io, const char *pathname, int rw, int mode) {
	RIOEwf *rewf;
	LIBEWF_HANDLE *ewf_h;
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

	if (!memcmp (pathname, "els://", 6)) {
		FILE *fd = fopen (pathname+6, "r");
		ut64 len;
		char *buf;

		if (fd == NULL)
			return -1;
		fseek (fd, 0, SEEK_END);
		len = ftell (fd);
		fseek(fd, 0, SEEK_SET);
		buf = (char *)malloc (len);
		fread (buf, len, 1, fd);
		
		ptr = strchr (buf, '\n');
		for (i=0,optr = buf; ptr&&(ptr=strchr(ptr, '\n')); optr=ptr) {
			ptr[0] = '\0';
			ptr = ptr + 1;
			filenames[i++] = optr;
		}
		filenames[i] = NULL;

		free (buf);
		fclose (fd);

		for (i=0;filenames[i];i++)
			eprintf ("%02x: %s)\n", i, filenames[i]);
	} else {
		filenames[0] = pathname + 6;
		filenames[1] = NULL;
	}
	
	ewf_h = libewf_open (&filenames, 1, rw?
		LIBEWF_OPEN_READ_WRITE:LIBEWF_OPEN_READ);
	if (ewf_h == NULL)
		return NULL;
#if 0
		if( ((libewf_internal_plugin_t*)ewf_h)->header_values == NULL ) {
			fprintf( stream, "\tNo information found in file.\n" );
		} else {
			libewf_get_header_value_examiner_name(ewf_h, hash, 128);
			eprintf("ExaminerName:     %s\n", hash);
			libewf_get_header_value_case_number(ewf_h, hash, 128);
			eprintf("CaseNumber:       %s\n", hash);
		}
#endif
	libewf_get_format (ewf_h, &format);
	eprintf ("FormatVersion:    %d\n", format);
	libewf_get_compression_values (ewf_h, &compression_level, &compress_empty_block);
	eprintf ("CompressionLevel: %d\n", compression_level);
	libewf_get_error_granularity (ewf_h, &error_granularity);
	eprintf ("ErrorGranurality: %d\n", error_granularity);
	libewf_get_amount_of_sectors (ewf_h, &amount_of_sectors);
	eprintf ("AmountOfSectors:  %d\n", amount_of_sectors);
	libewf_get_bytes_per_sector (ewf_h, &bytes_per_sector);
	eprintf ("BytesPerSector:   %d\n", bytes_per_sector);
	libewf_get_volume_type (ewf_h, &volume_type);
	eprintf ("VolumeType:       %d\n", volume_type);
	libewf_get_media_size (ewf_h, &media_size);
	eprintf ("MediaSize:        %"PFMT64d"\n", media_size);
	libewf_get_media_type (ewf_h, &media_type);
	eprintf ("MediaType:        %d\n", media_type);
	libewf_get_media_flags (ewf_h, &media_flags);
	eprintf ("MediaFlags:       %d\n", media_flags);
	libewf_get_md5_hash (ewf_h, hash, 128);
	eprintf ("CalculatedHash:   %s\n", hash);

	rewf = R_NEW (RIOEwf)
	rewf->handle = ewf_h;
	rewf->fd = RIOEWF_TO_FD (rewf);
	return r_io_desc_new (&r_io_plugin_shm, rewf->fd, pathname, rw, mode, rewf);
}

struct r_io_plugin_t r_io_plugin_ewf = {
        //void *plugin;
	.name = "ewf",
        .desc = "Forensic file formats (Encase, ..) (ewf://file, els://file)",
        .open = ewf__open,
        .close = ewf__close,
	.read = ewf__read,
        .plugin_open = ewf__plugin_open,
        .plugin_fd = ewf__plugin_fd,
	.lseek = ewf__lseek,
	.system = NULL, // ewf__system,
	.write = ewf__write,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_ewf
};
#endif
#endif
