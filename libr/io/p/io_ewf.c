/* radare - LGPL - Copyright 2007-2013 pancake */

// XXX: not yet tested

#include "r_io.h"
#include "r_lib.h"
#include <r_userconf.h>

#if HAVE_LIB_EWF
#include <sys/types.h>
#include <sys/ipc.h>
#include <libewf.h>

struct r_io_plugin_t r_io_plugin_ewf;
//#define EWF_FD 0x19b19b
typedef struct {
	int fd;
	libewf_handle_t *handle;
} RIOEwf;
#define RIOEWF_TO_FD(x) ((int)(size_t)(x))
#define RIOEWF_HANDLE(x) (((RIOEwf*)x->data)->handle)
#define RIOEWF_IS_VALID(x) ((x) && (x->data) && (x->plugin==&r_io_plugin_ewf))

static int ewf__write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	return libewf_handle_write_buffer (RIOEWF_HANDLE (fd),
		(void*)buf, count, NULL);
}

static int ewf__read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	return libewf_handle_read_buffer (RIOEWF_HANDLE (fd), buf, count, NULL);
}

static int ewf__close(RIODesc *fd) {
	if (RIOEWF_IS_VALID (fd)) {
		libewf_handle_close (RIOEWF_HANDLE (fd), NULL);
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
			offset += io->off;
			break;
		case SEEK_END:
			if (libewf_handle_get_media_size (
					RIOEWF_HANDLE (fd), &media_size, NULL))
				offset = media_size - offset;
			break;
		}
		libewf_handle_seek_offset (RIOEWF_HANDLE (fd), offset, whence, NULL);
		return offset;
	}
	return (ut64)-1;
}

static int ewf__plugin_open(RIO *io, const char *pathname, ut8 many) {
	if ((!strncmp (pathname, "ewf://", 6))
	||  (!strncmp (pathname, "els://", 6)))
		return R_TRUE;
	return R_FALSE;
}

static RIODesc *ewf__open(RIO *io, const char *pathname, int rw, int mode) {
	RIOEwf *rewf;
	libewf_handle_t *ewf_h;
	// XXX filename list should be dynamic. 1024 limit is ugly
	const char *filenames[1024];
	char *ptr,*optr;
	ut8 hash[1024];
	size64_t media_size;
	uint32_t bytes_per_sector;
	//uint64_t amount_of_sectors;
	uint32_t error_granularity;
	//uint32_t amount_of_acquiry_errors;
	int8_t compression_level;
	uint8_t media_type;
	uint8_t media_flags;
	uint8_t compress_empty_block;
	uint8_t format;
	int i;

	if (!strncmp (pathname, "els://", 6)) {
		FILE *fd = r_sandbox_fopen (pathname+6, "r");
		ut64 len;
		char *buf;

		if (fd == NULL)
			return NULL;
		fseek (fd, 0, SEEK_END);
		len = ftell (fd);
		fseek(fd, 0, SEEK_SET);
		buf = (char *)malloc (len);
		fread (buf, len, 1, fd);
		
		ptr = strchr (buf, '\n');
		for (i=0, optr = buf; ptr&&(ptr=strchr(ptr, '\n')); optr=ptr) {
			*ptr = '\0';
			ptr++;
			filenames[i++] = optr;
		}
		filenames[i] = NULL;

		free (buf);
		fclose (fd);

		for (i=0; filenames[i]; i++)
			eprintf ("%02x: %s)\n", i, filenames[i]);
	} else {
		filenames[0] = pathname + 6;
		filenames[1] = NULL;
	}
	libewf_handle_initialize (&ewf_h, NULL);
	if (libewf_handle_open (ewf_h, (char * const *)filenames, (int)1, rw?
			LIBEWF_OPEN_READ_WRITE: LIBEWF_OPEN_READ, NULL) != 1)
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
	libewf_handle_get_format (ewf_h, &format, NULL);
	eprintf ("FormatVersion:    %d\n", format);
	libewf_handle_get_compression_values (ewf_h,
		&compression_level, &compress_empty_block, NULL);
	eprintf ("CompressionLevel: %d\n", compression_level);
	libewf_handle_get_error_granularity (ewf_h, &error_granularity, NULL);
	eprintf ("ErrorGranurality: %d\n", error_granularity);
	//libewf_handle_get_number_of_sectors (ewf_h, &amount_of_sectors, NULL);
	//eprintf ("AmountOfSectors:  %"PFMT64d"\n", amount_of_sectors);
	libewf_handle_get_bytes_per_sector (ewf_h, &bytes_per_sector, NULL);
	eprintf ("BytesPerSector:   %d\n", bytes_per_sector);
	libewf_handle_get_media_size (ewf_h, &media_size, NULL);
	eprintf ("MediaSize:        %"PFMT64d"\n", media_size);
	libewf_handle_get_media_type (ewf_h, &media_type, NULL);
	eprintf ("MediaType:        %d\n", media_type);
	libewf_handle_get_media_flags (ewf_h, &media_flags, NULL);
	eprintf ("MediaFlags:       %d\n", media_flags);
	libewf_handle_get_md5_hash (ewf_h, hash, 128, NULL);
	eprintf ("CalculatedHash:   %s\n", hash);

	rewf = R_NEW (RIOEwf);
	rewf->handle = ewf_h;
	rewf->fd = RIOEWF_TO_FD (rewf);
	return r_io_desc_new (&r_io_plugin_shm, rewf->fd, pathname, rw, mode, rewf);
}

RIOPlugin r_io_plugin_ewf = {
        //void *plugin;
	.name = "ewf",
        .desc = "Forensic file formats (Encase, ..) (ewf://file, els://file)",
	.license = "LGPL3",
        .open = ewf__open,
        .close = ewf__close,
	.read = ewf__read,
        .plugin_open = ewf__plugin_open,
        //.plugin_fd = ewf__plugin_fd,
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
#else
struct r_io_plugin_t r_io_plugin_ewf = {
        .name = NULL,
        .desc = NULL
};

#endif
