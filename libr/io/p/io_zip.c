/* radare - LGPL - Copyright 2012-2013 - pancake 
   io_zip.c rewrite: Adam Pridgen <dso@rice.edu || adam.pridgen@thecoverofnight.com>
 */

#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>
#include <zip.h>


typedef enum{
	R_IO_PARENT_ZIP = 0x0001,
	R_IO_CHILD_FILE = 0x0002,

	R_IO_NEW_FILE = 0x0004,
	R_IO_EXISTING_FILE = 0x0008,
	R_IO_MODIFIED_FILE = 0x0010,
	R_IO_DELETED_FILE = 0x0020,

}R_IO_ZIP_ARCHIVE_TYPE;

typedef struct r_io_zip_uri_const_t {
	const char *name;
	ut32 len;
} RIOZipConstURI;

char *URI = "://";

static RIOZipConstURI ZIP_URIS[] = {
	 {"zip://", 6},
	 {"apk://", 6},
	 {"jar://", 6},
	 {NULL, 0}
};

typedef struct r_io_zip_file_obj_t{
	char * name;
	char * archivename;
	int mode;
	int rw;
	int fd;
	int opened;
	ut64 entry;
	int flags;
	ut8 modified;
	RBuffer *b;
	char *password;
	ut8 encryption_value;
	RIO * io_backref;
} RIOZipFileObj;

RList *r_io_zip_get_files(char *archivename, ut32 flags, int mode, int rw);
static int r_io_zip_init();
static int r_io_zip_plugin_open(RIO *io, const char *file);
static RIODesc * r_io_zip_open(RIO *io, const char *file, int rw, int mode);
int r_io_zip_slurp_file(RIOZipFileObj *zip_file_obj);
RIODesc *check_zip_file_open(RIO *io, const char* filename);
static int r_io_zip_has_uri_substr(const char *file);
static int r_io_zip_check_uri(const char *file);
static int r_io_zip_check_file(const char *file);
int r_io_zip_open_zip_file(RIOZipFileObj * zipFileObj);
RIOZipFileObj * r_io_zip_create_new_file(const char *archivename, const char *filename, struct zip_stat *sb, ut32 flags, int mode, int rw);
RIOZipFileObj *r_io_zip_alloc_zipfileobj(const char *archive_name, const char *filename, ut32 flags, int mode, int rw);
void r_io_zip_free_zipfileobj(RIOZipFileObj *zipFileObj);
static int r_io_zip_flush_file(RIOZipFileObj *zip_file_obj);
static int r_io_zip_read(RIO *io, RIODesc *fd, ut8 *buf, int count);
static int r_io_zip_write(RIO *io, RIODesc *fd, const ut8 *buf, int count);
static int r_io_zip_close(RIODesc *desc);

static int r_io_zip_init(RIO *io) {
	return R_TRUE;
}

static int r_io_zip_has_uri_substr(const char *file) {
	return (file && strstr(file, URI));
}

static int r_io_zip_check_uri(const char *file) {
	int result = R_FALSE; 
	int i = 0;	
	if (r_io_zip_has_uri_substr(file)) {
		for (i = 0; ZIP_URIS[i].name != NULL; i++) {
			if (!memcmp (file, ZIP_URIS[i].name, ZIP_URIS[i].len) && file[ZIP_URIS[i].len]) {
				result = R_TRUE;
				break;
			}
		}
	}
	return result;
}

int r_io_zip_open_zip_file(RIOZipFileObj * zipFileObj) {
	int result = R_FALSE;
	if (zipFileObj->opened) {
		result = R_TRUE;
	}
	return result;
}

struct zip * r_io_zip_open_archive(const char *archivename, ut32 flags, int mode, int rw) {
	int zip_errorp;
	struct zip * zipArch = NULL;

	if (!archivename)
		return zipArch;

	zipArch = zip_open(archivename, flags, &zip_errorp);
	if (!zipArch) {

		if ( zip_errorp == ZIP_ER_INVAL) {
			eprintf("ZIP File Error: Invalid file name (NULL).\n");
		}else if ( zip_errorp == ZIP_ER_OPEN) {
			eprintf("ZIP File Error: File could not be opened file name.\n");
		}else if ( zip_errorp == ZIP_ER_NOENT) {
			eprintf("ZIP File Error: File does not exist.\n");
		}else if (zip_errorp == ZIP_ER_READ) {
			eprintf("ZIP File Error: Read error occurred.\n");
		}else if (zip_errorp == ZIP_ER_NOZIP) {
			eprintf("ZIP File Error: File is not a valid ZIP archive.\n");
		}else if (zip_errorp == ZIP_ER_INCONS) {
			eprintf("ZIP File Error: ZIP file had some inconsistencies archive.\n");
		}else {
			eprintf("ZIP File Error: Something bad happened, get your debug on.\n");
		}
	}
	return zipArch;
}

static int r_io_zip_check_file(const char *file) {
	int result = R_FALSE;
	ut8 buf[10];

	FILE * fp = fopen(file, "rb");
	if (file && fp) {
		fread (buf,1,10,fp);
		if (!memcmp (buf, "\x50\x4b\x03\x04", 4)) {
			result = R_TRUE;
		}
		fclose(fp);
	}
	return result;
}

int r_io_zip_slurp_file(RIOZipFileObj *zip_file_obj) {
	struct zip_file *zFile = NULL;
	int result = R_FALSE;
	struct zip * zipArch = r_io_zip_open_archive(zip_file_obj->archivename, zip_file_obj->flags, zip_file_obj->mode, zip_file_obj->rw);
	struct zip_stat sb; 
	//eprintf("Slurping file");
	if (zip_file_obj && zip_file_obj->entry != -1) {

		zFile = zip_fopen_index(zipArch, zip_file_obj->entry, 0);
		if (!zip_file_obj->b) {
			zip_file_obj->b = r_buf_new();
		}
		zip_stat_init(&sb);

		if (zFile && zip_file_obj->b && !zip_stat_index(zipArch, zip_file_obj->entry, 0, &sb) ) {

			ut8 *buf = malloc(sb.size);
			memset(buf, 0, sb.size);

			if (buf) {			
				zip_fread(zFile, buf, sb.size);
				r_buf_set_bytes(zip_file_obj->b, buf, sb.size);
				zip_file_obj->opened = 1;
				result = R_TRUE;
			}
			if (buf)
				free(buf);
		}
		if (zFile) {
			zip_fclose(zFile);
		}
	}
	if (zipArch)
		zip_close(zipArch);

	return result;
}

RList * r_io_zip_get_files(char *archivename, ut32 flags, int mode, int rw) {
	ut64 num_entries = 0, i = 0;
	struct zip * zipArch = r_io_zip_open_archive(archivename, flags, mode, rw);
	struct zip_stat sb; 
	RList *files = NULL; 
	//eprintf("Slurping file");
	if (zipArch) {
		files = r_list_new();
		num_entries = zip_get_num_files(zipArch);

		for (i=0; i < num_entries; i++) {
			char *name = NULL;	
			zip_stat_init(&sb );
			zip_stat_index(zipArch, i, 0, &sb );	
			//eprintf("Comparing %s == %s = %d\n", sb.name, filename, strcmp(sb.name, filename));
			name = strdup(sb.name);
			if (name) {
				r_list_append(files, name);
			}

		}
	}
	if (zipArch)
		zip_close(zipArch);

	return files;
}

int r_io_zip_flush_file(RIOZipFileObj *zip_file_obj) {
	int result = R_FALSE;
	struct zip * zipArch = r_io_zip_open_archive(zip_file_obj->archivename, zip_file_obj->flags, zip_file_obj->mode, zip_file_obj->rw);  

	if (!zipArch) {
		return result;
	}

	if (zip_file_obj) {
		struct zip_source *s = zip_source_buffer(zipArch, zip_file_obj->b, zip_file_obj->b->length, 0);
		if (s && zip_file_obj->entry != -1) {

			if (zip_replace(zipArch, zip_file_obj->entry, s) == 0)
				result = R_TRUE;

		}else if (s && zip_file_obj->name) {

			if (zip_add(zipArch, zip_file_obj->name, s) == 0) {

				zip_file_obj->entry = zip_name_locate(zipArch, zip_file_obj->name, 0);
				result = R_TRUE;
			}
		}
		if (s)
			zip_source_free(s);		

	}

	if (zipArch)
		zip_close(zipArch);

	return result;
}

void r_io_zip_free_zipfileobj(RIOZipFileObj *zipFileObj) {
	if (zipFileObj) {
		if (zipFileObj->modified) {
			r_io_zip_flush_file(zipFileObj);
		}
		if (zipFileObj->name) {
			free(zipFileObj->name);
		}
		if (zipFileObj->password) {
			free(zipFileObj->password);
		}
		if (zipFileObj->b) {
			r_buf_free(zipFileObj->b);
		}
		free(zipFileObj);
	}

}

// Below this line are the r_io_zip plugin APIs
static RIODesc *r_io_zip_open(RIO *io, const char *file, int rw, int mode) {
	RIODesc *result = NULL;
	RIOZipFileObj *zipFileObj = NULL;

	char *zip_uri = NULL, *zip_filename = NULL, *filename_in_zipfile = NULL;
	if (!r_io_zip_plugin_open (io, file)) {
		return result;
	}

	zip_uri = strdup(file);
	// 1) Tokenize to the '//' and find the base file directory ('/')
	zip_filename = strstr(zip_uri, "//");
	if (zip_filename && zip_filename[2]) {
		if (zip_filename[0] && zip_filename[0] == '/' &&
			zip_filename[1] && zip_filename[1] == '/' ) {
			*zip_filename++ = 0;	
		}
		*zip_filename++ = 0;

		filename_in_zipfile = strstr(zip_filename, "//");
		if (filename_in_zipfile && filename_in_zipfile[2]) {
			// null terminating uri to filename here.
			*filename_in_zipfile++ = 0;
			*filename_in_zipfile++ = 0;
		}
	}

	if (!zip_filename) {// && !filename_in_zipfile) {
		if (zip_uri)
			free(zip_uri);
		eprintf("usage: zip:///path/to/archive//filepath\n");
		eprintf("Archive was not found.\n");

		return result;
	}

	// Failed to find the file name the archive.
	if (!filename_in_zipfile) {
		RList *files = NULL;
		RListIter *iter, *iter_tmp;
		char *name;
		//eprintf("usage: zip:///path/to/archive//filepath\n");
		eprintf("\nFiles in archive\n\n");
		files = r_io_zip_get_files(zip_filename, 0, mode, rw );

		if (files) {
			int i = 0;
			r_list_foreach_safe(files, iter, iter_tmp, name) {
				// XXX - io->printf does not flush
				// io->printf("%s\n", name);
				r_cons_printf("%s\n", name);
				r_cons_flush ();
				free (name);
				r_list_delete (files, iter);
			}
			r_list_free (files);
		}
		eprintf("\n");
		return result;
	}
	//eprintf("After parsing the given uri: %s\n", file);		
	//eprintf("Zip filename the given uri: %s\n", zip_filename);
	//eprintf("File in the zip: %s\n", filename_in_zipfile);
	zipFileObj = r_io_zip_alloc_zipfileobj (zip_filename,
		filename_in_zipfile, ZIP_CREATE, mode, rw);
	if (zipFileObj && zipFileObj->entry == -1)
		eprintf ("Warning: File did not exist, creating a new one.\n");

	if (zipFileObj) {
		zipFileObj->io_backref = io;
		result = r_io_desc_new(&r_io_plugin_zip, zipFileObj->fd, zipFileObj->name, rw, mode, zipFileObj); 
	}

	if (!result) {
		eprintf ("Failed to open the archive %s and file %s\n",
			zip_filename, filename_in_zipfile);
		free (zipFileObj);
	}	
	free (zip_uri);
	return result;
	}


static ut64 r_io_zip_lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RIOZipFileObj *zip_file_obj;

	ut64 seek_val = 0;
	if (fd == NULL || fd->data == NULL)
		return -1;

	zip_file_obj = fd->data;

	seek_val = zip_file_obj->b->cur;

	switch (whence) {
	case SEEK_SET:
		seek_val = zip_file_obj->b->length < offset ? zip_file_obj->b->length : offset;
		zip_file_obj->b->cur = io->off = seek_val; 
		return seek_val;
	case SEEK_CUR:
		seek_val = zip_file_obj->b->length < offset + zip_file_obj->b->cur ? zip_file_obj->b->length : offset + zip_file_obj->b->cur;
		zip_file_obj->b->cur = io->off = seek_val;
		return seek_val;

	case SEEK_END:
		seek_val = zip_file_obj->b->length;
		zip_file_obj->b->cur = io->off = seek_val;
		return seek_val;
	}
	return seek_val;
}

static int r_io_zip_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOZipFileObj *zip_file_obj = NULL;
	if (fd == NULL || fd->data == NULL || buf == NULL)
		return -1;

	zip_file_obj = fd->data;
	if (zip_file_obj->b->length < io->off)
		io->off = zip_file_obj->b->length;

	return r_buf_read_at(zip_file_obj->b, io->off, buf, count);
}

static int r_io_zip_write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RIOZipFileObj *zip_file_obj = NULL;
	if (fd == NULL || fd->data == NULL || buf == NULL)
		return -1;
	zip_file_obj = fd->data;


	if (zip_file_obj->b->length < io->off)
		io->off = zip_file_obj->b->length;

	zip_file_obj->modified = 1;
	return r_buf_write_at(zip_file_obj->b, io->off, buf, count);
}

static int r_io_zip_close(RIODesc *fd) {
	RIOZipFileObj *zip_file_obj = NULL;
	//eprintf("Am I called 2x?\n");
	// this api will be called multiple times :/
	if (fd == NULL || fd->data)
		return -1;

	zip_file_obj = fd->data;
	r_io_zip_free_zipfileobj(zip_file_obj);
	zip_file_obj = fd->data = NULL;
	return 0;
}

RIOZipFileObj* r_io_zip_alloc_zipfileobj(const char *archivename, const char *filename, ut32 flags, int mode, int rw) {
	ut64 i, num_entries;
	struct zip_stat sb;
	struct zip * zipArch = r_io_zip_open_archive(archivename, flags, mode, rw);  
	RIOZipFileObj *zipFileObj = NULL;
	if (!zipArch)
		return zipFileObj;
	num_entries = zip_get_num_files(zipArch);

	for (i=0; i < num_entries; i++) {

		zip_stat_init(&sb );
		zip_stat_index(zipArch, i, 0, &sb );	
		//eprintf("Comparing %s == %s = %d\n", sb.name, filename, strcmp(sb.name, filename));
		if (strcmp(sb.name, filename) == 0) {

			zipFileObj = r_io_zip_create_new_file(archivename, filename, &sb, flags, mode, rw);
			r_io_zip_slurp_file(zipFileObj);
			break;
		}
	}

	if (!zipFileObj) {
		zipFileObj = r_io_zip_create_new_file(archivename, filename, NULL, flags, mode, rw);
	}

	if (zipArch)
		zip_close(zipArch);

	return zipFileObj;
}


RIOZipFileObj *r_io_zip_create_new_file(const char *archivename, const char *filename, struct zip_stat *sb, ut32 flags, int mode, int rw) {
	RIOZipFileObj *zip_file_obj = NULL;

	zip_file_obj = malloc(sizeof(RIOZipFileObj));
	if (zip_file_obj)
		memset(zip_file_obj, 0, sizeof(RIOZipFileObj));


	zip_file_obj->archivename = strdup(archivename);
	zip_file_obj->b = r_buf_new();
	zip_file_obj->name = sb == NULL ? strdup(filename) : strdup(sb->name);
	zip_file_obj->entry = sb == NULL ? -1 : sb->index;
	zip_file_obj->fd = r_num_rand (0xFFFF);

	zip_file_obj->mode = mode;
	zip_file_obj->rw = rw;
	zip_file_obj->flags = flags;

	return zip_file_obj;
}

static int r_io_zip_plugin_open(RIO *io, const char *file) {	
	return (io && file) && (r_io_zip_check_uri(file));
}

RIOPlugin r_io_plugin_zip = {
	.name = "zip",
	.desc = "Open zip files apk://foo.apk//MANIFEST or zip://foo.apk//theclass/fun.class, and show files with: zip://foo.apk/",
	.license = "BSD",
	.open = r_io_zip_open,
	.write = r_io_zip_write,
	.read = r_io_zip_read,
	.close = r_io_zip_close,
	.lseek = r_io_zip_lseek,
	.plugin_open = r_io_zip_plugin_open,
	.system = NULL,
	.debug = NULL,
	.init = r_io_zip_init
};

#ifndef CORELIB
	struct r_lib_struct_t radare_plugin = {
		.type = R_LIB_TYPE_IO,
		.data = &r_io_plugin_zip
	};
#endif
