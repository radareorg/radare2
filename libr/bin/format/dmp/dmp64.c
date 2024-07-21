/* radare2 - LGPL - Copyright 2020-2024 - abcSup */

#include "dmp64.h"

static int r_bin_dmp64_init_memory_runs(struct r_bin_dmp64_obj_t *obj) {
	int i, j;
	dmp64_p_memory_desc *mem_desc = &obj->header->PhysicalMemoryBlockBuffer;
	if (!memcmp (mem_desc, DMP_UNUSED_MAGIC, 4)) {
		R_LOG_WARN ("Invalid PhysicalMemoryDescriptor");
		return false;
	}
	ut64 num_runs = mem_desc->NumberOfRuns;
	if (num_runs * sizeof (dmp_p_memory_run) >= r_offsetof (dmp64_header, ContextRecord)) {
		R_LOG_WARN ("Invalid PhysicalMemoryDescriptor");
		return false;
	}
	obj->pages = r_list_newf (free);
	if (!obj->pages) {
		return false;
	}
	dmp_p_memory_run *runs = calloc (num_runs, sizeof (dmp_p_memory_run));
	ut64 num_runs_offset = r_offsetof (dmp64_header, PhysicalMemoryBlockBuffer) + r_offsetof (dmp64_p_memory_desc, NumberOfRuns);
	if (r_buf_read_at (obj->b, num_runs_offset, (ut8*)runs, num_runs * sizeof (dmp_p_memory_run)) < 0) {
		R_LOG_WARN ("read memory runs");
		free (runs);
		return false;
	};

	ut64 num_page = 0;
	ut64 base = sizeof (dmp64_header);
	for (i = 0; i < num_runs; i++) {
		dmp_p_memory_run *run = &(runs[i]);
		for (j = 0; j < run->PageCount; j++) {
			dmp_page_desc *page = R_NEW0 (dmp_page_desc);
			if (!page) {
				free (runs);
				return false;
			}
			page->start = (run->BasePage + j) * DMP_PAGE_SIZE;
			page->file_offset = base + num_page * DMP_PAGE_SIZE;
			r_list_append (obj->pages, page);
			num_page++;
		}
	}
	if (mem_desc->NumberOfPages != num_page) {
		R_LOG_WARN ("Number of Pages not matches");
	}

	free (runs);
	return true;
}

static int r_bin_dmp64_init_header(struct r_bin_dmp64_obj_t *obj) {
	ut8 buf[sizeof (dmp64_header)];
	if (r_buf_read_at (obj->b, 0, buf, sizeof (buf)) < 0) {
		R_LOG_WARN ("read header");
		return false;
	}
	obj->header = R_NEW0 (dmp64_header);
	if (!obj->header) {
		r_sys_perror ("R_NEW0 (header)");
		return false;
	}
	memcpy (obj->header, buf, sizeof (buf));
#define DMPREAD(x) obj->header->x = r_read_le32 (buf + r_offsetof (dmp64_header, x))
#define DMPREAD_64(x) obj->header->x = r_read_le64 (buf + r_offsetof (dmp64_header, x))
	DMPREAD (MajorVersion);
	DMPREAD (MinorVersion);
	DMPREAD_64 (DirectoryTableBase);
	DMPREAD_64 (PfnDataBase);
	DMPREAD_64 (PsLoadedModuleList);
	DMPREAD_64 (PsActiveProcessHead);
	DMPREAD (MachineImageType);
	DMPREAD (NumberProcessors);
	DMPREAD (BugCheckCode);
	DMPREAD_64 (KdDebuggerDataBlock);
	DMPREAD (DumpType);
	DMPREAD (MiniDumpFields);
	DMPREAD (SecondaryDataState);
	DMPREAD (ProductType);
	DMPREAD (SuiteMask);
	DMPREAD (WriterStatus);
	DMPREAD_64 (RequiredDumpSpace);
	DMPREAD_64 (SystemUpTime);
	DMPREAD_64 (SystemTime);
#undef DMPREAD_64
#undef DMPREAD
	obj->dtb = obj->header->DirectoryTableBase;

	return true;
}

static int r_bin_dmp64_init_bmp_pages(struct r_bin_dmp64_obj_t *obj) {
	int i;
	if (!obj->bmp_header) {
		return false;
	}
	obj->pages = r_list_newf (free);
	if (!obj->pages) {
		return false;
	}
	ut64 paddr_base = obj->bmp_header->FirstPage;
	int num_pages = obj->bmp_header->Pages;
	if (num_pages < 1) {
		return false;
	}
	RBitmap *bitmap = r_bitmap_new (num_pages);
	r_bitmap_set_bytes (bitmap, obj->bitmap, num_pages / 8);

	ut64 num_bitset = 0;
	for (i = 0; i < num_pages; i++) {
		if (!r_bitmap_test(bitmap, i)) {
			continue;
		}
		dmp_page_desc *page = R_NEW0 (dmp_page_desc);
		if (R_UNLIKELY (!page)) {
			return false;
		}
		page->start = i * DMP_PAGE_SIZE;
		page->file_offset = paddr_base + num_bitset * DMP_PAGE_SIZE;
		r_list_append (obj->pages, page);
		num_bitset++;
	}
	if (obj->bmp_header->TotalPresentPages != num_bitset) {
		R_LOG_WARN ("TotalPresentPages not matched");
		return false;
	}

	r_bitmap_free (bitmap);
	return true;
}

static int r_bin_dmp64_init_bmp_header(struct r_bin_dmp64_obj_t *obj) {
	if (!(obj->bmp_header = R_NEW0 (dmp_bmp_header))) {
		r_sys_perror ("R_NEW0 (dmp_bmp_header)");
		return false;
	}
	if (r_buf_read_at (obj->b, sizeof (dmp64_header), (ut8*)obj->bmp_header,
			r_offsetof (dmp_bmp_header, Bitmap)) < 0) {
		R_LOG_WARN ("read bmp_header");
		return false;
	}
	obj->bmp_header->FirstPage = r_read_le64 (&obj->bmp_header->FirstPage);
	obj->bmp_header->TotalPresentPages = r_read_le64 (&obj->bmp_header->TotalPresentPages);
	obj->bmp_header->Pages = r_read_le64 (&obj->bmp_header->Pages);
	if (!!memcmp (obj->bmp_header, DMP_BMP_MAGIC, 8)) {
		R_LOG_WARN ("Invalid Bitmap Magic");
		return false;
	}
	int bitmapsize = obj->bmp_header->Pages / 8;
	if (bitmapsize < 1) {
		R_LOG_WARN ("Invalid Bitmap Size");
		return false;
	}
	obj->bitmap = calloc (1, bitmapsize);
	if (r_buf_read_at (obj->b, sizeof (dmp64_header) + offsetof (dmp_bmp_header, Bitmap), obj->bitmap, bitmapsize) < 0) {
		R_LOG_WARN ("read bitmap");
		return false;
	}

	return true;
}

static int r_bin_dmp64_init(struct r_bin_dmp64_obj_t *obj) {
	if (!r_bin_dmp64_init_header (obj)) {
		R_LOG_WARN ("Invalid Kernel Dump x64 Format");
		return false;
	}
	switch (obj->header->DumpType) {
	case DMP_DUMPTYPE_BITMAPFULL:
	case DMP_DUMPTYPE_BITMAPKERNEL:
		r_bin_dmp64_init_bmp_header (obj);
		r_bin_dmp64_init_bmp_pages (obj);
		break;
	case DMP_DUMPTYPE_FULL:
		r_bin_dmp64_init_memory_runs (obj);
		break;
	default:
		break;
	}

	return true;
}

R_IPI void r_bin_dmp64_free(struct r_bin_dmp64_obj_t *obj) {
	if (!obj) {
		return;
	}
	r_buf_free (obj->b);
	obj->b = NULL;
	free (obj->header);
	free (obj->bmp_header);
	free (obj->runs);
	free (obj->bitmap);
	r_list_free (obj->pages);
	free (obj);
}

R_IPI struct r_bin_dmp64_obj_t *r_bin_dmp64_new_buf(RBuffer* buf) {
	struct r_bin_dmp64_obj_t *obj = R_NEW0 (struct r_bin_dmp64_obj_t);
	if (!obj) {
		return NULL;
	}
	obj->kv = sdb_new0 ();
	obj->size = (ut32) r_buf_size (buf);
	obj->b = r_buf_ref (buf);

	if (!r_bin_dmp64_init (obj)) {
		r_bin_dmp64_free (obj);
		return NULL;
	}

	return obj;
}
