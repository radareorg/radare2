/* radare2 - LGPL - Copyright 2020-2026 - abcSup */

#include "dmp64.h"

static int r_bin_dmp64_init_memory_runs(struct r_bin_dmp64_obj_t *obj) {
	dmp64_p_memory_desc *mem_desc = &obj->header->PhysicalMemoryBlockBuffer;
	if (!memcmp (mem_desc, DMP_UNUSED_MAGIC, 4)) {
		R_LOG_WARN ("Invalid PhysicalMemoryDescriptor");
		return false;
	}
	const ut8 *mem_desc_buf = (const ut8 *)mem_desc;
	ut32 num_runs = r_read_le32 (mem_desc_buf + r_offsetof (dmp64_p_memory_desc, NumberOfRuns));
	ut64 expected_pages = r_read_le64 (mem_desc_buf + r_offsetof (dmp64_p_memory_desc, NumberOfPages));
	ut64 runs_offset = r_offsetof (dmp64_header, PhysicalMemoryBlockBuffer) + r_offsetof (dmp64_p_memory_desc, Run);
	ut64 max_runs_size = r_offsetof (dmp64_header, ContextRecord) - runs_offset;
	ut64 runs_size = 0;
	if (num_runs < 1 || r_mul_overflow ((ut64)num_runs, (ut64)sizeof (dmp_p_memory_run), &runs_size) || runs_size > max_runs_size) {
		R_LOG_WARN ("Invalid PhysicalMemoryDescriptor");
		return false;
	}
	ut64 file_size = r_buf_size (obj->b);
	ut64 base = sizeof (dmp64_header);
	if (file_size < base) {
		R_LOG_WARN ("Invalid dump size");
		return false;
	}
	ut64 max_file_pages = (file_size - base) / DMP_PAGE_SIZE;
	obj->pages = r_list_newf (free);

	ut64 num_page = 0;
	ut32 i;
	for (i = 0; i < num_runs; i++) {
		ut8 run_buf[sizeof (dmp_p_memory_run)];
		ut64 run_offset = runs_offset + (ut64)i * sizeof (dmp_p_memory_run);
		if (r_buf_read_at (obj->b, run_offset, run_buf, sizeof (run_buf)) != sizeof (run_buf)) {
			R_LOG_WARN ("read memory run");
			return false;
		}
		ut64 base_page = r_read_le64 (run_buf + r_offsetof (dmp_p_memory_run, BasePage));
		ut64 page_count = r_read_le64 (run_buf + r_offsetof (dmp_p_memory_run, PageCount));
		if (page_count < 1 || num_page > max_file_pages || page_count > max_file_pages - num_page) {
			R_LOG_WARN ("Invalid PageCount");
			return false;
		}
		if (num_page >= ST32_MAX || page_count > (ut64)ST32_MAX - num_page) {
			R_LOG_WARN ("Invalid PageCount");
			return false;
		}
		ut64 last_page = 0;
		if (r_add_overflow (base_page, page_count - 1, &last_page) || last_page > UT64_MAX / DMP_PAGE_SIZE) {
			R_LOG_WARN ("Invalid PageCount");
			return false;
		}
		ut64 j;
		for (j = 0; j < page_count; j++) {
			dmp_page_desc *page = R_NEW0 (dmp_page_desc);
			page->start = (base_page + j) * DMP_PAGE_SIZE;
			page->file_offset = base + num_page * DMP_PAGE_SIZE;
			r_list_append (obj->pages, page);
			num_page++;
		}
	}
	if (expected_pages != num_page) {
		R_LOG_WARN ("Number of Pages not matches");
	}

	return true;
}

static int r_bin_dmp64_init_header(struct r_bin_dmp64_obj_t *obj) {
	ut8 buf[sizeof (dmp64_header)];
	if (r_buf_read_at (obj->b, 0, buf, sizeof (buf)) < 0) {
		R_LOG_WARN ("read header");
		return false;
	}
	obj->header = R_NEW0 (dmp64_header);
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
	if (!obj->bmp_header) {
		return false;
	}
	ut64 pages = obj->bmp_header->Pages;
	if (!pages || pages > SZT_MAX) {
		return false;
	}
	size_t num_pages = (size_t)pages;
	if (num_pages > SIZE_MAX - 7) {
		return false;
	}
	obj->pages = r_list_newf (free);
	if (!obj->pages) {
		return false;
	}
	ut64 paddr_base = obj->bmp_header->FirstPage;
	RBitmap *bitmap = r_bitmap_new (num_pages);
	if (!bitmap) {
		return false;
	}
	r_bitmap_set_bytes (bitmap, obj->bitmap, (num_pages + 7) / 8);

	ut64 num_bitset = 0;
	size_t i = 0;
	while ((i = r_bitmap_find_next_set (bitmap, i)) != SZT_MAX) {
		dmp_page_desc *page = R_NEW0 (dmp_page_desc);
		page->start = (ut64)i * DMP_PAGE_SIZE;
		page->file_offset = paddr_base + num_bitset * DMP_PAGE_SIZE;
		r_list_append (obj->pages, page);
		num_bitset++;
		i++;
	}
	if (obj->bmp_header->TotalPresentPages != num_bitset) {
		R_LOG_WARN ("TotalPresentPages not matched");
		r_bitmap_free (bitmap);
		return false;
	}

	r_bitmap_free (bitmap);
	return true;
}

static int r_bin_dmp64_init_bmp_header(struct r_bin_dmp64_obj_t *obj) {
	obj->bmp_header = R_NEW0 (dmp_bmp_header);
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
	if (obj->bmp_header->Pages > UT64_MAX - 7) {
		R_LOG_WARN ("Invalid Bitmap Size");
		return false;
	}
	ut64 bitmapsize = (obj->bmp_header->Pages + 7) / 8;
	if (bitmapsize < 1 || bitmapsize > ST32_MAX) {
		R_LOG_WARN ("Invalid Bitmap Size");
		return false;
	}
	obj->bitmap = calloc (1, bitmapsize);
	if (!obj->bitmap) {
		return false;
	}
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
		if (!r_bin_dmp64_init_bmp_header (obj) || !r_bin_dmp64_init_bmp_pages (obj)) {
			return false;
		}
		break;
	case DMP_DUMPTYPE_FULL:
		if (!r_bin_dmp64_init_memory_runs (obj)) {
			return false;
		}
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
	r_unref (obj->b);
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
	obj->kv = sdb_new0 ();
	obj->size = (ut32) r_buf_size (buf);
	obj->b = r_ref (buf);

	if (!r_bin_dmp64_init (obj)) {
		r_bin_dmp64_free (obj);
		return NULL;
	}

	return obj;
}
