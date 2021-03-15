/* radare2 - LGPL - Copyright 2020 - abcSup */

#include <r_types.h>
#include <r_util.h>

#include "dmp64.h"

static int r_bin_dmp64_init_memory_runs(struct r_bin_dmp64_obj_t *obj) {
	int i, j;
	dmp64_p_memory_desc *mem_desc = &obj->header->PhysicalMemoryBlockBuffer;
	if (!memcmp (mem_desc, DMP_UNUSED_MAGIC, 4)) {
		eprintf ("Warning: Invalid PhysicalMemoryDescriptor\n");
		return false;
	}
	ut64 num_runs = mem_desc->NumberOfRuns;
	if (num_runs * sizeof (dmp_p_memory_run) >= r_offsetof (dmp64_header, ContextRecord)) {
		eprintf ("Warning: Invalid PhysicalMemoryDescriptor\n");
		return false;
	}
	obj->pages = r_list_newf (free);
	if (!obj->pages) {
		return false;
	}
	dmp_p_memory_run *runs = calloc (num_runs, sizeof (dmp_p_memory_run));
	ut64 num_runs_offset = r_offsetof (dmp64_header, PhysicalMemoryBlockBuffer) + r_offsetof (dmp64_p_memory_desc, NumberOfRuns);
	if (r_buf_read_at (obj->b, num_runs_offset, (ut8*)runs, num_runs * sizeof (dmp_p_memory_run)) < 0) {
		eprintf ("Warning: read memory runs\n");
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
			page->start = (run->BasePage + j) * DMP_PAGE_SIZE ;
			page->file_offset = base + num_page * DMP_PAGE_SIZE;
			r_list_append (obj->pages, page);
			num_page++;
		}
	}
	if (mem_desc->NumberOfPages != num_page) {
		eprintf ("Warning: Number of Pages not matches\n");
	}

	free (runs);
	return true;
}

static int r_bin_dmp64_init_header(struct r_bin_dmp64_obj_t *obj) {
	if (!(obj->header = R_NEW0 (dmp64_header))) {
		r_sys_perror ("R_NEW0 (header)");
		return false;
	}
	if (r_buf_read_at (obj->b, 0, (ut8*)obj->header, sizeof (dmp64_header)) < 0) {
		eprintf ("Warning: read header\n");
		return false;
	}
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
	ut64 num_pages = obj->bmp_header->Pages;
	RBitmap *bitmap = r_bitmap_new (num_pages);
	r_bitmap_set_bytes (bitmap, obj->bitmap, num_pages / 8);

	ut64 num_bitset = 0;
	for(i = 0; i < num_pages; i++) {
		if (!r_bitmap_test(bitmap, i)) {
			continue;
		}
		dmp_page_desc *page = R_NEW0 (dmp_page_desc);
		if (!page) {
			return false;
		}
		page->start = i * DMP_PAGE_SIZE;
		page->file_offset = paddr_base + num_bitset * DMP_PAGE_SIZE;
		r_list_append (obj->pages, page);
		num_bitset++;
	}
	if (obj->bmp_header->TotalPresentPages != num_bitset) {
		eprintf ("Warning: TotalPresentPages not matched\n");
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
	if (r_buf_read_at (obj->b, sizeof (dmp64_header), (ut8*)obj->bmp_header, offsetof (dmp_bmp_header, Bitmap)) < 0) {
		eprintf ("Warning: read bmp_header\n");
		return false;
	}
	if (!!memcmp (obj->bmp_header, DMP_BMP_MAGIC, 8)) {
		eprintf ("Warning: Invalid Bitmap Magic\n");
		return false;
	}
	ut64 bitmapsize = obj->bmp_header->Pages / 8;
	obj->bitmap = calloc (1, bitmapsize);
	if (r_buf_read_at (obj->b, sizeof (dmp64_header) + offsetof (dmp_bmp_header, Bitmap), obj->bitmap, bitmapsize) < 0) {
		eprintf ("Warning: read bitmap\n");
		return false;
	}

	return true;
}

static int r_bin_dmp64_init(struct r_bin_dmp64_obj_t *obj) {
	if (!r_bin_dmp64_init_header (obj)) {
		eprintf ("Warning: Invalid Kernel Dump x64 Format\n");
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

void r_bin_dmp64_free(struct r_bin_dmp64_obj_t *obj) {
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

struct r_bin_dmp64_obj_t *r_bin_dmp64_new_buf(RBuffer* buf) {
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
