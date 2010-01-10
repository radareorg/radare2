/* radare - LGPL - Copyright 2010 nibble at develsec.org */
/* gcc -I../../../include -DMAIN mach0.c -o mach0 */

#include <unistd.h>
#include <r_types.h>
#include "mach0.h"
#include "mach0_specs.h"

static int r_bin_mach0_init_mhdr(struct r_bin_mach0_obj_t* bin)
{
	lseek(bin->fd, 0, SEEK_SET);
	if (read(bin->fd, &bin->mhdr, sizeof(struct mach_header))
		!= sizeof(struct mach_header)) {
		perror("read (mhdr)");
		return R_FALSE;
	}
	if (bin->mhdr.magic != MH_MAGIC)
		return R_FALSE;
	return R_TRUE;
}

static int r_bin_mach0_init_lcmd(struct r_bin_mach0_obj_t* bin)
{
	return R_TRUE;
}

static int r_bin_mach0_init_scmd(struct r_bin_mach0_obj_t* bin)
{
	return R_TRUE;
}

static int r_bin_mach0_init_scn(struct r_bin_mach0_obj_t* bin)
{
	return R_TRUE;
}

static int r_bin_mach0_init(struct r_bin_mach0_obj_t* bin)
{
	if (!r_bin_mach0_init_mhdr(bin)) {
		ERR("Warning: File is no MACH0\n");
		return R_FALSE;
	}
	if (!r_bin_mach0_init_lcmd(bin))
		ERR("Warning: Cannot initalize load commands\n");
	if (!r_bin_mach0_init_scmd(bin))
		ERR("Warning: Cannot initalize segment commands\n");
	if (!r_bin_mach0_init_scn(bin))
		ERR("Warning: Cannot initalize sections\n");
	return R_TRUE;
}

int r_bin_mach0_open(struct r_bin_mach0_obj_t* bin, const char* file)
{
	if ((bin->fd = open(file, O_RDONLY)) == -1)
		return -1;
	bin->file = file;
	if (!r_bin_mach0_init(bin))
		return -1;
	return bin->fd;
}

int r_bin_mach0_close(struct r_bin_mach0_obj_t* bin)
{
	return close(bin->fd);
}

struct r_bin_mach0_section_t* r_bin_mach0_get_sections(struct r_bin_mach0_obj_t* bin)
{
	return NULL;
}

#ifdef MAIN
int main(int argc, char *argv[])
{
	struct r_bin_mach0_obj_t bin;
	struct r_bin_mach0_section_t *sections;
	int i;

	r_bin_mach0_open(&bin, argv[1]);
	sections = r_bin_mach0_get_sections(&bin);
	for (i = 0; sections && !sections[i].last; i++)
		printf( "offset=%08llx address=%08llx size=%05i name=%s\n",
				sections[i].offset, sections[i].addr, sections[i].size,
				sections[i].name);
	r_bin_mach0_close(&bin);

	return 0;
}
#endif
