/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#if 0
TODO: 
  support for multiple keywords
#endif


#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <r_types.h>
#include <r_search.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_io.h>

static struct r_io_t io;
static int hexdump = 0;
static int fd = -1;
static int rad = 0;
struct r_search_t *rs;
static u64 from = 0LL, to = -1;
static char *str;
static char *mask = "";
static int nonstop = 0;
static int mode = R_SEARCH_KEYWORD;
static u64 cur = 0;
static char *buffer = NULL;
static char *curfile = NULL;
static u64 bsize = 4096;
static int hexstr = 0;

static int hit(struct r_search_kw_t *kw, void *user, u64 addr)
{
	const u8 *buf = (u8*)user;
	int delta = addr-cur;
	if (rad) {
		printf("f hit%d_%d 0x%08llx ; %s\n", 0, kw->count, addr, curfile);
	} else {
		printf("==> HIT %d AT 0x%llx ; %s\n", kw->count, addr, curfile);
		if (hexdump) {
			r_print_hexdump(addr, buffer+delta, 16, 78, R_TRUE);
			r_cons_flush();
		}
	}
	return 1;
}

static int show_help(char *argv0, int line)
{
	printf("Usage: %s [-Xnzh] [-f from] [-t to] [-s str] [-z] [-x hex] file ...\n", argv0);
	if (line) return 0;
	printf(
	" -z        search for zero-terminated strings\n"
	" -s [str]  search for zero-terminated strings\n"
	" -x [hex]  search for hexpair string (909090)\n"
	" -f [from] start searching from address 'from'\n"
	" -f [to]   stop search at address 'to'\n"
	" -X        show hexdump of search results\n"
	" -n        do not stop on read errors\n"
	" -h        show this help\n"
	);
	return 0;
}

int radiff_open(char *file)
{
	int last = 0;
	r_io_init(&io);
	// TODO: add support for multiple files
	fd = r_io_open(&io, file, R_IO_READ, 0);
	if (fd == -1) {
		fprintf(stderr, "Cannot open file '%s'\n", file);
		return 1;
	}

	r_cons_init();
	rs = r_search_new(mode);
	buffer = malloc(bsize);
	r_search_set_callback(rs, &hit, buffer);
	if (to == -1) {
		to = r_io_size(&io, fd);
	}
	if (mode == R_SEARCH_KEYWORD) {
		if (hexstr)
			r_search_kw_add_hex(rs, str, mask);
		else r_search_kw_add(rs, str, mask);
	}
	curfile = file;
	r_search_begin(rs);
	r_io_lseek(&io, fd, from, R_IO_SEEK_SET);
	//printf("; %s 0x%08llx-0x%08llx\n", file, from, to);
	for(cur=from; !last && cur<to;cur+=bsize) {
		if ((cur+bsize)>to) {
			bsize = to-cur;
			last=1;
		}
		int ret = r_io_read(&io, fd, buffer, bsize);
		if (ret == 0) {
			if (nonstop) continue;
		//	fprintf(stderr, "Error reading at 0x%08llx\n", cur);
			return 1;
		}
		if (ret != bsize)
			bsize = ret;
		r_search_update_i(rs, cur, buffer, bsize);
	}
	rs = r_search_free(rs);
}

int main(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "s:x:Xzf:t:rnh")) != -1) {
		switch(c) {
		case 'r':
			rad = 1;
			break;
		case 'n':
			nonstop = 1;
			break;
		case 's':
			mode = R_SEARCH_KEYWORD;
			str = optarg;
			hexstr = 0;
			break;
		case 'b':
			bsize = r_num_math(NULL, optarg);
			break;
		case 'z':
			mode = R_SEARCH_STRING;
			break;
		case 'x':
			mode = R_SEARCH_KEYWORD;
			hexstr = 1;
			str = optarg;
			break;
		case 'm':
			// XXX should be from hexbin
			mask = optarg;
			break;
		case 'f':
			from = r_num_math(NULL, optarg);
			break;
		case 't':
			to = r_num_math(NULL, optarg);
			break;
		case 'X':
			hexdump = 1;
			break;
		case 'h':
			return show_help(argv[0], 0);
		}
	}

	if (optind == argc)
		return show_help(argv[0], 1);

	for (;optind < argc;optind++)
		radiff_open(argv[optind]);

	return 0;
}
