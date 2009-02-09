/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include "r_core.h"

static int cursor = 0;
static int flags = R_PRINT_FLAGS_ADDRMOD;
static int printidx = 0;

/* TODO: use r_cmd here in core->vcmd..optimize over 255 table */ 
int r_core_visual_cmd(struct r_core_t *core, int ch)
{
	char buf[1024];

	switch(ch) {
	case 'c':
		cursor ^= 1;
		if (cursor) flags|=R_PRINT_FLAGS_CURSOR;
		else flags &= !(flags&R_PRINT_FLAGS_CURSOR);
		r_print_set_flags(flags);
		break;
	case 'C':
		cursor ^= 1;
		if (cursor) flags|=R_PRINT_FLAGS_COLOR;
		else flags &= !(flags&R_PRINT_FLAGS_COLOR);
		r_print_set_flags(flags);
		break;
	case 'H':
		r_core_cmd(core, "s- 2", 0);
		break;
	case 'L':
		r_core_cmd(core, "s+ 2", 0);
		break;
	case 'h':
		r_core_cmd(core, "s- 1", 0);
		break;
	case 'l':
		r_core_cmd(core, "s+ 1", 0);
		break;
	case 'j':
		r_core_cmd(core, "s+ 16", 0);
		break;
	case 'k':
		r_core_cmd(core, "s- 16", 0);
		break;
	case 'J':
		r_core_cmd(core, "s++", 0);
		break;
	case 'K':
		r_core_cmd(core, "s--", 0);
		break;
	case 'p':
		printidx++;
		break;
	case 'P':
		printidx--;
		break;
	case '-':
		r_core_block_size( core, core->blocksize-1);
		break;
	case '+':
		r_core_block_size( core, core->blocksize+1);
		break;
	case '/':
		r_core_block_size( core, core->blocksize-=16);
		break;
	case '*':
		r_core_block_size( core, core->blocksize+=16);
		break;
	case ':':
		r_cons_fgets(buf, 1023, 0, NULL);
		r_core_cmd(core, buf, 0);
		break;
	case '?':
		r_cons_clear00();
		r_cons_printf(
		"\nVisual mode help:\n\n"
		" hjkl  -  move around\n"
		" HJKL  -  move around faster\n"
		" P||p  -  rotate print modes\n"
		" /*+-  -  change block size\n"
		" :cmd  -  run radare command\n"
		" q     -  back to radare shell\n");
		r_cons_flush();
		r_cons_any_key();
		break;
	case 'q':
		return 0;
	}
	return 1;
}

int r_core_visual(struct r_core_t *core, const char *input)
{
	int ch;
	char *printfmt[] = { "x", "pd", "p8", "pc", "ps" };

	while(input[0]) {
		if (!r_core_visual_cmd(core, input[0])) {
			r_cons_clear00();
			r_core_cmd(core, printfmt[printidx%5], 0);
			r_cons_flush();
			r_cons_any_key();
			return 0;
		}
		input = input + 1;
	}

	do {
		r_cons_clear00();
		r_core_cmd(core, printfmt[printidx%5], 0);
		r_cons_flush();
		ch = r_cons_readchar();
	} while (r_core_visual_cmd(core, ch));
	return 0;
}
