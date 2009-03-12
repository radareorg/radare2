/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include "r_core.h"

#define NPF 6
static int printidx = 0;
const char *printfmt[] = { "x", "pd", "p8", "pc", "ps", "s esp&&x 64&&dr&&s eip&&pd" };

static int curset = 0, cursor = -1, ocursor=-1;
static int color = 1;
static int flags = R_PRINT_FLAGS_ADDRMOD;

static int marks_init = 0;
static u64 marks[256];

static void r_core_visual_mark(struct r_core_t *core, u8 ch)
{
	if (marks_init==0) {
		int i;
		for(i=0;i<255;i++)
			marks[i] = 0;
		marks_init = 1;
	}
	marks[ch] = core->seek;
}

static void r_core_visual_mark_seek(struct r_core_t *core, u8 ch)
{
	if (marks_init==0) {
		int i;
		for(i=0;i<255;i++)
			marks[i] = 0;
		marks_init = 1;
	}
	if (marks[ch])
		r_core_seek(core, marks[ch]);
}

/* TODO: use r_cmd here in core->vcmd..optimize over 255 table */ 
int r_core_visual_cmd(struct r_core_t *core, int ch)
{
	char buf[1024];

	switch(ch) {
	case 'c':
		curset ^= 1;
		if (curset) flags|=R_PRINT_FLAGS_CURSOR; // XXX dupped flag imho
		else flags &= !(flags&R_PRINT_FLAGS_CURSOR);
		r_print_set_flags(&core->print, flags);
		break;
	case 'C':
		color ^= 1;
		if (color) flags|=R_PRINT_FLAGS_COLOR;
		else flags &= !(flags&R_PRINT_FLAGS_COLOR);
		r_print_set_flags(&core->print, flags);
		break;
	/* select */
	case 'H':
		if (curset) {
			if (ocursor ==-1) ocursor=cursor;
			cursor--;
		} else
		r_core_cmd(core, "s-2", 0);
		break;
	case 'J':
		if (curset) {
			if (ocursor ==-1) ocursor=cursor;
			cursor+=16;
		} else
		r_core_cmd(core, "s++", 0);
		break;
	case 'K':
		if (curset) {
			if (ocursor ==-1) ocursor=cursor;
			cursor-=16;
		} else
		r_core_cmd(core, "s--", 0);
		break;
	case 'L':
		if (curset) {
			if (ocursor ==-1) ocursor=cursor;
			cursor++;
		} else
		r_core_cmd(core, "s+2", 0);
		break;
	/* move */
	case 'h':
		if (curset) {
			cursor--;
			ocursor=-1;
		} else r_core_cmd(core, "s-1", 0);
		break;
	case 'l':
		if (curset) {
			cursor++;
			ocursor=-1;
		} else r_core_cmd(core, "s+1", 0);
		break;
	case 'j':
		if (curset) {
			cursor+=16;
			ocursor=-1;
		} else r_core_cmd(core, "s+16", 0);
		break;
	case 'k':
		if (curset) {
			cursor-=16;
			ocursor=-1;
		} else r_core_cmd(core, "s- 16", 0);
		break;
	case 's':
		r_core_cmd(core, "ds", 0);
		r_core_cmd(core, ".dr", 0);
		r_core_cmd(core, "s eip", 0);
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
	case 'm':
		r_core_visual_mark(core, r_cons_readchar());
		break;
	case '\'':
		r_core_visual_mark_seek(core, r_cons_readchar());
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
	case 'Q':
		return 0;
	}
	return 1;
}

void r_core_visual_prompt(struct r_core_t *core)
{
	r_cons_printf("[0x%08llx] %s\n", core->seek, printfmt[printidx%NPF]);
}

int r_core_visual(struct r_core_t *core, const char *input)
{
	int ch;

	char *vi = r_config_get(&core->config, "cmd.visual");
	if (vi) r_core_cmd(core, vi, 0);

	while(input[0]) {
		if (!r_core_visual_cmd(core, input[0])) {
			r_cons_clear00();
			r_core_cmd(core, printfmt[printidx%NPF], 0);
			r_cons_flush();
			r_cons_any_key();
			return 0;
		}
		input = input + 1;
	}

	color = r_config_get_i(&core->config, "scr.color");
	do {
		char *cmdprompt = r_config_get(&core->config, "cmd.vprompt");
		if (cmdprompt && cmdprompt[0])
			r_core_cmd(core, cmdprompt, 0);
		r_cons_clear00();
		r_print_set_cursor(&core->print, curset, ocursor, cursor);
		r_core_visual_prompt(core);
		r_core_cmd(core, printfmt[printidx%NPF], 0);
		r_cons_flush();
		ch = r_cons_readchar();
	} while (r_core_visual_cmd(core, ch));

	return 0;
}
