/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_list.h>
#include <r_core.h>

static char *r_core_anal_graph_label (struct r_core_t *core, ut64 addr, ut64 size) {
	char cmd[1024], *cmdstr = NULL, *str = NULL;
	int i, j;

	snprintf (cmd, 1023, "pD %lli @ 0x%08llx", size, addr);
	if ((cmdstr = r_core_cmd_str(core, cmd))) {
		if (!(str = malloc(strlen(cmdstr)*2)))
			return NULL;
		for(i=j=0;cmdstr[i];i++,j++) {
			switch(cmdstr[i]) {
				case 0x1b:
					/* skip ansi chars */
					for(i++;cmdstr[i]&&cmdstr[i]!='m'&&cmdstr[i]!='H'&&cmdstr[i]!='J';i++);
					j--;
					break;
				case '\n':
				case '\r':
					str[j]='\\';
					str[++j]='l';
					break;
				default:
					str[j]=cmdstr[i];
			}
		}
		str[j]='\0';
		free (cmdstr);
	}
	return str;
}

R_API int r_core_anal_bb (struct r_core_t *core, ut64 at, int depth) {
	struct r_anal_bb_t *bb, *bbi;
	struct r_anal_aop_t *aopi;
	RListIter *iter;
	ut64 jump, fail;
	ut8 *buf;
	int len, split = 0;

	if (depth < 0)
		return R_FALSE;
	iter = r_list_iterator (core->anal.bbs);
	while (r_list_iter_next (iter)) {
		bbi = r_list_iter_get (iter);
		if (at == bbi->addr)
			return R_FALSE;
		else if (at > bbi->addr && at < bbi->addr + bbi->size) {
			split = 1;
			break;
		}
	}
	if (!(bb = r_anal_bb_new()))
		return R_FALSE;
	if (split) {
		r_list_append (core->anal.bbs, bb);
		bb->addr = at;
		bb->size = bbi->addr + bbi->size - at;
		bb->jump = bbi->jump;
		bb->fail = bbi->fail;
		bbi->size = at - bbi->addr;
		bbi->jump = at;
		bbi->fail = -1;
		iter = r_list_iterator (bbi->aops);
		while (r_list_iter_next (iter)) {
			aopi = r_list_iter_get (iter);
			if (aopi->addr >= at) {
				r_list_split (bbi->aops, aopi);
				r_list_append (bb->aops, aopi);
			}
		}
	} else {
		if (!(buf = malloc (core->blocksize)))
			return R_FALSE;
		if ((len = r_io_read_at (&core->io, at, buf, core->blocksize)) == -1)
			return R_FALSE;
		if (r_anal_bb (&core->anal, bb, at, buf, len) > 0) {
			r_list_append (core->anal.bbs, bb);
			fail = bb->fail;
			jump = bb->jump;
			if (fail != -1)
				r_core_anal_bb (core, fail, depth-1);
			if (jump != -1)
				r_core_anal_bb (core, jump, depth-1);
		} else r_anal_bb_free (bb);
		free (buf);
	}
	return R_TRUE;
}

R_API int r_core_anal_graph (struct r_core_t *core) {
	struct r_anal_bb_t *bbi;
	RListIter *iter;
	char *str;
	int reflines = r_config_get_i(&core->config, "asm.reflines");

	r_config_set_i(&core->config, "asm.reflines", 0);
	r_cons_printf ("digraph code {\n");
	r_cons_printf ("\tgraph [bgcolor=white];\n");
	r_cons_printf ("\tnode [color=lightgray, style=filled shape=box fontname=\"Courier\" fontsize=\"8\"];\n");
	iter = r_list_iterator (core->anal.bbs);
	while (r_list_iter_next (iter)) {
		bbi = r_list_iter_get (iter);
		if (bbi->jump != -1)
			r_cons_printf ("\t\"0x%08llx\" -> \"0x%08llx\" [color=\"green\"];\n", bbi->addr, bbi->jump);
		if (bbi->fail != -1)
			r_cons_printf ("\t\"0x%08llx\" -> \"0x%08llx\" [color=\"red\"];\n", bbi->addr, bbi->fail);
		r_cons_flush ();
		if ((str = r_core_anal_graph_label (core, bbi->addr, bbi->size))) {
			r_cons_printf (" \"0x%08llx\" [label=\"%s\"]\n", bbi->addr, str);
			free(str);
		}
	}
	r_cons_printf ("}\n");
	r_config_set_i(&core->config, "asm.reflines", reflines);
	return R_TRUE;
}
