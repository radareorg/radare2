/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_list.h>
#include <r_core.h>

static char *r_core_anal_graph_label (struct r_core_t *core, ut64 addr, ut64 size) {
	char cmd[1024], *cmdstr = NULL, *str = NULL;
	int i, j;

	snprintf (cmd, 1023, "pD %lli @ 0x%08llx", size, addr);
	//eprintf ("%s\n", cmd);
	if ((cmdstr = r_core_cmd_str(core, cmd))) {
		if (!(str = malloc(strlen(cmdstr)*2)))
			return NULL;
		for(i=j=0;cmdstr[i];i++,j++) {
			switch(cmdstr[i]) {
				case 0x1b: // hackyansistrip
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

R_API int r_core_anal_bb (struct r_core_t *core, ut64 at) {
	struct r_anal_bb_t *bb, *bbi;
	RListIter *iter;
	ut8 *buf;
	int len;

	iter = r_list_iterator (core->anal.bbs);
	while (r_list_iter_next (iter)) {
		bbi = r_list_iter_get (iter);
		if (at >= bbi->addr && at < bbi->addr + bbi->size) {
			eprintf ("TOO OLD! 0x%08llx\n", at);
			return R_FALSE;
		}
	}
	if (!(buf = malloc (core->blocksize)))
		return R_FALSE;
	if (!(bb = r_anal_bb_new()))
		return R_FALSE;
	if ((len = r_io_read_at (&core->io, at, buf, core->blocksize)) == -1)
		return R_FALSE;
	r_list_append (core->anal.bbs, bb);
	if (r_anal_bb (&core->anal, bb, at, buf, len)) {
		if (bb->fail != -1) {
			eprintf ("FAIL: 0x%08llx\n", bb->fail);
			r_core_anal_bb (core, bb->fail);
		}
		if (bb->jump != -1) {
			eprintf ("JUMP: 0x%08llx\n", bb->jump);
			r_core_anal_bb (core, bb->jump);
		}
	}
	free (buf);
	return R_TRUE;
}

R_API int r_core_anal_graph (struct r_core_t *core) {
	struct r_anal_bb_t *bbi;
	RListIter *iter;
	char *str;
	int reflines = r_config_get_i(&core->config, "asm.reflines");;

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
		if (bbi->jump == -1 && bbi->fail == -1)
			r_cons_printf ("\t\"0x%08llx\";\n", bbi->addr);
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
