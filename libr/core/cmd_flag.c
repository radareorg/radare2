/* radare - LGPL - Copyright 2009-2016 - pancake */

#include <stddef.h>
#include "r_cons.h"
#include "r_core.h"

static void cmd_fz(RCore *core, const char *input) {
	switch (*input) {
	case '?':
		eprintf ("Usage: fz[?|-name| name] [@addr]\n");
		eprintf (" fz math    add new flagzone named 'math'\n");
		eprintf (" fz-math    remove the math flagzone\n");
		eprintf (" fz-*       remove all flagzones\n");
		eprintf (" fz.        show around flagzone context\n");
		eprintf (" fz:        show what's in scr.flagzone for visual\n");
		eprintf (" fz*        dump into r2 commands, for projects\n");
		break;
	case '.':
		{
			const char *a, *b;
			r_flag_zone_around (core->flags, core->offset, &a, &b);
			r_cons_printf ("%s %s\n", a, b);
		}
		break;
	case ':':
		{
			const char *a, *b;
			int a_len = 0;
			int w = r_cons_get_size (NULL);
			r_flag_zone_around (core->flags, core->offset, &a, &b);
			if (a) {
				r_cons_printf ("[<< %s]", a);
				a_len = strlen (a) + 4;
			}
			int padsize = (w / 2)  - a_len;
			int title_size = 12;
			if (a || b) {
				char *title = r_str_newf ("[ 0x%08"PFMT64x" ]", core->offset);
				title_size = strlen (title);
				padsize -= strlen (title) / 2;
				const char *halfpad = r_str_pad (' ', padsize);
				r_cons_printf ("%s%s", halfpad, title);
				free (title);
			}
			if (b) {
				padsize = (w / 2) - title_size - strlen (b) - 4;
				const char *halfpad = padsize > 1? r_str_pad (' ', padsize): "";
				r_cons_printf ("%s[%s >>]", halfpad, b);
			}
			if (a || b) {
				r_cons_newline();
			}
		}
		break;
	case ' ':
		r_flag_zone_add (core->flags, r_str_chop_ro (input + 1), core->offset);
		break;
	case '-':
		if (input[1] == '*') {
			r_flag_zone_reset (core->flags);
		} else {
			r_flag_zone_del (core->flags, input + 1);
		}
		break;
	case '*':
		r_flag_zone_list (core->flags, '*');
		break;
	case 0:
		r_flag_zone_list (core->flags, 0);
		break;
	}
}


static void flagbars(RCore *core, const char *glob) {
	int cols = r_cons_get_size (NULL);
	RListIter *iter;
	RFlagItem *flag;
	cols -= 80;
	if (cols < 0) {
		cols += 80;
	}
	r_list_foreach (core->flags->flags, iter, flag) {
		ut64 min = 0, max = r_io_size (core->io);
		SdbList *secs = r_io_section_vget_secs_at (core->io, flag->offset);
		RIOSection *s = secs ? ls_pop (secs) : NULL;
		ls_free (secs);
		if (s) {
			min = s->vaddr;
			max = s->vaddr + s->size;
		}
		if (r_str_glob (flag->name, glob)) {
			r_cons_printf ("0x%08"PFMT64x" ", flag->offset);
			r_print_rangebar (core->print, flag->offset, flag->offset + flag->size, min, max, cols);
			r_cons_printf ("  %s\n", flag->name);
		}
	}
}

static int cmd_flag(void *data, const char *input) {
	static int flagenum = 0;
	RCore *core = (RCore *)data;
	ut64 off = core->offset;
	char *ptr, *str = NULL;
	RFlagItem *item;
	char *name = NULL;
	st64 base;

	// TODO: off+=cursor
	if (*input) {
		str = strdup (input + 1);
	}
rep:
	switch (*input) {
	case 'e':
		switch (input[1]) {
		case ' ':
			ptr = r_str_newf ("%s.%d", input+2, flagenum);
			(void)r_flag_set (core->flags, ptr,
					core->offset, 1);
			flagenum++;
			free (ptr);
			break;
		case '-':
			flagenum = 0;
			break;
		default:
			eprintf ("|Usage: fe[-| name] @@= 1 2 3 4\n");
			break;
		}
		break;
	case '=': // "f="
		switch (input[1]) {
		case ' ':
			flagbars (core, input + 2);
			break;
		case 0:
			flagbars (core, NULL);
			break;
		default:
		case '?':
			eprintf ("Usage: f= [glob] to grep for matching flag names\n");
			break;
		}
		break;
	case 'a':
		if (input[1] == ' '){
			RFlagItem *fi;
			R_FREE (str);
			str = strdup (input+2);
			ptr = strchr (str, '=');
			if (!ptr)
				ptr = strchr (str, ' ');
			if (ptr) *ptr++ = 0;
			name = (char *)r_str_chop_ro (str);
			ptr = (char *)r_str_chop_ro (ptr);
			fi = r_flag_get (core->flags, name);
			if (!fi)
				fi = r_flag_set (core->flags, name,
					core->offset, 1);
			if (fi) {
				r_flag_item_set_alias (fi, ptr);
			} else {
				eprintf ("Cannot find flag '%s'\n", name);
			}
		} else {
			eprintf ("Usage: fa flagname flagalias\n");
		}
		break;
	case 'V': // visual marks
		switch(input[1]) {
		case '-':
			r_core_visual_mark_reset (core);
			break;
		case ' ':
			{
			const char *arg = strchr (input+2, ' ');
			ut64 addr = arg? r_num_math (core->num, arg): core->offset;
			r_core_visual_mark_set (core, atoi (input+1), addr);
			}
			break;
		case '?':
			eprintf ("Usage: fV[*-] [nkey] [offset]\n");
			eprintf ("Dump/Restore visual marks (mK/'K)\n");
			break;
		default:
			r_core_visual_mark_dump (core);
			break;
		}
		break;
	case 'm': // "fm"
		r_flag_move (core->flags, core->offset, r_num_math (core->num, input+1));
		break;
	case '2': // "f2"
		r_flag_get_i2 (core->flags, r_num_math (core->num, input+1));
		break;
	case 'R': // "fR"
		{
		if (*str == '\0'){
			eprintf ("Usage: fR [from] [to] ([mask])\n");
			eprintf ("Example to relocate PIE flags on debugger:\n"
				" > fR entry0 `dm~:1[1]`\n");
			break;
		}
		char *p = strchr (str+1, ' ');
		ut64 from, to, mask = 0xffff;
		int ret;
		if (p) {
			char *q = strchr (p+1, ' ');
			*p = 0;
			if (q) {
				*q = 0;
				mask = r_num_math (core->num, q+1);
			}
			from = r_num_math (core->num, str+1);
			to = r_num_math (core->num, p+1);
			ret = r_flag_relocate (core->flags, from, mask, to);
			eprintf ("Relocated %d flags\n", ret);
		} else {
			eprintf ("Usage: fR [from] [to] ([mask])\n");
			eprintf ("Example to relocate PIE flags on debugger:\n"
				" > fR entry0 `dm~:1[1]`\n");
		}
		}
		break;
	case 'b': // "fb"
		switch (input[1]) {
		case ' ':
			free (str);
			str = strdup (input + 2);
			ptr = strchr (str, ' ');
			if (ptr) {
				RListIter *iter;
				RFlagItem *flag;
				RFlag *f = core->flags;
				*ptr = 0;
				base = r_num_math (core->num, str);
				r_list_foreach (f->flags, iter, flag) {
					if (r_str_glob (flag->name, ptr+1))
						flag->offset += base;
				}
			} else {
				core->flags->base = r_num_math (core->num, input+1);
			}
			free (str);
			str = NULL;
			break;
		case '\0':
			r_cons_printf ("%"PFMT64d" 0x%"PFMT64x"\n",
				core->flags->base,
				core->flags->base);
			break;
		default:
			eprintf ("Usage: fb [addr] [[flags*]]\n");
			break;
		}
		break;
	case '+':
	case ' ': {
		const char *cstr = r_str_chop_ro (str);
		char* eq = strchr (cstr, '=');
		char* s = strchr (cstr, ' ');
		char* s2 = NULL;
		ut32 bsze = 1; //core->blocksize;
		if (eq) {
			// TODO: add support for '=' char in flag comments
			*eq = 0;
			off = r_num_math (core->num, eq + 1);
		}
		if (s) {
			*s = '\0';
			s2 = strchr (s + 1, ' ');
			if (s2) {
				*s2 = '\0';
				if (s2[1] && s2[2]) {
					off = r_num_math (core->num, s2 + 1);
				}
			}
			bsze = r_num_math (core->num, s + 1);
		}
		if (*cstr == '.') {
			input++;
			goto rep;
#if 0
eprintf ("WTF 'f .xxx' adds a variable to the function? ?!!?(%s)\n");
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off, 0);
			if (fcn) r_anal_var_add (core->anal, fcn->addr, 0, off, 'v', "int", 4, str+1);
			else eprintf ("Cannot find function at 0x%08"PFMT64x"\n", off);
#endif
		} else {
			r_flag_set (core->flags, cstr, off, bsze);
		}
		}
		break;
	case '-':
		if (input[1] == '-') {
			r_flag_unset_all (core->flags);
		} else if (input[1]) {
			const char *flagname = r_str_chop_ro (input + 1);
			while (*flagname==' ') {
				flagname++;
			}
			if (*flagname=='.') {
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off, 0);
				if (fcn) {
					eprintf ("TODO: local_del_name has been deprecated\n");
					//;r_anal_fcn_local_del_name (core->anal, fcn, flagname+1);
				} else {
					eprintf ("Cannot find function at 0x%08"PFMT64x"\n", off);
				}
			} else {
				if (strchr (flagname, '*')) {
					r_flag_unset_glob (core->flags, flagname);
				} else {
					r_flag_unset_name (core->flags, flagname);
				}
			}
		} else {
			r_flag_unset_off (core->flags, off);
		}
		break;
	case '.':
		input = r_str_chop_ro (input + 1) - 1;
		if (input[1]) {
			if (input[1] == '*') {
				if (input[2] == '*') {
					r_anal_fcn_labels (core->anal, NULL, 1);
				} else {
					RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off, 0);
					if (fcn) r_anal_fcn_labels (core->anal, fcn, 1);
					else eprintf ("Cannot find function at 0x%08"PFMT64x"\n", off);
				}
			} else {
				char *name = strdup (input + ((input[2] == ' ')? 2: 1));
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off, 0);
				if (name) {
					char *eq = strchr (name, '=');
					if (eq) {
						*eq ++ = 0;
						off = r_num_math (core->num, eq);
					}
					r_str_chop (name);
					if (fcn) {
						if (*name=='-') {
							r_anal_fcn_label_del (core->anal, fcn, name + 1, off);
						} else {
							r_anal_fcn_label_set (core->anal, fcn, name, off);
						}
					} else eprintf ("Cannot find function at 0x%08"PFMT64x"\n", off);
					free (name);
				}
			}
		} else {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off, 0);
			if (fcn) r_anal_fcn_labels (core->anal, fcn, 0);
			else eprintf ("Cannot find function at 0x%08"PFMT64x"\n", off);
		}
		break;
	case 'l': // "fl"
		if (input[1] == '?') { // "fl?"
			eprintf ("Usage: fl[a] [flagname] [flagsize]\n");
		} else
		if (input[1] == 'a') { // "fla"
			// TODO: we can optimize this if core->flags->flags is sorted by flagitem->offset
			char *glob = strchr (input, ' ');
			if (glob) {
				glob++;
			}
			RListIter *iter, *iter2;
			RFlagItem *flag, *flag2;
			r_list_foreach (core->flags->flags, iter, flag) {
				if (flag->size == 0 && (!glob || r_str_glob (flag->name, glob))) {
					RFlagItem *win = NULL;
					ut64 at = flag->offset;
					r_list_foreach (core->flags->flags, iter2, flag2) {
						if (flag2->offset > at) {
							if (!win || flag2->offset < win->offset) {
								win = flag2;
							}
						}
					}
					if (win) {
						flag->size = win->offset - flag->offset;
					}
				}
			}
		} else if (input[1] == ' ') { // "fl ..."
			char *p, *arg = strdup (input + 2);
			r_str_trim_head_tail (arg);
			p = strchr (arg, ' ');
			if (p) {
				*p++ = 0;
				item = r_flag_get_i (core->flags,
					r_num_math (core->num, arg));
				if (item)
					item->size = r_num_math (core->num, p);
			} else {
				if (*arg) {
					item = r_flag_get_i (core->flags, core->offset);
					if (item) {
						item->size = r_num_math (core->num, arg);
					}
				} else {
					item = r_flag_get_i (core->flags, r_num_math (core->num, arg));
					if (item) {
						r_cons_printf ("0x%08"PFMT64x"\n", item->size);
					}
				}
			}
			free (arg);
		} else { // "fl"
			item = r_flag_get_i (core->flags, core->offset);
			if (item)
				r_cons_printf ("0x%08"PFMT64x"\n", item->size);
		}
		break;
#if 0
	case 'd':
		if (input[1] == ' ') {
			char cmd[128];
			RFlagItem *item = r_flag_get_i (core->flags,
				r_num_math (core->num, input+2));
			if (item) {
				r_cons_printf ("0x%08"PFMT64x"\n", item->offset);
				snprintf (cmd, sizeof (cmd), "pD@%"PFMT64d":%"PFMT64d,
					 item->offset, item->size);
				r_core_cmd0 (core, cmd);
			}
		} else eprintf ("Missing arguments\n");
		break;
#endif
	case 'z':
		cmd_fz (core, input + 1);
		break;
	case 'x':
		if (input[1] == ' ') {
			char cmd[128];
			RFlagItem *item = r_flag_get_i (core->flags,
				r_num_math (core->num, input+2));
			if (item) {
				r_cons_printf ("0x%08"PFMT64x"\n", item->offset);
				snprintf (cmd, sizeof (cmd), "px@%"PFMT64d":%"PFMT64d,
					 item->offset, item->size);
				r_core_cmd0 (core, cmd);
			}
		} else {
			eprintf ("Missing arguments\n");
		}
		break;
	case 'S':
		r_flag_sort (core->flags, (input[1]=='n'));
		break;
	case 's':
		switch (input[1]) {
		case '?':
			{
			const char *help_msg[] = {
			"Usage: fs","[*] [+-][flagspace|addr]", " # Manage flagspaces",
			"fs","","display flagspaces",
			"fs"," *","select all flagspaces",
			"fs"," flagspace","select flagspace or create if it doesn't exist",
			"fs","-flagspace","remove flagspace",
			"fs","-*","remove all flagspaces",
			"fs","+foo","push previous flagspace and set",
			"fs","-","pop to the previous flagspace",
			"fs","-.","remove the current flagspace",
			"fsm"," [addr]","move flags at given address to the current flagspace",
			"fsr"," newname","rename selected flagspace",
			NULL};
			r_core_cmd_help (core, help_msg);
			}
			break;
		case '+':
			r_flag_space_push (core->flags, input+2);
			break;
		case 'r':
			if (input[2] ==' ') {
				r_flag_space_rename (core->flags, NULL, input + 2);
			} else {
				eprintf ("Usage: fsr [newname]\n");
			}
			break;
		case '-':
			switch (input[2]) {
			case '*':
				r_flag_space_unset (core->flags, NULL);
				break;
			case '.':
				{
				const char *curfs = r_flag_space_cur (core->flags);
				r_flag_space_unset (core->flags, curfs);
				}
				break;
			case 0:
				r_flag_space_pop (core->flags);
				break;
			default:
				r_flag_space_unset (core->flags, input+2);
				break;
			}
			break;
		case 'j':
		case '\0':
		case '*':
			r_flag_space_list (core->flags, input[1]);
			break;
		case ' ':
			r_flag_space_set (core->flags, input+2);
			break;
		case 'm':
			{ RFlagItem *f;
			ut64 off = core->offset;
			if (input[2] == ' ') {
				off = r_num_math (core->num, input+2);
			}
			f = r_flag_get_i (core->flags, off);
			if (f) {
				f->space = core->flags->space_idx;
			} else {
				eprintf ("Cannot find any flag at 0x%"PFMT64x".\n", off);
			}
			}
			break;
		default: {
			int i, j = 0;
			for (i = 0; i < R_FLAG_SPACES_MAX; i++) {
				if (core->flags->spaces[i])
					r_cons_printf ("%02d %c %s\n", j++,
					(i == core->flags->space_idx)?'*':' ',
					core->flags->spaces[i]);
			}
			} break;
		}
		break;
	case 'g':
		r_core_cmd0 (core, "V");
		break;
	case 'c':
		if (input[1]=='?' || input[1] != ' ') {
			const char *help_msg[] = {
			"Usage: fc", "<flagname> [color]", " # List colors with 'ecs'",
			"fc", " flagname", "Get current color for given flagname",
			"fc", " flagname color", "Set color to a flag",
			NULL
			};
			r_core_cmd_help (core, help_msg);
		} else {
			RFlagItem *fi;
			const char *ret;
			char *arg = r_str_chop (strdup (input+2));
			char *color = strchr (arg, ' ');
			if (color && color[1]) {
				*color++ = 0;
			}
			fi = r_flag_get (core->flags, arg);
			if (fi) {
				ret = r_flag_color (core->flags, fi, color);
				if (!color && ret)
					r_cons_println (ret);
			} else {
				eprintf ("Unknown flag '%s'\n", arg);
			}
			free (arg);
		}
		break;
	case 'C':
		if (input[1] == ' ') {
			RFlagItem *item;
			char *q, *p = strdup (input + 2);
			q = strchr (p, ' ');
			if (q) {
				*q = 0;
				item = r_flag_get (core->flags, p);
				if (item) {
					r_flag_item_set_comment (item, q+1);
				} else {
					eprintf ("Cannot find flag with name '%s'\n", p);
				}
			} else {
				item = r_flag_get_i (core->flags, r_num_math (core->num, p));
				if (item && item->comment) {
					r_cons_println (item->comment);
				} else {
					eprintf ("Cannot find item\n");
				}
			}
			free (p);
		} else eprintf ("Usage: fC [name] [comment]\n");
		break;
	case 'o':
		{ // TODO: use file.fortunes // can be dangerous in sandbox mode
			const char *fortunes_tips = R2_PREFIX "/share/doc/radare2/fortunes.tips";
			const char *fortunes_fuun = R2_PREFIX "/share/doc/radare2/fortunes.fun";
			const char *fortunes_nsfw = R2_PREFIX "/share/doc/radare2/fortunes.nsfw";
			const char *fortunes_crep = R2_PREFIX "/share/doc/radare2/fortunes.creepy";
			const char *types = (char *)r_config_get (core->config, "cfg.fortunes.type");
			char *line = NULL, *templine = NULL;
			int i = 0;
			if (strstr (types, "tips")) {
				templine = r_file_slurp_random_line_count (fortunes_tips, &i);
				line = templine;
			}
			if (strstr (types, "fun")) {
				templine = r_file_slurp_random_line_count (fortunes_fuun, &i);
				if (templine) {
					free (line);
					line = templine;
				}
			}
			if (strstr (types, "nsfw")) {
				templine = r_file_slurp_random_line_count (fortunes_nsfw, &i);
				if (templine) {
					free (line);
					line = templine;
				}
			}
			if (strstr (types, "creepy")) {
				templine = r_file_slurp_random_line_count (fortunes_crep, &i);
				if (templine) {
					free (line);
					line = templine;
				}
			}
			if (line) {
				if (r_config_get_i (core->config, "cfg.fortunes.clippy")) {
					r_core_clippy (line);
				} else {
					r_cons_printf (" -- %s\n", line);
				}
				if (r_config_get_i (core->config, "cfg.fortunes.tts")) {
					r_sys_tts (line, true);
				}
				free (line);
			}
		}
		break;
	case 'r':
		if (input[1]==' ' && input[2]) {
			char *old, *new;
			RFlagItem *item;
			old = str + 1;
			new = strchr (old, ' ');
			if (new) {
				*new = 0;
				new++;
				item = r_flag_get (core->flags, old);
				if (!item && !strncmp (old, "fcn.", 4)) {
					item = r_flag_get (core->flags, old+4);
				}
			} else {
				new = old;
				item = r_flag_get_i (core->flags, core->offset);
			}
			if (item) {
				if (!r_flag_rename (core->flags, item, new)) {
					eprintf ("Invalid name\n");
				}
			} else {
				eprintf ("Cannot find flag (%s)\n", old);
			}
		}
		break;
	case '\0':
	case 'n': // "fn"
	case '*': // "f*"
	case 'j': // "fj"
		r_flag_list (core->flags, *input, input[0]? input + 1: "");
		break;
	case 'i': // "fi"
		if (input[1] == ' ' || input[2] == ' ') {
			char *arg = strdup (r_str_chop_ro (input + 2));
			if (*arg) {
				arg = strdup (r_str_chop_ro (input + 2));
				char *sp = strchr (arg, ' ');
				if (!sp) {
					char *newarg = r_str_newf ("%c0x%"PFMT64x" %s+0x%"PFMT64x,
						input[1], core->offset, arg, core->offset);
					free (arg);
					arg = newarg;
				} else {
					char *newarg = r_str_newf ("%c%s", input[1], arg);
					free (arg);
					arg = newarg;
				}
			} else {
				free (arg);
				arg = r_str_newf (" 0x%"PFMT64x" 0x%"PFMT64x,
					core->offset, core->offset + core->blocksize);
			}
			r_flag_list (core->flags, 'i', arg);
			free (arg);
		} else {
			// XXX dupe for prev case
			char *arg = r_str_newf (" 0x%"PFMT64x" 0x%"PFMT64x,
				core->offset, core->offset + core->blocksize);
			r_flag_list (core->flags, 'i', arg);
			free (arg);
		}
		break;
	case 'd': // "fd"
		{
			ut64 addr = core->offset;
			RFlagItem *f = NULL;
			bool space_strict = true;
			switch (input[1]) {
			case '?':
				eprintf ("Usage: fd[d] [offset|flag|expression]\n");
				eprintf ("  fd $$   # describe flag + delta for given offset\n");
				eprintf ("  fdd $$  # describe flag without space restrictions\n");
				if (str) {
					free (str);
				}
				return false;
			case '\0':
				addr = core->offset;
				break;
			case 'd':
				space_strict = false;
				if (input[2] == ' ') {
					addr = r_num_math (core->num, input + 3);
				}
				break;
			default:
				addr = r_num_math (core->num, input + 2);
				break;
			}
			core->flags->space_strict = space_strict;
			f = r_flag_get_at (core->flags, addr, true);
			core->flags->space_strict = false;
			if (f) {
				if (f->offset != addr) {
					r_cons_printf ("%s + %d\n", f->name,
						(int)(addr - f->offset));
				} else {
					r_cons_println (f->name);
				}
			}
		}
		break;
	case '?':
	{
		const char *help_msg[] = {
		"Usage: f","[?] [flagname]", " # Manage offset-name flags",
		"f","","list flags (will only list flags from selected flagspaces)",
		"f."," [*[*]]","list local per-function flags (*) as r2 commands",
		"f.","blah=$$+12","set local function label named 'blah'",
		"f*","","list flags in r commands",
		"f"," name 12 @ 33","set flag 'name' with length 12 at offset 33",
		"f"," name = 33","alias for 'f name @ 33' or 'f name 1 33'",
		"f"," name 12 33 [cmt]","same as above + optional comment",
		"f-",".blah@fcn.foo","delete local label from function at current seek (also f.-)",
		"f--","","delete all flags and flagspaces (deinit)",
		"f+","name 12 @ 33","like above but creates new one if doesnt exist",
		"f-","name","remove flag 'name'",
		"f-","@addr","remove flag at address expression",
		"f."," fname","list all local labels for the given function",
		"f="," [glob]","list range bars graphics with flag offsets and sizes",
		"fa"," [name] [alias]","alias a flag to evaluate an expression",
		"fb"," [addr]","set base address for new flags",
		"fb"," [addr] [flag*]","move flags matching 'flag' to relative addr",
		"fc"," [?][name] [color]","set color for given flag",
		"fC"," [name] [cmt]","set comment for given flag",
		"fd"," addr","return flag+delta",
		"fe-","","resets the enumerator counter",
		"fe"," [name]","create flag name.#num# enumerated flag. See fe?",
		"fi"," [size] | [from] [to]","show flags in current block or range",
		"fg","","bring visual mode to foreground",
		"fj","","list flags in JSON format",
		"fl"," ([flag]) [size]","show or set flag length (size)",
		"fla"," [glob]","automatically compute the size of all flags matching glob",
		"fm"," addr","move flag at current offset to new address",
		"fn","","list flags displaying the real name (demangled)",
		"fo","","show fortunes",
		//" fc [name] [cmt]  ; set execution command for a specific flag"
		"fr"," [old] [[new]]","rename flag (if no new flag current seek one is used)",
		"fR"," [?] [f] [t] [m]","relocate all flags matching f&~m 'f'rom, 't'o, 'm'ask",
		"fs","[?]+-*","manage flagspaces",
		"fS","[on]","sort flags by offset or name",
		"fV","[*-] [nkey] [offset]","dump/restore visual marks (mK/'K)",
		"fx","[d]","show hexdump (or disasm) of flag:flagsize",
		"fz"," [?][name]","add named flag zone -name to delete. see fz?[name]",
		NULL};
		r_core_cmd_help (core, help_msg);
		break;
	}
	}
	if (str)
		free (str);
	return 0;
}

