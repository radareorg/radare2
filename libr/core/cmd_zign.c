/* radare - LGPL - Copyright 2009-2016 - pancake */

#include "r_anal.h"
#include "r_cons.h"
#include "r_core.h"
#include "r_list.h"
#include "r_sign.h"

static int cmd_zign(void *data, const char *input);

static void fcn_zig_add(RSignItem *si, int idx, ut8 *addr, const char *prefix) {
	const int type = si->type;
	if (type == 'f') {
		r_cons_printf ("f %s.fun_%s_%d @ 0x%08"PFMT64x"\n", prefix, si->name, idx, addr);
	} else if (type == 'p') {
		r_cons_printf ("afn %s.fun_%s_%d 0x%08"PFMT64x"\n", prefix, si->name, idx, addr);
	} else {
		r_cons_printf ("f %s.%s_%d @ 0x%08"PFMT64x"\n", prefix , si->name, idx, addr);
	}
}

static bool fcn_zig_search(RCore *core, ut64 ini, ut64 fin) {
	RSignItem *si;
	bool retval = true;
	int idx = 0;
	int count = 0;
	int old_fs = core->flags->space_idx;
	ut8 *buf = NULL;
	ut64 len = fin - ini;
	ut64 align = r_config_get_i (core->config, "search.align");
	const char *prefix = r_config_get (core->config, "zign.prefix");

	if (len <= 0) {
		eprintf ("Invalid range (0x%"PFMT64x"-0x%"PFMT64x").\n", ini, fin);
		retval = false;
		goto exit_func;
	}

	if (!(buf = malloc (len))) {
		eprintf ("Cannot allocate buffer\n");
		core->sign->matches = 0;
		retval = false;
		goto exit_func;
	}

	if (r_io_read_at (core->io, ini, buf, len) != len) {
		eprintf ("Cannot read %"PFMT64d" bytes at 0x%08"PFMT64x"\n", len, ini);
		retval = false;
		goto exit_func;
	}

	eprintf ("Ranges are: 0x%08"PFMT64x" 0x%08"PFMT64x"\n", ini, fin);

	r_cons_printf ("fs sign\n");
	r_cons_break_push (NULL, NULL);

	for (idx = 0; idx < len; idx++) {
		if (align != 0 && (ini + idx) % align != 0) {
			continue;
		}
		if (r_cons_is_breaked()) {
			break;
		}
		si = r_sign_check (core->sign, buf + idx, len - idx);
		if (si) {
			fcn_zig_add (si, count, (ut8 *)ini + idx, prefix);
			eprintf ("- Found %d matching function signatures\r", count);
			count++;
		}
	}

	core->sign->matches = count;

	r_cons_printf ("fs %s\n", (old_fs == -1) ? "*" : core->flags->spaces[old_fs]);
	r_cons_break_pop ();

exit_func:
	free (buf);

	return retval;
}

static int fcn_offset_cmp(ut64 offset, const RAnalFunction *fcn) {
	return fcn->addr == offset ? 0 : -1;
}

static void openSignature(RCore *core, const char *str) {
	if (str && *str) {
		int len = 0;
		char *ptr, *data = r_file_slurp (str, &len);
		if (data) {
			for (ptr = data;;) {
				char *nl = strchr (ptr, '\n');
				if (nl) {
					*nl = 0;
				} else {
					break;
				}
				if (*ptr == 'z') {
					cmd_zign (core, ptr +1);
				}
				ptr = nl + 1;
			}
			free (data);
		} else {
			eprintf ("Cannot open %s\n", str);
		}
	} else {
		eprintf ("Usage: zo [filename] (Same as '. filename')\n");
	}
}

static void fcn_zig_generate_fcn(RCore *core, RAnalFunction *fcn, int minzlen, int maxzlen, bool exact) {
	RAnalOp *op = NULL;
	int fcnlen = 0, oplen = 0, idx = 0, i;
	ut8 *buf = NULL;
	char *outbuf = NULL;
	const char *fcnname = NULL;

	fcnlen = r_anal_fcn_realsize (fcn);
	if (!(buf = calloc (1, fcnlen))) {
		eprintf ("Cannot allocate buffer\n");
		goto exit_func;
	}

	if (r_io_read_at (core->io, fcn->addr, buf, fcnlen) != fcnlen) {
		eprintf ("Cannot read at 0x%08"PFMT64x"\n", fcn->addr);
		goto exit_func;
	}

	RFlagItem *flag = r_flag_get_i (core->flags, fcn->addr);
	if (!flag) {
		eprintf ("Unnamed function at 0x%08"PFMT64x"\n", fcn->addr);
		goto exit_func;
	}
	fcnname = flag->name;

	if (!(op = r_anal_op_new ())) {
		eprintf ("Cannot allocate RAnalOp\n");
		goto exit_func;
	}

	while (idx < fcnlen && idx < maxzlen) {
		if (exact) {
			outbuf = r_str_concatf (outbuf, "%02x", buf[idx]);
			idx++;
		} else {
			oplen = r_anal_op (core->anal, op, fcn->addr + idx, buf + idx, fcnlen - idx);
			if (oplen < 1) {
				break;
			}
			for (i = 0; i < op->nopcode; i++) {
				outbuf = r_str_concatf (outbuf, "%02x", buf[idx + i]);
			}
			for (i = 0; i < R_MAX (oplen - op->nopcode, 0); i++) {
				outbuf = r_str_concat (outbuf, "..");
			}
			idx += oplen;
		}
	}

	if (idx < minzlen) {
		eprintf ("Omitting %s zignature is too small. Length is %d. Check zign.min.\n", fcnname, idx);
		goto exit_func;
	}

	r_cons_printf ("zb %s %s", fcnname, outbuf);
	r_cons_newline ();

exit_func:
	free (buf);
	free (outbuf);
	r_anal_op_free (op);
}

static void fcn_zig_generate(RCore *core, const char *namespace, const char *filename, bool exact) {
	RAnalFunction *fcni = NULL;
	RListIter *iter = NULL;
	int fdold = r_cons_singleton ()->fdout, fd = -1;
	char *ptr = NULL;
	int minzlen = r_config_get_i (core->config, "zign.min");
	int maxzlen = r_config_get_i (core->config, "zign.max");

	if (filename) {
		fd = r_sandbox_open (filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (fd == -1) {
			eprintf ("Cannot open %s in read-write\n", ptr + 1);
			return;
		}
		r_cons_singleton ()->fdout = fd;
		r_cons_strcat ("# Signatures\n");
	}

	r_cons_printf ("zn %s\n", namespace);
	r_cons_break_push (NULL, NULL);

	r_list_foreach (core->anal->fcns, iter, fcni) {
		if (r_cons_is_breaked ()) {
			break;
		}
		fcn_zig_generate_fcn (core, fcni, minzlen, maxzlen, exact);
	}

	r_cons_break_pop ();
	r_cons_strcat ("zn-\n");

	if (filename) {
		r_cons_flush ();
		r_cons_singleton ()->fdout = fdold;
		close (fd);
	}
}

static int cmd_zign(void *data, const char *input) {
	RCore *core = (RCore *)data;
	RAnalFunction *fcni;
	RListIter *iter;
	RSignItem *item;
	int i, len;
	char *ptr, *name;

	switch (*input) {
	case 'B':
		if (input[1] == ' ' && input[2]) {
			ut8 buf[128];
			ut64 addr = core->offset;
			int size = 32;
			ptr = strchr (input + 2, ' ');
			if (ptr) {
				size = atoi (ptr + 1);
				if (size < 1) {
					size = 1;
				}
			}
			if (r_io_read_at (core->io, core->offset, buf, sizeof (buf)) == sizeof (buf)) {
				RFlagItem *flag = r_flag_get_i (core->flags, addr);
				if (flag) {
					name = flag->name;
					r_cons_printf ("zb %s ", name);
					len = R_MIN (size, sizeof (buf));
					for (i = 0; i < len; i++) {
						r_cons_printf ("%02x", buf[i]);
					}
					r_cons_newline ();
				} else {
					eprintf ("Unnamed function at 0x%08"PFMT64x"\n", addr);
				}
			} else {
				eprintf ("Cannot read at 0x%08"PFMT64x"\n", addr);
			}
		} else {
			eprintf ("Usage: zB [size] @@ sym*\nNote: Use zn and zn-");
		}
		break;
	case 'G':
	case 'g':
		if (input[1] == ' ' && input[2]) {
			bool exact = (*input == 'G');
			const char* namespace = input + 2;
			const char* filename = NULL;

			ptr = strchr (input + 2, ' ');
			if (ptr) {
				*ptr = '\0';
				filename = ptr + 1;
			}

			fcn_zig_generate (core, namespace, filename, exact);
		} else {
			eprintf ("Usage: zg libc [libc.sig]\n");
		}
		break;
	case 'n':
		if (!input[1]) {
			r_cons_println (core->sign->ns);
		} else if (!strcmp ("-", input + 1)) {
			r_sign_ns (core->sign, "");
		} else {
			r_sign_ns (core->sign, input + 2);
		}
		break;
	case 'a':
	case 'b':
	case 'h':
	case 'f':
	case 'p':
		if (input[1] == '\0' || input[2] == '\0') {
			eprintf ("Usage: z%c [name] [arg]\n", *input);
		} else {
			ptr = strchr (input+3, ' ');
			if (ptr) {
				*ptr = 0;
				r_sign_add (core->sign, core->anal, (int)*input, input+2, ptr+1);
			}
		}
		break;
	case 'c':
		item = r_sign_check (core->sign, core->block, core->blocksize);
		if (item) {
			r_cons_printf ("f sign.%s @ 0x%08"PFMT64x"\n", item->name, core->offset);
		}
		break;
	case '-':
		if (input[1] == '*') {
			r_sign_reset (core->sign);
		} else {
			int i = r_sign_remove_ns (core->sign, input+1);
			r_cons_printf ("%d zignatures removed\n", i);
		}
		break;
	case 's':
	case '/':
		{
			RList *list;
			RIOMap *map;
			ut64 ini, fin;
			char *ptr;
			bool retval = true;

			if (input[1] == ' ') {
				ptr = strchr (input + 2, ' ');
				if (ptr) {
					*ptr = '\0';
					ini = r_num_math (core->num, input + 2);
					fin = r_num_math (core->num, ptr + 1);
				} else {
					ini = core->offset;
					fin = ini+r_num_math (core->num, input + 2);
				}
				retval = fcn_zig_search (core, ini, fin);
			} else if (input[1] == '\x0') {
				list = r_core_get_boundaries_ok (core);
				if (!list) {
					eprintf ("Invalid boundaries\n");
					return false;
				}
				r_list_foreach (list, iter, map) {
					retval &= fcn_zig_search (core, map->from, map->to);
				}
				r_list_free (list);
			} else {
				eprintf ("Usage: z%c [ini] [end]\n", *input);
				return false;
			}

			return retval;
		}
		break;
	case 'o':
		if (input[1] == ' ') {
			openSignature (core, input + 2);
		} else {
			eprintf ("Usage: zo [filename] (Same as '. filename')\n");
		}
		break;
	case '\0':
	case '*':
		r_sign_list (core->sign, (*input=='*'), 0);
		break;
	case 'j':
		r_sign_list (core->sign, (*input=='*'), 1);
		break;
	case 'F':
		if (input[1] == 'd') {
			if (input[2] != ' ') {
				eprintf ("Usage: zFd <flirt-sig-file>\n");
				return false;
			}
			r_sign_flirt_dump (core->anal, input + 3);
		} else {
			if(input[1] != ' ') {
				eprintf ("Usage: zF <flirt-sig-file>\n");
				return false;
			}
			r_sign_flirt_scan (core->anal, input + 2);
		}
		break;
	case '.':
		{
			RSignItem *si;
			int len = 0;
			int count = 0;
			int old_fs;
			RListIter *it;
			ut8 *buf;
			if (r_list_empty (core->anal->fcns)) {
				eprintf("No functions found, please run some analysis before.\n");
				return false;
			}
			if (!(it = r_list_find (
				      core->anal->fcns,
				      (const void *)core->offset,
				      (RListComparator)fcn_offset_cmp))) {
				return false;
			}
			fcni = (RAnalFunction*)it->data;
			len = r_anal_fcn_realsize (fcni);
			if (!(buf = malloc (len))) {
				return false;
			}
			if (r_io_read_at (core->io, fcni->addr, buf, len) == len) {
				si = r_sign_check (core->sign, buf, len);
				if (si) {
					old_fs = core->flags->space_idx;
					r_cons_printf ("fs sign\n");
					fcn_zig_add (si, count, (ut8 *)fcni->addr, r_config_get (core->config, "zign.prefix"));
					r_cons_printf ("fs %s\n", (old_fs == -1) ? "*" : core->flags->spaces[old_fs]);
					count++;
				}
			}
			free (buf);
			core->sign->matches += count;
		}
		break;
	default:
	case '?':{
		const char* help_msg[] = {
			"Usage:", "z[abcp/*-] [arg]", "Zignatures",
			"z", "", "show status of zignatures",
			"z*", "", "display all zignatures",
			"z-", " namespace", "unload zignatures in namespace",
			"z-*", "", "unload all zignatures",
			"z/", " [ini] [end]", "search zignatures between these regions (alias for zs)",
			"z.", " [@addr]", "match zignatures by function at address",
			"za", " ...", "define new zignature for analysis",
			"zb", " name bytes", "define zignature for bytes",
			"zB", " size", "generate zignatures for current offset/flag",
			"zc", " @ fcn.foo", "flag signature if matching (.zc@@fcn)",
			"zf", " name fmt", "define function zignature (fast/slow, args, types)",
			"zF", " file", "Open a FLIRT signature file and scan opened file",
			"zFd", " file", "Dump a FLIRT signature",
			"zg", " namespace [file]", "Generate zignatures",
			"zG", " namespace [file]", "Generate exact-match zignatures",
			"zh", " name bytes", "define function header zignature",
			"zn", " namespace", "define namespace for following zignatures (until zn-)",
			"zn", "", "display current namespace",
			"zn-", "", "unset namespace",
			"zo", " [filename]", "open Signature files (Same as . filename)",
			"zp", " name bytes", "define new zignature for function body",
			"NOTE:", "", "bytes can contain '.' (dots) to specify a binary mask",
			NULL};
			r_core_cmd_help (core, help_msg);
			 }
		break;
	}
	return 0;
}
