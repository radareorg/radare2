/* radare - LGPL - Copyright 2009-2016 - pancake */

#include "r_anal.h"
#include "r_cons.h"
#include "r_core.h"
#include "r_list.h"
#include "r_sign.h"

static int cmd_zign(void *data, const char *input);

static void fcn_zig_add(RSignItem *si, int pref, ut8 *addr, const char *prefix) {
	const int type = si->type;
	if (type == 'f') {
		r_cons_printf ("f %s.fun_%s_%d @ 0x%08"PFMT64x"\n", prefix, si->name, pref, addr);
	} else if (type == 'p') {
		r_cons_printf ("afn %s.fun_%s_%d 0x%08"PFMT64x"\n", prefix, si->name, pref, addr);
	} else {
		r_cons_printf ("f %s.%s @ 0x%08"PFMT64x"\n", prefix , si->name, addr);
	}
}

static void fcn_zig_search(RCore *core, ut64 ini, ut64 fin) {
	int idx, old_fs;
	ut64 len = fin - ini;
	RSignItem *si;
	ut8 *buf = malloc (len);
	const char *prefix = r_config_get (core->config, "zign.prefix");

	if (buf) {
		int count = 0;
		eprintf ("Ranges are: 0x%08"PFMT64x" 0x%08"PFMT64x"\n", ini, fin);
		old_fs = core->flags->space_idx;
		r_cons_printf ("fs sign\n");
		r_cons_break_push (NULL, NULL);
		if (r_io_read_at (core->io, ini, buf, len) == len) {
			ut64 align = r_config_get_i (core->config, "search.align");
			for (idx = 0; idx < len; idx++) {
				if (align != 0 && (ini + idx) % align != 0) {
					continue;
				}
				if (r_cons_is_breaked()) {
					break;
				}
				si = r_sign_check (core->sign, buf+idx, len-idx);
				if (si) {
					count++;
					fcn_zig_add (si, idx, (ut8 *)ini + idx, prefix);
					eprintf ("- Found %d matching function signatures\r", count);
				}
			}
		} else {
			eprintf ("Cannot read %"PFMT64d" bytes at 0x%08"PFMT64x"\n", len, ini);
		}
		r_cons_printf ("fs %s\n", (old_fs == -1) ? "*" : core->flags->spaces[old_fs]);
		r_cons_break_pop ();
		free (buf);
		core->sign->matches = count;
	} else {
		eprintf ("Cannot alloc %"PFMT64d" bytes\n", len);
		core->sign->matches = 0;
	}
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

static int cmd_zign(void *data, const char *input) {
	RCore *core = (RCore *)data;
	RAnalFunction *fcni;
	RListIter *iter;
	RSignItem *item;
	int i, fd = -1, len;
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
			if (r_io_read_at (core->io, core->offset, buf, sizeof (buf))) {
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
			int fdold = r_cons_singleton ()->fdout;
			int minzlen = r_config_get_i (core->config, "zign.min");
			int maxzlen = r_config_get_i (core->config, "zign.max");
			ptr = strchr (input + 2, ' ');
			if (ptr) {
				*ptr = '\0';
				fd = r_sandbox_open (ptr+1, O_RDWR|O_CREAT|O_TRUNC, 0644);
				if (fd == -1) {
					eprintf ("Cannot open %s in read-write\n", ptr+1);
					return false;
				}
				r_cons_singleton ()->fdout = fd;
				r_cons_strcat ("# Signatures\n");
			}
			r_cons_printf ("zn %s\n", input + 2);
			r_cons_break_push (NULL, NULL);
			r_list_foreach (core->anal->fcns, iter, fcni) {
				RAnalOp *op = NULL;
				int zlen, len, oplen, idx = 0;
				ut8 *buf;
				if (r_cons_is_breaked ()) {
					break;
				}
				len = r_anal_fcn_realsize (fcni);
				if (!(buf = calloc (1, len))) {
					r_cons_break_pop ();
					return false;
				}
				/* XXX this is wrong. we must read for each basic block not the whole function length */
				if (!r_io_read_at (core->io, fcni->addr, buf, len)) {
					RFlagItem *flag = r_flag_get_i (core->flags, fcni->addr);
					if (flag) {
						name = flag->name;
						if (!(op = r_anal_op_new ())) {
							free (buf);
							r_cons_break_pop ();
							return false;
						}
						zlen = 0;
						if (input[0] == 'G') {
							zlen = len;
						} else {
							while (idx < len) {
								oplen = r_anal_op (core->anal, op, fcni->addr + idx, buf + idx, len - idx);
								if (oplen < 1) {
									break;
								}
								if (op->nopcode) {
									int left = R_MAX (oplen - op->nopcode, 0);
									memset (buf + idx + op->nopcode, 0, left);
								}
								zlen += op->nopcode;
								idx += oplen;
							}
						}
						if (zlen > minzlen && maxzlen > zlen) {
							r_cons_printf ("zb %s ", name);
							for (i = 0; i < len; i++) {
								/* XXX assuming buf[i] == 0 is wrong because mask != data */
								if (!buf[i]) {
									r_cons_printf ("..");
								} else {
									r_cons_printf ("%02x", buf[i]);
								}
							}
							r_cons_newline ();
						} else {
							if (zlen <= minzlen) {
								eprintf ("Omitting %s zignature is too small. Length is %d. Check zign.min.\n", name, zlen);
							} else {
								eprintf ("Omitting %s zignature is too big. Length is %d. Check zign.max.\n", name, zlen);
							}
						}
					} else {
						eprintf ("Unnamed function at 0x%08"PFMT64x"\n", fcni->addr);
					}
				} else {
					eprintf ("Cannot read at 0x%08"PFMT64x"\n", fcni->addr);
				}
				free (buf);
				r_anal_op_free (op);
			}
			r_cons_break_pop ();
			r_cons_strcat ("zn-\n");
			if (ptr) {
				r_cons_flush ();
				r_cons_singleton ()->fdout = fdold;
				close (fd);
			}
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
		if (*(input + 1) == '\0' || *(input + 2) == '\0')
			eprintf ("Usage: z%c [name] [arg]\n", *input);
		else{
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
			// TODO: parse arg0 and arg1
			ut64 ini, fin;
			RList *list;
			RListIter *iter;
			RIOMap *map;

			if (input[1]) {
				if(input[1] != ' ') {
					eprintf ("Usage: z%c [ini] [end]\n", *input);
					return false;
				}
				char *ptr = strchr (input+2, ' ');
				if (ptr) {
					*ptr = '\0';
					ini = r_num_math (core->num, input+2);
					fin = r_num_math (core->num, ptr+1);
				} else {
					ini = core->offset;
					fin = ini+r_num_math (core->num, input+2);
				}

				if (ini >= fin) {
					eprintf ("Invalid range (0x%"PFMT64x"-0x%"PFMT64x").\n", ini, fin);
					return false;
				}
				fcn_zig_search (core, ini, fin);
			} else {
				list = r_core_get_boundaries_ok (core);
				if (!list) {
					eprintf ("Invalid boundaries\n");
					return false;
				}
				r_list_foreach (list, iter, map) {
					fcn_zig_search (core, map->from, map->to);
				}
				r_list_free (list);
			}
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
					count++;
					fcn_zig_add (si, count, (ut8 *)fcni->addr, r_config_get (core->config, "zign.prefix"));
					r_cons_printf ("fs %s\n", (old_fs == -1) ? "*" : core->flags->spaces[old_fs]);
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
