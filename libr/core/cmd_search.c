/* radare - LGPL - Copyright 2009-2014 - pancake */

static int preludecnt = 0;
static int searchflags = 0;
static int searchshow = 0;
static int searchhits = 0;
static int maplist = 0;
static int json = 0;
static const char *cmdhit = NULL;
static const char *searchprefix = NULL;
static unsigned int searchcount = 0;

static void cmd_search_bin(RCore *core, ut64 from, ut64 to) {
	RBinPlugin *plug;
	ut8 buf[1024];
	int size, sz = sizeof (buf);

	while (from <to) {
		r_io_read_at (core->io, from, buf, sz);
		plug = r_bin_get_binplugin_by_bytes (core->bin, buf, sz);
		if (plug) {
			r_cons_printf ("0x%08"PFMT64x"  %s\n",
				from, plug->name);
			// TODO: load the bin and calculate its size
			if (plug->size) {
				r_bin_load_io_at_offset_as_sz (core->bin,
					core->file->desc, 0, 0, 0, core->offset,
					plug->name, 4096);
				size = plug->size (core->bin->cur);
				if (size)
					r_cons_printf ("size %d\n", size);
			}
		}
		from ++;
	}
}

static int cmd_search_value_in_range(RCore *core, ut64 from, ut64 to, ut64 vmin, ut64 vmax, int vsize) {
	ut8 buf[4096];
	const int sz = sizeof (buf);
	int i, align = core->search->align;
	int hitctr = 0;
#define cbhit(y) \
	r_cons_printf ("f hit0_%d = 0x%"PFMT64x"\n", hitctr, y);\
	hitctr++;

	if (vmin >= vmax) {
		eprintf ("Error: vmin must be lower than vmax\n");
		return -1;
	}
	while (from <to) {
		memset (buf, 0, sz);
		r_io_read_at (core->io, from, buf, sz);
		for (i=0;i<sizeof (buf)-vsize; i++) { //= vsize) {
			void *v = (buf+i);
			if (align) {
				if ((from+i)%4)
					continue;
			}
			switch (vsize) {
			case 1:
				if (buf[i]>=vmin && buf[i]<=vmax)
					cbhit (from+i);
				break;
			case 2:
				{ ut16 v16 = *((ut16*)(v));
				if (v16>=vmin && v16<=vmax)
					cbhit (from+i);
				} break;
			case 4:
				{ ut32 v32 = *((ut32 *)(v));
				if (v32>=vmin && v32<=vmax)
					cbhit (from+i);
				} break;
			case 8:
				{ ut64 v64 = *((ut64 *)(v));
				if (v64>=vmin && v64<=vmax)
					cbhit (from+i);
				} break;
			default:
				eprintf ("Unknown vsize\n");
				return -1;
			}
		}
		from += sz;
	}
	return hitctr;
}

static int __prelude_cb_hit(RSearchKeyword *kw, void *user, ut64 addr) {
	RCore *core = (RCore *)user;
	int depth = r_config_get_i (core->config, "anal.depth");
	//eprintf ("ap: Found function prelude %d at 0x%08"PFMT64x"\n", preludecnt, addr);
	searchhits ++; //= kw->count+1;
	r_core_anal_fcn (core, addr, -1, R_ANAL_REF_TYPE_NULL, depth);
	preludecnt++;
	return R_TRUE;
}

R_API int r_core_search_prelude(RCore *core, ut64 from, ut64 to, const ut8 *buf, int blen, const ut8 *mask, int mlen) {
	int ret;
	ut64 at;
	ut8 *b = (ut8 *)malloc (core->blocksize);
// TODO: handle sections ?
	r_search_reset (core->search, R_SEARCH_KEYWORD);
	r_search_kw_add (core->search,
		r_search_keyword_new (buf, blen, mask, mlen, NULL));
	r_search_begin (core->search);
	r_search_set_callback (core->search, &__prelude_cb_hit, core);
	preludecnt = 0;
	for (at = from; at < to; at += core->blocksize) {
		if (r_cons_singleton ()->breaked)
			break;
		ret = r_io_read_at (core->io, at, b, core->blocksize);
		if (ret != core->blocksize)
			break;
		if (r_search_update (core->search, &at, b, ret) == -1) {
			eprintf ("search: update read error at 0x%08"PFMT64x"\n", at);
			break;
		}
	}
	eprintf ("Analized %d functions based on preludes\n", preludecnt);
	free (b);
	return preludecnt;
}

R_API int r_core_search_preludes(RCore *core) {
	int ret = -1;
	const char *prelude = r_config_get (core->config, "anal.prelude");
	const char *arch = r_config_get (core->config, "asm.arch");
	int bits = r_config_get_i (core->config, "asm.bits");
	ut64 from = core->offset;
	ut64 to = core->offset+0xffffff; // hacky!
	// TODO: this is x86 only
	if (prelude && *prelude) {
		ut8 *kw = malloc (strlen (prelude)+1);
		int kwlen = r_hex_str2bin (prelude, kw);
		ret = r_core_search_prelude (core, from, to, kw, kwlen, NULL, 0);
		free (kw);
	} else
	if (strstr (arch, "mips")) {
		ret = r_core_search_prelude (core, from, to,
			(const ut8 *)"\x27\xbd\x00", 3, NULL, 0);
	} else
	if (strstr (arch, "x86")) {
		switch (bits) {
		case 32:
			ret = r_core_search_prelude (core, from, to,
				(const ut8 *)"\x55\x89\xe5", 3, NULL, 0);
			break;
		case 64:
			ret = r_core_search_prelude (core, from, to,
				(const ut8 *)"\x55\x48\x89\xe5", 3, NULL, 0);
			//r_core_cmd0 (core, "./x 554989e5");
			break;
		default:
			eprintf ("ap: Unsupported bits: %d\n", bits);
		}
	} else eprintf ("ap: Unsupported asm.arch and asm.bits\n");
	return ret;
}

static int __cb_hit(RSearchKeyword *kw, void *user, ut64 addr) {
	RCore *core = (RCore *)user;
	ut64 base_addr = 0;

	if (!core) {
		eprintf ("Error: Callback has an invalid RCore.\n");
		return R_FALSE;
	}

	searchhits ++ ;///= kw->count+1;
	if (searchcount) {
		if (!--searchcount) {
			//eprintf ("\nsearch stop: search.count reached\n");
			return R_FALSE;
		}
	}
	if (searchshow && kw && kw->keyword_length > 0) {
		int len, i, extra;
		ut32 buf_sz = kw->keyword_length;
		ut8 *buf = malloc (buf_sz);
		char *str = NULL, *p = NULL;
		extra = (json) ? 3 : 1;
		switch (kw->type) {
		case R_SEARCH_KEYWORD_TYPE_STRING:
			i = (json) ? 0 : 1;
			str = malloc (kw->keyword_length + 20);
			r_core_read_at (core, addr, (ut8*)str+i, kw->keyword_length);
			if (json) {
				r_str_filter_zeroline (str, kw->keyword_length);
			} else {
				*str = '"';
				r_str_filter_zeroline (str, kw->keyword_length+1);
				strcpy (str+kw->keyword_length+1, "\"");
			}
			break;
		default:
			len = kw->keyword_length; // 8 byte context
			str = malloc ((len*2)+extra);
			p=str;
			memset (str, 0, len);
			r_core_read_at (core, addr, buf, kw->keyword_length);
			if (json) {
				strcpy (str, "0x");
				p=str+2;
			} 
			for (i=0; i<len; i++) {
				sprintf (p, "%02x", buf[i]);
				p += 2;
			}
			*p = 0;
			break;
		}

		if (json) {
			if (searchhits > 1) r_cons_printf(",");
			r_cons_printf ("{\"offset\": %"PFMT64d",\"id:\":%d,\"data\":\"%s\"}", 
					base_addr + addr, kw->kwidx, str);
		} else {
			r_cons_printf ("0x%08"PFMT64x" %s%d_%d %s\n",
				base_addr + addr, searchprefix, kw->kwidx, kw->count, str);
		}

		free (buf);
		free (str);
	} else if (kw) {
		if (json) {
			if (searchhits > 1) r_cons_printf(",");
			r_cons_printf ("{\"offset\": %"PFMT64d",\"id:\":%d,\"len\":%d}", 
					base_addr + addr, kw->kwidx, kw->keyword_length);
		} else {
			if (searchflags)
				r_cons_printf ("%s%d_%d\n", searchprefix, kw->kwidx, kw->count);
			else r_cons_printf ("f %s%d_%d %d 0x%08"PFMT64x"\n", searchprefix,
					kw->kwidx, kw->count, kw->keyword_length, addr);
		}
	}
	if (searchflags) {
		char flag[64];
		snprintf (flag, sizeof (flag), "%s%d_%d", searchprefix, kw->kwidx, kw->count);
		r_flag_set (core->flags, flag, addr, kw->keyword_length, 1);
	}
	if (!strnull (cmdhit)) {
		ut64 here = core->offset;
		r_core_seek (core, addr, R_FALSE);
		r_core_cmd (core, cmdhit, 0);
		r_core_seek (core, here, R_TRUE);
	}

	return R_TRUE;
}


static int c = 0;
static inline void print_search_progress(ut64 at, ut64 to, int n) {
	if ((++c%64) || (json))
		return;
	if (r_cons_singleton()->columns<50)
		eprintf ("\r[  ]  0x%08"PFMT64x"  hits = %d   \r%s",
				at, n, (c%2)?"[ #]":"[# ]");
	else eprintf ("\r[  ]  0x%08"PFMT64x" < 0x%08"PFMT64x"  hits = %d   \r%s",
			at, to, n, (c%2)?"[ #]":"[# ]");
}

R_API RList *r_core_get_boundaries (RCore *core, const char *mode, ut64 *from, ut64 *to) {
	RList *list = NULL;
	if (!strcmp (mode, "block")) {
		*from = core->offset;
		*to = core->offset + core->blocksize;
	} else
	if (!strcmp (mode, "io.maps")) {
		*from = *to = 0;
		return core->io->maps;
	} else if (!strcmp (mode, "io.maps.range")) {
		RListIter *iter;
		RIOMap *m;
		*from = *to = 0;
		list = r_list_newf (free);
		r_list_foreach (core->io->maps, iter, m) {
			if (!*from) {
				*from = m->from;
				*to = m->to;
				continue;
			}
			if ((m->from < *from) && m->from)
				*from = m->from;
			if (m->to > *to)
				*to = m->to;
		}
		if (*to == 0LL || *to == UT64_MAX || *to == UT32_MAX)
			*to = r_io_size (core->io);
	} else
	if (!strcmp (mode, "file")) {
		if (core->io->va) {
			RListIter *iter;
			RIOSection *s;
			*from = *to = 0;
			r_list_foreach (core->io->sections, iter, s) {
				if (!*from) {
					*from = s->vaddr;
					*to = s->vaddr+s->vsize;
					continue;
				}
				if (((s->vaddr) < *from) && s->vaddr)
					*from = s->vaddr;
				if ((s->vaddr+s->vsize) > *to)
					*to = s->vaddr+s->vsize;
			}
			if (*to == 0LL || *to == UT64_MAX || *to == UT32_MAX)
				*to = r_io_size (core->io);
		} else {
			RIOMap *map = r_io_map_get (core->io, core->offset);
			*from = core->offset;
			*to = r_io_size (core->io) + (map? map->to:0);
		}
	} else
	if (!strcmp (mode, "io.section")) {
		if (core->io->va) {
			RListIter *iter;
			RIOSection *s;
			*from = *to = core->offset;
			r_list_foreach (core->io->sections, iter, s) {
				if (*from >= s->offset && *from < (s->offset+s->size)) {
					*from = s->vaddr;
					*to = s->vaddr+s->vsize;
					break;
				}
				if (*from >= s->vaddr && *from < (s->vaddr+s->vsize)) {
					*to = s->vaddr+s->size;
					break;
				}
			}
		} else {
			*from = core->offset;
			*to = r_io_size (core->io);
		}
	} else
	if (!strncmp (mode, "io.sections", sizeof("io.sections")-1)) {
		if (core->io->va) {
			int mask = 0;
			RListIter *iter;
			RIOSection *s;

			if (!strcmp (mode, "io.sections.exec")) mask = R_IO_EXEC;
			if (!strcmp (mode, "io.sections.write")) mask = R_IO_WRITE;

			r_list_foreach (core->io->sections, iter, s) {
				if (!mask || (s->rwx & mask)) {
					if (!list) {
						list = r_list_newf (free);
						maplist = R_TRUE;
					}
					RIOMap *map = R_NEW0 (RIOMap);
					map->fd = s->fd;
					map->from = s->vaddr;
					map->to = s->vaddr + s->size;
					map->flags = s->rwx;
					map->delta = 0;
					r_list_append (list, map);
				}
			}
		} else {
			*from = core->offset;
			*to = r_io_size (core->io);
		}
	} else
	if (!strncmp (mode, "dbg.", sizeof("dbg.")-1)) {
		if (core->io->debug) {

			int mask = 0;
			int add = 0;
			int heap = R_FALSE;
			int stack = R_FALSE;
			int all = R_FALSE;
			RListIter *iter;
			RDebugMap *map;

			r_debug_map_sync (core->dbg);

			if (!strcmp (mode, "dbg.map")) {
				*from = *to = core->offset;
				r_list_foreach (core->dbg->maps, iter, map) {
					if (*from >= map->addr && *from < map->addr_end) {
						*from = map->addr;
						*to = map->addr_end;
					}
				}

			} else {
				if (!strcmp (mode, "dbg.maps")) all = R_TRUE;
				if (!strcmp (mode, "dbg.maps.exec")) mask = R_IO_EXEC;
				if (!strcmp (mode, "dbg.maps.write")) mask = R_IO_WRITE;
				if (!strcmp (mode, "dbg.heap")) heap = R_TRUE;
				if (!strcmp (mode, "dbg.stack")) stack = R_TRUE;

				r_list_foreach (core->dbg->maps, iter, map) {
					add = 0;

					if (stack && strstr(map->name, "stack"))
						add = 1;
					else if ((heap && (map->perm | R_IO_WRITE)) && \
							strstr(map->name, "heap"))
						add = 1;

					if ((mask && (map->perm & mask)) || add || all) {
						if (!list) {
							list = r_list_newf (free);
							maplist = R_TRUE;
						}
						RIOMap *nmap = R_NEW0 (RIOMap);
						nmap->fd = core->io->desc->fd;
						nmap->from = map->addr;
						nmap->to = map->addr_end;
						nmap->flags = map->perm;
						nmap->delta = 0;
						r_list_append (list, nmap);
					}
				}
			}
		} else {
			*from = core->offset;
			*to = r_io_size (core->io);
		}
	} else {
		//if (!strcmp (mode, "raw")) {
		/* obey temporary seek if defined '/x 8080 @ addr:len' */
		if (core->tmpseek) {
			*from = core->offset;
			*to = core->offset + core->blocksize;
		} else {
			// TODO: repeat last search doesnt works for /a
			*from = r_config_get_i (core->config, "search.from");
			if (*from == UT64_MAX)
				*from = core->offset;
			*to = r_config_get_i (core->config, "search.to");
			if (*to == UT64_MAX) {
				if (core->io->va) {
					/* TODO: section size? */
				} else {
					*to = r_io_desc_size (core->io, core->file->desc);
				}
			}
		}
	}
	return list;
}

static ut64 findprevopsz(RCore *core, ut64 addr, ut8 *buf) {
	ut8 i;
	RAnalOp aop;

	for (i=0; i<16; i++) {
		if (r_anal_op (core->anal, &aop, addr-i, buf-i, 32-i)) {
			if (aop.size < 1)
				return UT64_MAX;
			if (i == aop.size) {
				switch (aop.type) {
				case R_ANAL_OP_TYPE_ILL:
				case R_ANAL_OP_TYPE_TRAP:
				case R_ANAL_OP_TYPE_RET:
				case R_ANAL_OP_TYPE_UCALL:
				case R_ANAL_OP_TYPE_CJMP:
				case R_ANAL_OP_TYPE_UJMP:
				case R_ANAL_OP_TYPE_JMP:
				case R_ANAL_OP_TYPE_CALL:
					return UT64_MAX;
				}
				return addr-i;
			}
		}
	}
	return UT64_MAX;
}

//TODO: follow unconditional jumps
static RList* construct_rop_gadget(RCore *core, ut64 addr, ut8 *buf, int idx, const char* grep) {
	RAnalOp aop;
	RAsmOp asmop;
	const char* start, *end;
	RCoreAsmHit *hit = NULL;
	RList *hitlist = r_core_asm_hit_list_new ();
	ut8 nb_instr = 0;
	const ut8 max_instr = r_config_get_i (core->config, "search.roplen");
	const ut8 crop = r_config_get_i (core->config, "search.conditionalrop");	//decide if cjmp, cret, and ccall should be used too for the gadget-search
	boolt valid = 0;

	if (grep) {
		start = grep;
		end = strstr (grep, ",");
		if (!end) // We filter on a single opcode, so no ","
			end = start + strlen (grep);
	}

	while (nb_instr < max_instr) {
		if (r_anal_op (core->anal, &aop, addr, buf+idx, 32) > 0) {
			r_asm_set_pc (core->assembler, addr);
			if (!r_asm_disassemble (core->assembler, &asmop, buf+idx, 32))
				goto ret;
			else if (aop.size < 1 || aop.type == R_ANAL_OP_TYPE_ILL)
				goto ret;

			hit = r_core_asm_hit_new ();
			hit->addr = addr;
			hit->len = aop.size;
			r_list_append (hitlist, hit);

			//Move on to the next instruction
			idx += aop.size;
			addr += aop.size;

			//Handle (possible) grep
			if (end && grep && !strncasecmp (asmop.buf_asm, start, end - start)) {
				if (end[0] == ',') { // fields are comma-seperated
					start = end + 1; // skip the comma
					end = strstr (start, ",");
					end = end?end: start + strlen(start); //latest field?
				} else
					end = NULL;
			}

			switch (aop.type) { // end of the gadget
				case R_ANAL_OP_TYPE_TRAP:
				case R_ANAL_OP_TYPE_RET:
				case R_ANAL_OP_TYPE_UCALL:
				case R_ANAL_OP_TYPE_UJMP:
				case R_ANAL_OP_TYPE_JMP:
				case R_ANAL_OP_TYPE_CALL:
					valid = R_TRUE;
					goto ret;
			}
			if (crop) { //if conditional jumps, calls and returns should be used for the gadget-search too
				switch (aop.type) {
					case R_ANAL_OP_TYPE_CJMP:
					case R_ANAL_OP_TYPE_UCJMP:
					case R_ANAL_OP_TYPE_CCALL:
					case R_ANAL_OP_TYPE_UCCALL:
					case R_ANAL_OP_TYPE_CRET:	//i'm a condret
						valid = R_TRUE;
						goto ret;
				}
			}
		}
		nb_instr++;
	}
ret:
	if (!valid || (grep && end)) {
		r_list_free (hitlist);
		return NULL;
	}
	return hitlist;
}

static int r_core_search_rop(RCore *core, ut64 from, ut64 to, int opt, const char *grep) {
	int i=0, end=0, mode=0, increment=1, ret;
	int delta = 0;
	RAsmOp asmop;
	RAnalOp aop;
	ut8 *buf;
	RIOMap *map;
	RList* hitlist;
	RList/*<RIOMap>*/ *list;
	RCoreAsmHit *hit = NULL;
	RAnalOp analop = {0};
	RListIter *iter = NULL;
	RListIter *itermap = NULL;
	boolt json_first = 1;
	const char *smode = r_config_get (core->config, "search.in");
	const char *arch = r_config_get (core->config, "asm.arch");

	if (!strcmp (arch, "mips")) // MIPS has no jump-in-the-middle
		increment = 4;
	else if (!strcmp (arch, "arm")) // ARM has no jump-in-the-middle
		increment = r_config_get_i(core->config, "asm.bits")==16?2:4;

	//Options, like JSON, linear, ...
	if (*grep != ' ') {
		mode = *grep;
		grep++;
	}

	if (*grep==' ') // grep mode
		for (++grep; *grep==' '; grep++);
	else // No grep
		grep = NULL;


	smode = r_config_get (core->config, "search.in");
	if (!strncmp(smode, "dbg.", 4) || !strncmp(smode, "io.sections", 11))
		list = r_core_get_boundaries (core, smode, &from, &to);
	else
		list = NULL;

	if (!list) {
		map = R_NEW0 (RIOMap);
		map->fd = core->io->desc->fd;
		map->from = from;
		map->to = to;
		list = r_list_newf (free);
		r_list_append (list, map);
		maplist = R_TRUE;
	}


	if (json)
		r_cons_printf ("[");

	r_list_foreach (list, itermap, map) {

		from = map->from;
		to = map->to;

		delta = to - from;
		if (delta < 1) {
			delta = from - to;
			if (delta < 1)
				return R_FALSE;
		}

		buf = malloc (delta);
		if (!buf)
			return -1;

		for (i=0; i < delta - 32; i+=increment) {
			if (i >= end) { // read by chunk of 4k
				r_core_read_at (core, from+i, buf+i, R_MIN ((delta-i), 4096));
				end = i + 2048;
			}
			if (r_anal_op (core->anal, &aop, from+i, buf+i, delta-i) > 0) {
				r_asm_set_pc (core->assembler, from+i);
				/// XXX isnt the analop alrady disassembling?
				ret = r_asm_disassemble (core->assembler, &asmop, buf+i, delta-i);
				if (!ret)
					continue;

				hitlist = construct_rop_gadget (core, from+i, buf, i, grep);
				if (!hitlist)
					continue;

				if (json) { // json
					unsigned int size = 0;

					//Handle comma between gadgets
					if (json_first == 0)
						r_cons_strcat (",");
					else
						json_first = 0;

					r_cons_printf("{\"opcodes\":[");
					r_list_foreach (hitlist, iter, hit) {
						r_core_read_at (core, hit->addr, buf, hit->len);
						r_asm_set_pc (core->assembler, hit->addr);
						r_asm_disassemble (core->assembler, &asmop, buf, hit->len);
						r_anal_op (core->anal, &analop, hit->addr, buf, hit->len);
						size += hit->len;
						r_cons_printf ("{\"offset\":%"PFMT64d",\"size\":%d,\"opcode\":\"%s\",\"type\":\"%s\"}%s",
								hit->addr, hit->len, asmop.buf_asm,
								r_anal_optype_to_string (analop.type), iter->n?",":"");
					}
					r_cons_printf ("],\"retaddr\":%"PFMT64d",\"size\":%d}", hit->addr, size);
				} else {
					const char *otype;
					char *buf_asm, *buf_hex;

					// The two loops are distinct for performance reason
					if (mode == 'l') {
						hit = r_list_get_top (hitlist);
						r_cons_printf ("0x%08"PFMT64x" 0x%08"PFMT64x":",
								from+i, hit->addr);
						r_list_foreach (hitlist, iter, hit) {
							r_core_read_at (core, hit->addr, buf, hit->len);
							r_asm_set_pc (core->assembler, hit->addr);
							r_asm_disassemble (core->assembler, &asmop, buf, hit->len);
							buf_asm = r_print_colorize_opcode (asmop.buf_asm, 
								core->cons->pal.reg, core->cons->pal.num);
							r_cons_printf (" %s%s;", buf_asm, Color_RESET);
							free (buf_asm);
						}
					} else {
						r_list_foreach (hitlist, iter, hit) {
							r_core_read_at (core, hit->addr, buf, hit->len);
							r_asm_set_pc (core->assembler, hit->addr);
							r_asm_disassemble (core->assembler, &asmop, buf, hit->len);
							buf_asm = r_print_colorize_opcode (asmop.buf_asm, 
								core->cons->pal.reg, core->cons->pal.num);
							buf_hex = r_print_colorize_opcode (asmop.buf_hex, 
								core->cons->pal.reg, core->cons->pal.num);
							otype = r_print_color_op_type (core->print, analop.type);
							r_cons_printf ("  0x%08"PFMT64x" %s%16s  %s%s\n", 
								hit->addr, otype, buf_hex, buf_asm, Color_RESET);
							free (buf_asm);
							free (buf_hex);
						}
					}
					r_cons_newline ();
				}
			}
		}

		free (buf);
	}

	if (json)
		r_cons_printf ("]\n");

	if (maplist) {
		list->free = free;
		r_list_free (list);
		list = NULL;
	}

	return R_TRUE;
}

static int esil_addrinfo(RAnalEsil *esil) {
	RCore *core = (RCore*)esil->user;
	ut64 num = 0;
	char *src = r_anal_esil_pop (esil);
	if (src && *src && r_anal_esil_get_parm (esil, src, &num)) {
		num = r_core_anal_address (core, num);
		r_anal_esil_pushnum (esil, num);
	} else {
// error. empty stack?
		return 0;
	}
	free (src);
	return 1;
}

static int cmd_search(void *data, const char *input) {
	int i, len, ret, dosearch = R_FALSE;
	RCore *core = (RCore *)data;
	int aes_search = R_FALSE;
	int rsa_search = R_FALSE;
	int crypto_search = R_FALSE;
	int ignorecase = R_FALSE;
	int inverse = R_FALSE;
	int use_mread = R_FALSE;
	int param_offset = 2;
	ut64 at, from = 0, to = 0;
	const char *mode;
	char *inp, bckwrds = R_FALSE, do_bckwrd_srch = R_FALSE;
	ut64 n64, __from, __to;
	ut32 n32;
	ut16 n16;
	ut8 n8;
	ut8 *buf;
	RList/*<RIOMap>*/ *list;

	c = 0;
	json = R_FALSE;
	//core->search->n_kws = 0;
	maplist = R_FALSE;
	__from = r_config_get_i (core->config, "search.from");
	__to = r_config_get_i (core->config, "search.to");

	searchshow = r_config_get_i (core->config, "search.show");
	mode = r_config_get (core->config, "search.in");
	list = r_core_get_boundaries (core, mode, &from, &to);
	use_mread = (!strcmp (mode, "maps"))? 1: 0;

	if (__from != UT64_MAX) from = __from;
	if (__to != UT64_MAX) to = __to;
	/*
	  this introduces a bug until we implement backwards search
	  for all search types
	if (__to < __from) {
		eprintf ("Invalid search range. Check 'e search.{from|to}'\n");
		return R_FALSE;
	}
	since the backward search will be implemented soon I'm not gonna stick
	checks for every case in switch // jjdredd
	remove when everything is done
	*/

	core->search->align = r_config_get_i (core->config, "search.align");
	searchflags = r_config_get_i (core->config, "search.flags");
	//TODO: handle section ranges if from&&to==0
/*
	section = r_io_section_vget (core->io, core->offset);
	if (section) {
		from += section->vaddr;
		//fin = ini + s->size;
	}
*/
	searchprefix = r_config_get (core->config, "search.prefix");
	// TODO: get ranges from current IO section
	/* XXX: Think how to get the section ranges here */
	if (from == 0LL) from = core->offset;
	if (to == 0LL) to = UT32_MAX; // XXX?

	/* we don't really care what's bigger bc there's a flag for backward search
	   from now on 'from' and 'to' represent only the search boundaries, not
	   search direction */
	__from = R_MIN (from, to);
	to = R_MAX (from, to);
	from = __from;
	core->search->bckwrds = R_FALSE;

	if (from == to) {
		eprintf ("WARNING from == to?\n");
	}

	/* Quick & dirty check for json output */
	if(input[1] == 'j') {
		json = R_TRUE;
		param_offset++;
	}

	reread:
	switch (*input) {
	case '!':
		input++;
		inverse = R_TRUE;
		goto reread;
		break;
	case 'B':
		cmd_search_bin (core, from, to);
		break;
	case 'b':
		if (*(++input) == '?'){
			eprintf ("Usage: /b<command> [value] backward search, see '/?'\n");
			return R_TRUE;
		}
		core->search->bckwrds = bckwrds = do_bckwrd_srch = R_TRUE;
		/* if backward search and __to wasn't specified
		   search from the beginning */
		if ((unsigned int)to ==  UT32_MAX){
			to = from;
			from = 0;
		}
		goto reread;
		break;
	case 'P':
		{
		// print the offset of the Previous opcode
		ut8 buf[64];
		ut64 off = core->offset;
		r_core_read_at (core, off-16, buf, 32);
		off = findprevopsz (core, off, buf + 16);
		if (json) r_cons_printf ("[%llu]", off);
		else r_cons_printf ("0x%08llx\n", off);
		}
		break;
	case 'R':
		if (input[1]=='?') {
			const char* help_msg[] = {
				"Usage: /R", "", "Search for ROP gadgets",
				"/R", " [filter-by-string]" , "Show gadgets",
				"/Rl", " [filter-by-string]" , "Show gadgets in a linear manner",
				"/Rj", " [filter-by-string]", "JSON output",
				NULL};
			r_core_cmd_help (core, help_msg);
		} else r_core_search_rop (core, from, to, 0, input+1);
		return R_TRUE;
	case 'r': // "/r"
		if (input[param_offset-1]==' ') {
			r_core_anal_search (core, from, to,
				r_num_math (core->num, input+2));
		} else r_core_anal_search (core, from, to, core->offset);
		break;
	case 'a': {
		char *kwd;
		if (!(kwd = r_core_asm_search (core, input+param_offset, from, to)))
			return R_FALSE;
		r_search_reset (core->search, R_SEARCH_KEYWORD);
		r_search_set_distance (core->search, (int)
				r_config_get_i (core->config, "search.distance"));
		r_search_kw_add (core->search,
				r_search_keyword_new_hexmask (kwd, NULL));
		r_search_begin (core->search);
		free (kwd);
		dosearch = R_TRUE;
		} break;
	case 'C': {
		dosearch = crypto_search = R_TRUE;
		switch (input[1]) {
			case 'a':
				aes_search = R_TRUE;
				break;
			case 'r':
				rsa_search = R_TRUE;
				break;
			default:{
				dosearch = crypto_search = R_FALSE;
				const char* help_msg[] = {
					"Usage: /C", "", "Search for crypto materials",
					"/Ca", "" , "Search for AES keys",
					"/Cr", "", "Search for private RSA keys",
					NULL};
				r_core_cmd_help (core, help_msg);
				}
			}
		} break;
	case '/':
		r_search_begin (core->search);
		dosearch = R_TRUE;
		break;
	case 'm': // "/m"
		dosearch = R_FALSE;
		if (input[1]==' ' || input[1]=='\0') {
			int ret;
			const char *file = input[1]? input+2: NULL;
			ut64 addr = from;
			r_cons_break (NULL, NULL);
			for (; addr<to; addr++) {
				if (r_cons_singleton ()->breaked)
					break;
				ret = r_core_magic_at (core, file, addr, 99, R_FALSE);
				if (ret == -1) {
					// something went terribly wrong.
					break;
				}
				addr += ret-1;
			}
			r_cons_clear_line (0);
			r_cons_break_end ();
		} else eprintf ("Usage: /m [file]\n");
		r_cons_clear_line (1);
		break;
	case 'p': // "/p"
		{
			int ps = atoi (input+param_offset);
			if (ps>1) {
				r_cons_break (NULL, NULL);
				r_search_pattern_size (core->search, ps);
				r_search_pattern (core->search, from, to);
				r_cons_break_end ();
			} else eprintf ("Invalid pattern size (must be >0)\n");
		}
		break;
	case 'V':
		// TODO: add support for json
		{
		int err = 1, vsize = atoi (input+1);
		ut64 vmin = r_num_math (core->num, input+2);
		char *w = strchr (input+3, ' ');
		if (w) {
			ut64 vmax = r_num_math (core->num, w);
			if (vsize>0) {
				err = 0;
				(void)cmd_search_value_in_range (core, from, to, vmin, vmax, vsize);
			}
		}
		if (err)
			eprintf ("Usage: /V[1|2|4|8] [minval] [maxval]\n");
		}
		break;
	case 'v':
		if (input[2] == 'j') {
			json = R_TRUE;
			param_offset++;
		}
		r_search_reset (core->search, R_SEARCH_KEYWORD);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
		switch (input[1]) {
		case '8':
			n64 = r_num_math (core->num, input+param_offset);
			r_mem_copyendian ((ut8*)&n64, (const ut8*)&n64,
				8, !core->assembler->big_endian);
			r_search_kw_add (core->search,
				r_search_keyword_new ((const ut8*)&n64, 8, NULL, 0, NULL));
			break;
		case '1':
			n8 = (ut8)r_num_math (core->num, input+param_offset);
			r_search_kw_add (core->search,
				r_search_keyword_new ((const ut8*)&n8, 1, NULL, 0, NULL));
			break;
		case '2':
			n16 = (ut16)r_num_math (core->num, input+param_offset);
			r_mem_copyendian ((ut8*)&n16, (ut8*)&n16,
				2, !core->assembler->big_endian);
			r_search_kw_add (core->search,
				r_search_keyword_new ((const ut8*)&n16, 2, NULL, 0, NULL));
			break;
		default: // default size
		case '4':
			n32 = (ut32)r_num_math (core->num, input+param_offset);
			r_mem_copyendian ((ut8*)&n32, (const ut8*)&n32,
				4, !core->assembler->big_endian);
			r_search_kw_add (core->search,
				r_search_keyword_new ((const ut8*)&n32, 4, NULL, 0, NULL));
			break;
		}
// TODO: Add support for /v4 /v8 /v2
		r_search_begin (core->search);
		dosearch = R_TRUE;
		break;
	case 'w': /* search wide string, includes ignorecase search functionality (/wi cmd)! */
		if (input[1] == 'j' || input[2] == 'j') json = R_TRUE;
		if (input[1] == 'i' || input[2] == 'i') ignorecase = R_TRUE;

		if (input[1+json+ignorecase] == ' ') {
			int strstart, len;
			const char *p2;
			char *p, *str;
			strstart = 2+json+ignorecase;
			len = strlen(input+strstart);
			str = malloc ((len+1)*2);
			for (p2=input+strstart, p=str; *p2; p+=2, p2++) {
				if (ignorecase)
					p[0] = tolower(*p2);
				else
					p[0] = *p2;
				p[1] = 0;
			}
			r_search_reset (core->search, R_SEARCH_KEYWORD);
			r_search_set_distance (core->search, (int)
				r_config_get_i (core->config, "search.distance"));
			RSearchKeyword *skw;
			skw = r_search_keyword_new ((const ut8*)str, len*2, NULL, 0, NULL);
			free (str);
			if (skw) {
				skw->icase = ignorecase;
				r_search_kw_add (core->search, skw);
				r_search_begin (core->search);
				dosearch = R_TRUE;
			} else {
				eprintf ("Invalid keyword\n");
				break;
			}
		}
		break;
	case 'i':
		if (input[param_offset-1]!= ' ') {
			eprintf ("Missing ' ' after /i\n");
			return R_FALSE;
		}
		ignorecase = R_TRUE;
	case 'j':
		if (input[0] =='j') json = R_TRUE;
	case ' ': /* search string */
		inp = strdup (input+1+ignorecase+json);
		len = r_str_unescape (inp);
		if (!json) {
			eprintf ("Searching %d bytes from 0x%08"PFMT64x" to 0x%08"PFMT64x": ", 
				len, from, to);
			for (i=0; i<len; i++) eprintf ("%02x ", (ut8)inp[i]);
			eprintf ("\n");
		}
		r_search_reset (core->search, R_SEARCH_KEYWORD);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
		{
		RSearchKeyword *skw;
		skw = r_search_keyword_new ((const ut8*)inp, len, NULL, 0, NULL);
		free (inp);
		if (skw) {
			skw->icase = ignorecase;
			skw->type = R_SEARCH_KEYWORD_TYPE_STRING;
			r_search_kw_add (core->search, skw);
		} else {
			eprintf ("Invalid keyword\n");
			break;
		}
		}
		r_search_begin (core->search);
		dosearch = R_TRUE;
		break;
	case 'e': /* match regexp */
		{
		RSearchKeyword *kw;
		kw = r_search_keyword_new_regexp (input + param_offset, NULL);
		if (!kw) {
			eprintf("Invalid regexp specified\n");
			break;
		}
		r_search_reset (core->search, R_SEARCH_REGEXP);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
		r_search_kw_add (core->search, kw);
		r_search_begin (core->search);
		dosearch = R_TRUE;
		}
		break;
	case 'E': {
		RSearchKeyword kw;
		dosearch = R_FALSE;
		if (input[1]==' ') {
			int kwidx = r_config_get_i (core->config, "search.kwidx");
			char *res;
			ut64 nres, addr = from;
			r_cons_break (NULL, NULL);
			if (!core->anal->esil)
				core->anal->esil = r_anal_esil_new ();
			/* hook addrinfo */
			core->anal->esil->user = core;
			r_anal_esil_set_op (core->anal->esil, "AddrInfo", esil_addrinfo);
			/* hook addrinfo */
			r_anal_esil_setup (core->anal->esil, core->anal, 1, 0);
			r_anal_esil_stack_free (core->anal->esil);
			core->anal->esil->debug = 0;
			for (; addr<to; addr++) {
				if (core->search->align) {
					if ((addr % core->search->align)) {
						continue;
					}
				}
#if 0
// we need a way to retrieve info from a speicif address, and make it accessible from the esil search
// maybe we can just do it like this: 0x804840,AddressType,3,&, ... bitmask
// executable = 1
// writable = 2
// inprogram
// instack
// inlibrary
// inheap
r_anal_esil_set_op (core->anal->esil, "AddressInfo", esil_search_address_info);
#endif
				if (r_cons_singleton ()->breaked) {
					eprintf ("Breaked at 0x%08"PFMT64x"\n", addr);
					break;
				}
				r_anal_esil_set_offset (core->anal->esil, addr);
				if (!r_anal_esil_parse (core->anal->esil, input+2)) {
					// XXX: return value doesnt seems to be correct here
					eprintf ("Cannot parse esil (%s)\n", input+2);
					break;
				}
				res = r_anal_esil_pop (core->anal->esil);
				if (r_anal_esil_get_parm (core->anal->esil, res, &nres)) {
					if (nres) {
						__cb_hit (&kw, core, addr);
						//eprintf (" HIT AT 0x%"PFMT64x"\n", addr);
						kw.type = 0; //R_SEARCH_TYPE_ESIL;
						kw.kwidx = kwidx;
						kw.count++;
						kw.keyword_length = 0;
					}
				} else {
					eprintf ("Cannot parse esil (%s)\n", input+2);
					r_anal_esil_stack_free (core->anal->esil);
					free (res);
					break;
				}
				r_anal_esil_stack_free (core->anal->esil);
				free (res);
			}
			r_config_set_i (core->config, "search.kwidx", kwidx +1);
			r_cons_break_end ();
		} else eprintf ("Usage: /E [esil-expr]\n");
		r_cons_clear_line (1);
		return R_TRUE;
		}
		break;
	case 'd': /* search delta key */
		r_search_reset (core->search, R_SEARCH_DELTAKEY);
		r_search_kw_add (core->search,
			r_search_keyword_new_hexmask (input+param_offset, NULL));
		r_search_begin (core->search);
		dosearch = R_TRUE;
		break;
	case 'x': /* search hex */
		r_search_reset (core->search, R_SEARCH_KEYWORD);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
		// TODO: add support for binmask here
		{
			char *s, *p = strdup (input+json+2);
			s = strchr (p, ' ');
			if (!s) s = strchr (p, ':');
			if (s) {
				*s++ = 0;
				r_search_kw_add (core->search,
						r_search_keyword_new_hex (p, s, NULL));
			} else {
				r_search_kw_add (core->search,
						r_search_keyword_new_hexmask (input+json+2, NULL));
			}
			free (p);
		}
		r_search_begin (core->search);
		dosearch = R_TRUE;
		break;
	case 'c': /* search asm */
		{
		RCoreAsmHit *hit;
		RListIter *iter, *itermap;
		int count = 0;
		RList *hits;
		RIOMap *map;

		if (!strncmp(mode, "dbg.", 4) || !strncmp(mode, "io.sections", 11))
			list = r_core_get_boundaries (core, mode, &from, &to);
		else
			list = NULL;

		if (!list) {
			map = R_NEW0 (RIOMap);
			map->fd = core->io->desc->fd;
			map->from = from;
			map->to = to;
			list = r_list_newf (free);
			r_list_append (list, map);
			maplist = R_TRUE;
		}

		if (json) r_cons_printf ("[");
		r_list_foreach (list, itermap, map) {
			from = map->from;
			to = map->to;

			if ((hits = r_core_asm_strsearch (core, input+2, from, to))) {
				r_list_foreach (hits, iter, hit) {
					if (json) {
						if (count > 0) r_cons_printf (",");
						r_cons_printf (
							"{\"offset\":%"PFMT64d",\"len\":%d,\"code\":\"%s\"}", 
							hit->addr, hit->len, hit->code);
					} else {
						r_cons_printf ("f %s_%i @ 0x%08"PFMT64x"   # %i: %s\n",
							searchprefix, count, hit->addr, hit->len, hit->code);
					}
					count++;
				}
				r_list_purge (hits);
				free (hits);
			}
		}
		if (json) r_cons_printf ("]");

		if (maplist) {
			list->free = free;
			r_list_free (list);
			list = NULL;
		}

		dosearch = 0;
		}
		break;
	case '+':
		if (input[1]==' ') {
// TODO: support /+j
			char *buf = malloc (strlen (input)*2);
			char *str = strdup (input+2);
			int ochunksize;
			int i, len, chunksize = r_config_get_i (core->config, "search.chunk");
			if (chunksize<1) {
				chunksize = core->assembler->bits / 8;
			}
			len = r_str_unescape (str);
			ochunksize = chunksize = R_MIN (len, chunksize);
			eprintf ("Using chunksize: %d\n", chunksize);
			for (i=0; i<len; i += chunksize) {
				chunksize = ochunksize;
				again:
				r_hex_bin2str ((ut8*)str+i, R_MIN (chunksize, len-i), buf);
				eprintf ("/x %s\n", buf);
				r_core_cmdf (core, "/x %s", buf);
				if (core->num->value == 0) {
					chunksize--;
					if (chunksize<1) {
						eprintf ("Oops\n");
						free (buf);
						free (str);
						return R_TRUE;
					}
					eprintf ("Repeat with chunk size %d\n", chunksize);
					goto again;
				}
			}
			free (str);
			free (buf);
		} else {
			eprintf ("Usage: /+ [string]\n");
		}
		break;
	case 'z': /* search asm */
		{
		char *p;
		ut32 min, max;
		if (!input[1]) {
			eprintf ("Usage: /z min max\n");
			break;
		}
		if ((p = strchr (input+2, ' '))) {
			*p = 0;
			max = r_num_math (core->num, p+1);
		} else {
			eprintf ("Usage: /z min max\n");
			break;
		}
		min = r_num_math (core->num, input+2);
		if (!r_search_set_string_limits (core->search, min, max)) {
			eprintf ("Error: min must be lower than max\n");
			break;
		}
		r_search_reset (core->search, R_SEARCH_STRING);
		r_search_set_distance (core->search, (int)
				r_config_get_i (core->config, "search.distance"));
		r_search_kw_add (core->search,
			r_search_keyword_new_hexmask ("00", NULL)); //XXX
		r_search_begin (core->search);
		dosearch = R_TRUE;
		}
		break;
	default:{
		const char* help_msg[] = {
			"Usage:", "/[amx/] [arg]", "Search",
			"/"," foo\\x00", "search for string 'foo\\0'",
			"/j"," foo\\x00", "search for string 'foo\\0' (json output)",
			"/!", " ff", "search for first occurrence not matching",
			"/+", " /bin/sh", "construct the string with chunks",
			"/!x", " 00", "inverse hexa search (find first byte != 0x00)",
			"//", "", "repeat last search",
			"/a", " jmp eax", "assemble opcode and search its bytes",
			"/b", "", "search backwards",
			"/B", "", "search recognized RBin headers",
			"/c", " jmp [esp]", "search for asm code (see search.asmstr)",
			"/C", "[ae]", "search for crypto materials",
			"/d", " 101112", "search for a deltified sequence of bytes",
			"/e", " /E.F/i", "match regular expression",
			"/E", " esil-expr", "offset matching given esil expressions %%= here ",
			"/i", " foo", "search for string 'foo' ignoring case",
			"/m", " magicfile", "search for matching magic file (use blocksize)",
			"/p", " patternsize", "search for pattern of given size",
			"/P", "", "show offset of previous instruction",
			"/r", " sym.printf", "analyze opcode reference an offset",
			"/R", " [grepopcode]", "search for matching ROP gadgets, comma-separated",
			"/v", "[1248] value", "look for an `asm.bigendian` 32bit value",
			"/V", "[1248] min max", "look for an `asm.bigendian` 32bit value in range",
			"/w", " foo", "search for wide string 'f\\0o\\0o\\0'",
			"/wi", " foo", "search for wide string ignoring case 'f\\0o\\0o\\0'",
			"/x"," ff..33", "search for hex string ignoring some nibbles",
			"/x"," ff0033", "search for hex string",
			"/x"," ff43 ffd0", "search for hexpair with mask",
			"/z"," min max", "search for strings of given size",
			"\nConfiguration:", "", "",
			"e", " cmd.hit = x", "command to execute on every search hit",
			"e", " search.in = ?", "specify where to search stuff (depends on .from/.to)",
			"e", " search.align = 4", "only catch aligned search hits",
			"e", " search.from = 0", "start address",
			"e", " search.to = 0", "end address",
			"e", " search.asmstr = 0", "search string instead of assembly",
			"e", " search.flags = true", "if enabled store flags on keyword hits",
			NULL};
		r_core_cmd_help (core, help_msg);
		}
		break;
	}
	searchhits = 0;
	r_config_set_i (core->config, "search.kwidx", core->search->n_kws);
	if (dosearch) {
		if (json) r_cons_printf("[");
		int oraise = core->io->raised;
		int bufsz;
		RListIter *iter;
		RIOMap *map;
		if (!searchflags && !json)
			r_cons_printf ("fs hits\n");
		core->search->inverse = inverse;
		searchcount = r_config_get_i (core->config, "search.count");
		if (searchcount)
			searchcount++;
		if (core->search->n_kws>0 || crypto_search) {
			RSearchKeyword aeskw;
			if (crypto_search) {
				memset (&aeskw, 0, sizeof (aeskw));
				aeskw.keyword_length = 31;
			}
			/* set callback */
			/* TODO: handle last block of data */
			/* TODO: handle ^C */
			/* TODO: launch search in background support */
			// REMOVE OLD FLAGS r_core_cmdf (core, "f-%s*", r_config_get (core->config, "search.prefix"));
			r_search_set_callback (core->search, &__cb_hit, core);
			cmdhit = r_config_get (core->config, "cmd.hit");
			r_cons_break (NULL, NULL);
			// XXX required? imho nor_io_set_fd (core->io, core->file->fd);
			if (!list) {
				RIOMap *map = R_NEW0 (RIOMap);
				map->fd = core->io->desc->fd;
				map->from = from;
				map->to = to;
				list = r_list_newf (free);
				r_list_append (list, map);
				maplist = R_TRUE;
			}
			buf = (ut8 *)malloc (core->blocksize);
			bufsz = core->blocksize;
			r_list_foreach (list, iter, map) {
				int fd;
				from = map->from;
				to = map->to;
				searchhits = 0;

				r_io_raise (core->io, map->fd);
				fd = core->io->raised;
				if (fd == -1 && core->io->desc) {
					fd = core->io->desc->fd;
				}
				if (!json)
					eprintf ("# %d [0x%llx-0x%llx]\n", fd, from, to);

				if (bckwrds) {
					if (to < from + bufsz) {
						at = from;
						do_bckwrd_srch = R_FALSE;
					} else at = to - bufsz;
				} else at = from;
				/* bckwrds = false -> normal search -> must be at < to
				   bckwrds search -> check later */
				for (; ( !bckwrds && at < to ) ||  bckwrds ;) {
					print_search_progress (at, to, searchhits);
					if (r_cons_singleton ()->breaked) {
						eprintf ("\n\n");
						break;
					}
					//ret = r_core_read_at (core, at, buf, bufsz);
					//	ret = r_io_read_at (core->io, at, buf, bufsz);
					if (use_mread) {
						// what about a config var to choose which io api to use?
						ret = r_io_mread (core->io, fd, at, buf, bufsz);
					} else {
						r_io_seek (core->io, at, R_IO_SEEK_SET);
						ret = r_io_read (core->io, buf, bufsz);
					}
					/*
					   if (ignorecase) {
					   int i;
					   for (i=0; i<bufsz; i++)
					   buf[i] = tolower (buf[i]);
					   }
					 */
					if (ret <1)
						break;
					if (crypto_search) {
						int delta = 0;
						if (aes_search)
							delta = r_search_aes_update (core->search, at, buf, ret);
						else if (rsa_search)
							delta = r_search_rsa_update (core->search, at, buf, ret);
						if (delta != -1) {
							if (!r_search_hit_new (core->search, &aeskw, at+delta)) {
								break;
							}
							aeskw.count++;
						}
					} else if (r_search_update (core->search, &at, buf, ret) == -1) {
						//eprintf ("search: update read error at 0x%08"PFMT64x"\n", at);
						break;
					}
					if (bckwrds) {
						if (!do_bckwrd_srch) break;
						if (at > from + bufsz) at -= bufsz;
						else {
							do_bckwrd_srch = R_FALSE;
							at = from;
						}
					} else at += bufsz;
				}
				print_search_progress (at, to, searchhits);
				r_cons_break_end ();
				r_cons_clear_line (1);
				core->num->value = searchhits;
				if (searchflags && (searchcount>0) && !json) {
					eprintf ("hits: %d  %s%d_0 .. %s%d_%d\n",
							searchhits,
							searchprefix, core->search->n_kws-1,
							searchprefix, core->search->n_kws-1, searchcount-1);
				} else if (!json) {
					eprintf ("hits: %d\n", searchhits);
				}
				if (!r_list_empty (core->search->kws)) {
					RListIter *iter;
					RSearchKeyword *kw;
					r_list_foreach (core->search->kws, iter, kw) {
						kw->kwidx++;
					}
				}
			}
			free (buf);
			if (maplist) {
				list->free = free;
				r_list_free (list);
				list = NULL;
			}
			r_io_raise (core->io, oraise);
		} else eprintf ("No keywords defined\n");

		/* Crazy party counter (kill me please) */
		if ((searchhits == 0 ) && (core->search->n_kws > 0))
			core->search->n_kws--;

		if (json) r_cons_printf("]");
	}
	return R_TRUE;
}
