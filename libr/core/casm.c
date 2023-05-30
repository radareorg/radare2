/* radare - LGPL - Copyright 2009-2019 - nibble, pancake */

#include <r_types.h>
#include <r_core.h>
#include <r_asm.h>

#define IFDBG if (0)

static RCoreAsmHit *find_addr(RList *hits, ut64 addr);
static int prune_hits_in_hit_range(RList *hits, RCoreAsmHit *hit);
static int is_hit_inrange(RCoreAsmHit *hit, ut64 start_range, ut64 end_range);
static int is_addr_in_range(ut64 start, ut64 end, ut64 start_range, ut64 end_range);
static void add_hit_to_sorted_hits(RList* hits, ut64 addr, int len, ut8 is_valid);
static int prune_hits_in_addr_range(RList *hits, ut64 addr, ut64 len, ut8 is_valid);

static int rcoreasm_address_comparator(RCoreAsmHit *a, RCoreAsmHit *b) {
	if (a->addr == b->addr) {
		return 0;
	}
	if (a->addr < b->addr) {
		return -1;
	}
	return 1; /* a->addr > b->addr */
}

R_API RCoreAsmHit *r_core_asm_hit_new(void) {
	RCoreAsmHit *hit = R_NEW0 (RCoreAsmHit);
	if (!hit) {
		return NULL;
	}
	hit->addr = -1;
	hit->valid = false;
	return hit;
}

R_API RList *r_core_asm_hit_list_new(void) {
	RList *list = r_list_new ();
	if (list) {
		list->free = &r_core_asm_hit_free;
	}
	return list;
}

R_API void r_core_asm_hit_free(void *_hit) {
	RCoreAsmHit *hit = _hit;
	if (hit) {
		if (hit->code) {
			free (hit->code);
		}
		free (hit);
	}
}

R_API char* r_core_asm_search(RCore *core, const char *input) {
	RAsmCode *acode;
	char *ret;
	if (!(acode = r_asm_massemble (core->rasm, input))) {
		return NULL;
	}
	ret = r_asm_code_get_hex (acode);
	r_asm_code_free (acode);
	return ret;
}

// TODO: add support for byte-per-byte opcode search
R_API RList *r_core_asm_strsearch(RCore *core, const char *input, ut64 from, ut64 to, int maxhits, int regexp, int everyByte, int mode) {
	RCoreAsmHit *hit;
	RList *hits;
	ut64 at, toff = core->offset;
	ut8 *buf;
	int align = core->search->align;
	RRegex* rx = NULL;
	char *tok, *tokens[1024], *code = NULL, *ptr;
	char *save_ptr = NULL;
	int idx, tidx = 0, len = 0;
	int tokcount, matchcount, count = 0;
	int matches = 0;
	const int addrbytes = core->io->addrbytes;
	 ut64 first_match_addr = 0;

	if (!input || !*input) {
		return NULL;
	}

	char *inp = r_str_trim_dup (input + 1);
	char *inp_arg = strchr (inp, ' ');
	if (inp_arg) {
		*inp_arg++ = 0;
	}
	ut64 usrimm = r_num_math (core->num, inp);
	ut64 usrimm2 = inp_arg? r_num_math (core->num, inp_arg): usrimm;
	if (usrimm > usrimm2) {
		R_LOG_ERROR ("/ci : Invalid range");
		return NULL;
	}

	if (core->blocksize < 8) {
		R_LOG_ERROR ("block size too small");
		return NULL;
	}
	if (!(buf = (ut8 *)calloc (core->blocksize, 1))) {
		return NULL;
	}
	if (!(ptr = strdup (input))) {
		free (buf);
		return NULL;
	}
	if (!(hits = r_core_asm_hit_list_new ())) {
		free (buf);
		free (ptr);
		return NULL;
	}
	tokens[0] = NULL;
	for (tokcount = 0; tokcount < R_ARRAY_SIZE (tokens) - 1; tokcount++) {
		tok = r_str_tok_r (tokcount? NULL: ptr, ";", &save_ptr);
		if (!tok) {
			break;
		}
		r_str_trim (tok);
		tokens[tokcount] = tok;
	}
	tokens[tokcount] = NULL;
	r_cons_break_push (NULL, NULL);
	char *opst = NULL;
	for (at = from; at < to; at += core->blocksize) {
		if (r_cons_is_breaked ()) {
			break;
		}
		if (!r_io_is_valid_offset (core->io, at, 0)) {
			break;
		}
		(void)r_io_read_at (core->io, at, buf, core->blocksize);
		idx = 0, matchcount = 0;
		while (addrbytes * (idx + 1) <= core->blocksize) {
			ut64 addr = at + idx;
			if (addr >= to) {
				break;
			}
			r_asm_set_pc (core->rasm, addr);
			if (mode == 'i') {
				RAnalOp analop = {0};
				ut64 len = R_MIN (15, core->blocksize - idx);
				if (r_anal_op (core->anal, &analop, addr, buf + idx, len, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_DISASM) < 1) {
					idx ++; // TODO: honor mininstrsz
					continue;
				}
				ut64 val = analop.val; // maybe chk for ptr or others?
				bool match = (val != UT64_MAX && val >= usrimm && val <= usrimm2);
				if (!match) {
					ut64 val = analop.disp;
					match = (val != UT64_MAX && val >= usrimm && val <= usrimm2);
				}
				if (!match) {
					ut64 val = analop.ptr;
					match = (val != UT64_MAX && val >= usrimm && val <= usrimm2);
				}
				if (match) {
					RAnalOp op;
					if (!(hit = r_core_asm_hit_new ())) {
						r_list_purge (hits);
						R_FREE (hits);
						goto beach;
					}
					hit->addr = addr;
					hit->len = analop.size;  //  idx + len - tidx;
					if (hit->len == -1) {
						r_core_asm_hit_free (hit);
						goto beach;
					}
					r_asm_disassemble (core->rasm, &op, buf + addrbytes * idx,
					      core->blocksize - addrbytes * idx);
					hit->code = strdup (op.mnemonic);
					r_asm_op_fini (&op);
					idx = (matchcount)? tidx + 1: idx + 1;
					matchcount = 0;
					r_list_append (hits, hit);
					continue;
				}
				r_anal_op_fini (&analop);
				idx ++; // TODO: honor mininstrsz
				continue;
			} else if (mode == 'e') {
				RAnalOp analop = {0};
				if (r_anal_op (core->anal, &analop, addr, buf + idx, 15, R_ARCH_OP_MASK_ESIL) < 1) {
					idx ++; // TODO: honor mininstrsz
					continue;
				}
				//opsz = analop.size;
				opst = strdup (r_strbuf_get (&analop.esil));
				r_anal_op_fini (&analop);
			} else {
				RAnalOp op;
				if (!(len = r_asm_disassemble (
					      core->rasm, &op,
					      buf + addrbytes * idx,
					      core->blocksize - addrbytes * idx))) {
					idx = (matchcount)? tidx + 1: idx + 1;
					matchcount = 0;
					r_asm_op_fini (&op);
					continue;
				}
				//opsz = op.size;
				opst = strdup (op.mnemonic);
				r_asm_op_fini (&op);
			}
			if (opst) {
				matches = strcmp (opst, "invalid") && strcmp (opst, "unaligned");
			}
			if (matches && tokens[matchcount]) {
				if (mode == 'a') { // check for case sensitive
					matches = !r_str_ncasecmp (opst, tokens[matchcount], strlen (tokens[matchcount]));
				} else if (!regexp) {
					matches = !!strstr (opst, tokens[matchcount]);
				} else {
					rx = r_regex_new (tokens[matchcount], "es");
					matches = r_regex_exec (rx, opst, 0, 0, 0) == 0;
					r_regex_free (rx);
				}
			}
			if (align && align > 1) {
				if (addr % align) {
					matches = false;
				}
			}
			if (matches) {
				code = r_str_appendf (code, "%s; ", opst);
				if (matchcount == 0) {
					first_match_addr = addr;
				}
				if (matchcount == tokcount - 1) {
					if (tokcount == 1) {
						tidx = idx;
					}
					if (!(hit = r_core_asm_hit_new ())) {
						r_list_purge (hits);
						R_FREE (hits);
						goto beach;
					}
					hit->addr = first_match_addr;
					hit->len = idx + len - tidx;
					if (hit->len == -1) {
						r_core_asm_hit_free (hit);
						goto beach;
					}
					code[strlen (code) - 2] = 0;
					hit->code = strdup (code);
					r_list_append (hits, hit);
					R_FREE (code);
					matchcount = 0;
					idx = tidx + 1;
					if (maxhits) {
						count++;
						if (count >= maxhits) {
							//R_LOG_ERROR ("search.maxhits reached");
							goto beach;
						}
					}
				} else if (!matchcount) {
					tidx = idx;
					matchcount++;
					idx += len;
				} else {
					matchcount++;
					idx += len;
				}
			} else {
				if (everyByte) {
					idx = matchcount? tidx + 1: idx + 1;
				} else {
					idx += R_MAX (1, len);
				}
				R_FREE (code);
				matchcount = 0;
			}
			R_FREE (opst);
		}
	}
beach:
	r_asm_set_pc (core->rasm, toff);
	free (buf);
	free (ptr);
	free (code);
	free (inp);
	R_FREE (opst);
	r_cons_break_pop ();
	return hits;
}

static void add_hit_to_sorted_hits(RList* hits, ut64 addr, int len, ut8 is_valid) {
	RCoreAsmHit *hit = r_core_asm_hit_new();
	if (hit) {
		IFDBG eprintf("*** Inserting instruction (valid?: %d): instr_addr: 0x%"PFMT64x" instr_len: %d\n", is_valid, addr, len );
		hit->addr = addr;
		hit->len = len;
		hit->valid = is_valid;
		hit->code = NULL;
		r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));
	}
}

static void add_hit_to_hits(RList* hits, ut64 addr, int len, ut8 is_valid) {
	RCoreAsmHit *hit = r_core_asm_hit_new();
	if (hit) {
		IFDBG eprintf("*** Inserting instruction (valid?: %d): instr_addr: 0x%"PFMT64x" instr_len: %d\n", is_valid, addr, len);
		hit->addr = addr;
		hit->len = len;
		hit->valid = is_valid;
		hit->code = NULL;
		if (!r_list_append (hits, hit)) {
			free (hit);
		}
	}
}

static int prune_hits_in_addr_range(RList *hits, ut64 addr, ut64 len, ut8 is_valid) {
	RCoreAsmHit hit = {0};
	hit.addr = addr;
	hit.len = len;
	hit.valid = is_valid;
	return prune_hits_in_hit_range(hits, &hit);
}

static int prune_hits_in_hit_range(RList *hits, RCoreAsmHit *hit) {
	RListIter *iter, *iter_tmp;
	RCoreAsmHit *to_check_hit;
	int result = 0;
	ut64 start_range, end_range;
	if (!hit || !hits) {
		return 0;
	}
	start_range = hit->addr;
	end_range =  hit->addr +  hit->len;
	r_list_foreach_safe (hits, iter, iter_tmp, to_check_hit) {
		if (to_check_hit && is_hit_inrange(to_check_hit, start_range, end_range)) {
			IFDBG eprintf ("Found hit that clashed (start: 0x%"PFMT64x
				" - end: 0x%"PFMT64x" ), 0x%"PFMT64x" len: %d (valid: %d 0x%"PFMT64x
				" - 0x%"PFMT64x")\n", start_range, end_range, to_check_hit->addr,
				to_check_hit->len, to_check_hit->valid, to_check_hit->addr,
				to_check_hit->addr+to_check_hit->len);
			// XXX - could this be a valid decode instruction we are deleting?
			r_list_delete (hits, iter);
			//iter->data = NULL;
			to_check_hit = NULL;
			result ++;
		}
	}
	return result;
}

static RCoreAsmHit *find_addr(RList *hits, ut64 addr) {
	// Find an address in the list of hits
	RListIter *addr_iter = NULL;
	RCoreAsmHit dummy_value;
	dummy_value.addr = addr;
	addr_iter = r_list_find (hits, &dummy_value, ((RListComparator)rcoreasm_address_comparator));
	return r_list_iter_get_data(addr_iter);
}

static int handle_forward_disassemble(RCore* core, RList *hits, ut8* buf, ut64 len, ut64 current_buf_pos, ut64 current_instr_addr, ut64 end_addr) {
	RCoreAsmHit *hit = NULL, *found_addr = NULL;
	// forward disassemble from the current instruction up to the end address
	ut64 temp_instr_addr = current_instr_addr;
	ut64 tmp_current_buf_pos = current_buf_pos;
	ut64 start_range = current_instr_addr;
	ut64 end_range = end_addr;
	ut64 temp_instr_len = 0;
	ut64 start = 0, end = 0;
	ut8 is_valid = false;

	if (end_addr < current_instr_addr) {
		return end_addr;
	}

	r_asm_set_pc (core->rasm, current_instr_addr);
	while (tmp_current_buf_pos < len && temp_instr_addr < end_addr) {
		RAnalOp op;
		temp_instr_len = len - tmp_current_buf_pos;
		IFDBG eprintf("Current position: %"PFMT64d" instr_addr: 0x%"PFMT64x"\n", tmp_current_buf_pos, temp_instr_addr);
		temp_instr_len = r_asm_disassemble (core->rasm, &op, buf+tmp_current_buf_pos, temp_instr_len);

		if (temp_instr_len == 0) {
			is_valid = false;
			temp_instr_len = 1;
		} else {
			is_valid = true;
		}

		// check to see if addr exits
		found_addr = find_addr(hits, temp_instr_addr);
		start = temp_instr_addr;
		end = temp_instr_addr + temp_instr_len;

		if (!found_addr) {
			add_hit_to_sorted_hits(hits, temp_instr_addr, temp_instr_len, is_valid);
		} else if (is_valid && !found_addr->valid && is_addr_in_range(start, end, start_range, end_range )) {
			ut32 prune_results = 0;
			prune_results = prune_hits_in_addr_range(hits, temp_instr_addr, temp_instr_len, is_valid);
			add_hit_to_sorted_hits(hits, temp_instr_addr, temp_instr_len, is_valid);
			if (prune_results) {
				r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));
				IFDBG eprintf("Pruned %u hits from list in fwd sweep.\n", prune_results);
			} else {
				R_FREE (hit);
			}
		}

		temp_instr_addr += temp_instr_len;
		tmp_current_buf_pos += temp_instr_len;
		r_asm_op_fini (&op);
	}
	return temp_instr_addr;
}

#if 0
static int handle_disassembly_overlap(RCore* core, RList *hits, ut8* buf, int len, ut64 current_buf_pos, ut64 current_instr_addr ) {
	// disassemble over lap means the current instruction decoded using the bytes in a previously decoded instruction
	ut64 next_buf_pos = current_buf_pos,
		end_addr = current_instr_addr + ( len - current_buf_pos - 1);

	/* Sub optimal method (e.g. easy) */
	handle_forward_disassemble (core, hits, buf, len, current_buf_pos, current_instr_addr, end_addr );
	next_buf_pos = current_buf_pos;
	return next_buf_pos;
}
#endif

static int is_addr_in_range(ut64 start, ut64 end, ut64 start_range, ut64 end_range) {
	int result = false;
	if (start == start_range) {
		return true;
	}
	if (start < end && start_range < end_range) {
		// ez cases
		if (start_range <= start && start < end_range) {
			result = true;
		} else if (start_range < end && end < end_range) {
			result = true;
		} else if (start <= start_range && end_range < end) {
			result = true;
		}
	// XXX - these cases need to be tested
	// (long long) start_range < 0 < end_range
	} else if (start_range > end_range) {
		if (start < end) {
			if (start < end_range) {
				result = true;
			} else if (end <= end_range) {
				result = true;
			} else if (start_range <= start) {
				result = true;
			} else if (start_range < end) {
				result = true;
			}
			// (long long) start < 0 < end
		} else {
			if (end < end_range) {
				result = true;
			} else if (end <= end_range) {
				result = true;
			} else if (start_range <= start) {
				result = true;
			}
		}
	// XXX - these cases need to be tested
	// (long long) start < 0 < end
	} else if (start_range < end_range) {
		if (start < end_range) {
			result = true;
		} else if (start <= start_range) {
			result = true;
		} else if (start_range < end) {
			result = true;
		}
	}
	return result;
}

static int is_hit_inrange(RCoreAsmHit *hit, ut64 start_range, ut64 end_range) {
	int result = false;
	if (hit) {
		result = is_addr_in_range (hit->addr,
			hit->addr + hit->len,
			start_range, end_range);
	}
	return result;
}

R_API RList *r_core_asm_bwdisassemble(RCore *core, ut64 addr, int n, int len) {
	// if (n > core->blocksize) n = core->blocksize;
	ut64 at;
	ut32 idx = 0, hit_count;
	int numinstr, asmlen, ii;
	const int addrbytes = core->io->addrbytes;
	RAsmCode *c;
	RList *hits = r_core_asm_hit_list_new ();
	if (!hits) {
		return NULL;
	}

	len = R_MIN (len - len % addrbytes, addrbytes * addr);
	if (len < 1) {
		r_list_free (hits);
		return NULL;
	}

	ut8 *buf = (ut8 *)malloc (len);
	if (!buf) {
		r_list_free (hits);
		return NULL;
	} else if (!hits) {
		free (buf);
		return NULL;
	}
	if (!r_io_read_at (core->io, addr - len / addrbytes, buf, len)) {
		r_list_free (hits);
		free (buf);
		return NULL;
	}

	for (idx = addrbytes; idx < len; idx += addrbytes) {
		if (r_cons_is_breaked ()) {
			break;
		}
		c = r_asm_mdisassemble (core->rasm, buf + len - idx, idx);
		if (strstr (c->assembly, "invalid") || strstr (c->assembly, ".byte")) {
			r_asm_code_free (c);
			continue;
		}
		numinstr = 0;
		asmlen = strlen (c->assembly);
		for (ii = 0; ii < asmlen; ii++) {
			if (c->assembly[ii] == '\n') {
				numinstr++;
			}
		}
		r_asm_code_free (c);
		if (numinstr >= n || idx > 16 * n) { // assume average instruction length <= 16
			break;
		}
	}
	at = addr - idx / addrbytes;
	r_asm_set_pc (core->rasm, at);
	for (hit_count = 0; hit_count < n; hit_count++) {
		RAnalOp op;
		int instrlen = r_asm_disassemble (core->rasm, &op,
			buf + len - addrbytes * (addr - at), addrbytes * (addr - at));
		add_hit_to_hits (hits, at, instrlen, true);
		at += instrlen;
		r_asm_op_fini (&op);
	}
	free (buf);
	return hits;
}

static RList *r_core_asm_back_disassemble_all(RCore *core, ut64 addr, ut64 len, ut64 max_hit_count, ut32 extra_padding) {
	RList *hits = r_core_asm_hit_list_new ();
	RCoreAsmHit dummy_value;
	RCoreAsmHit *hit = NULL;
	ut8 *buf = (ut8 *)malloc (len + extra_padding);
	int current_instr_len = 0;
	ut64 current_instr_addr = addr,
		 current_buf_pos = len - 1,
		 hit_count = 0;

	memset (&dummy_value, 0, sizeof (RCoreAsmHit));

	if (!hits || !buf ) {
		if (hits) {
			r_list_purge (hits);
			free (hits);
		}
		free (buf);
		return NULL;
	}

	if (!r_io_read_at (core->io, addr-(len+extra_padding), buf, len + extra_padding)) {
		r_list_purge (hits);
		free (hits);
		free (buf);
		return NULL;
	}

	if (len == 0) {
		return hits;
	}

	do {
		RAnalOp op;
		if (r_cons_is_breaked ()) {
			break;
		}
		// reset assembler
		r_asm_set_pc (core->rasm, current_instr_addr);
		current_instr_len = len - current_buf_pos + extra_padding;
		IFDBG eprintf("current_buf_pos: 0x%"PFMT64x", current_instr_len: %d\n", current_buf_pos, current_instr_len);
		current_instr_len = r_asm_disassemble (core->rasm, &op, buf+current_buf_pos, current_instr_len);
		hit = r_core_asm_hit_new ();
		hit->addr = current_instr_addr;
		hit->len = current_instr_len;
		hit->code = NULL;
		r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));

		current_buf_pos--;
		current_instr_addr--;
		hit_count++;
		r_asm_op_fini (&op);
	} while ( ((int) current_buf_pos  >= 0) && (int)(len - current_buf_pos) >= 0 && hit_count <= max_hit_count);

	free (buf);
	return hits;
}

static RList *r_core_asm_back_disassemble(RCore *core, ut64 addr, int len, ut64 max_hit_count, ut8 disassmble_each_addr, ut32 extra_padding) {
	RList *hits;
	ut8 *buf = NULL;
	ut8 max_invalid_b4_exit = 4,
		last_num_invalid = 0;
	int current_instr_len = 0;
	ut64 current_instr_addr = addr,
		current_buf_pos = 0,
		next_buf_pos = len;

	RCoreAsmHit dummy_value;
	ut32 hit_count = 0;

	if (disassmble_each_addr) {
		return r_core_asm_back_disassemble_all(core, addr, len, max_hit_count, extra_padding+1);
	}

	hits = r_core_asm_hit_list_new ();
	buf = malloc (len + extra_padding);
	if (!hits || !buf) {
		if (hits) {
			r_list_purge (hits);
			free (hits);
		}
		free (buf);
		return NULL;
	}

	if (!r_io_read_at (core->io, (addr + extra_padding) - len, buf, len + extra_padding)) {
		r_list_purge (hits);
		free (hits);
		free (buf);
		return NULL;
	}

	//
	// XXX - This is a heavy handed approach without a
	// 		an appropriate btree or hash table for storing
	//	 hits, because are using:
	//			1) Sorted RList with many inserts and searches
	//			2) Pruning hits to find the most optimal disassembly

	// greedy approach
	// 1) Consume previous bytes
	// 1a) Instruction is invalid (incr current_instr_addr)
	// 1b) Disasm is perfect
	// 1c) Disasm is underlap (disasm(current_instr_addr, next_instr_addr - current_instr_addr) short some bytes)
	// 1d) Disasm is overlap (disasm(current_instr_addr, next_instr_addr - current_instr_addr) over some bytes)

	memset (&dummy_value, 0, sizeof (RCoreAsmHit));
	// disassemble instructions previous to current address, extra_padding can move the location of addr
	// so we need to account for that with current_buf_pos
	current_buf_pos = len - extra_padding - 1;
	next_buf_pos = len + extra_padding - 1;
	current_instr_addr = addr - 1;
	do {
		RAnalOp op;
		if (r_cons_is_breaked ()) {
			break;
		}
		// reset assembler
		r_asm_set_pc (core->rasm, current_instr_addr);
		current_instr_len = next_buf_pos - current_buf_pos;
		current_instr_len = r_asm_disassemble (core->rasm, &op, buf+current_buf_pos, current_instr_len);
		IFDBG {
			ut32 byte_cnt =  current_instr_len ? current_instr_len : 1;
			eprintf("current_instr_addr: 0x%"PFMT64x", current_buf_pos: 0x%"PFMT64x", current_instr_len: %d \n", current_instr_addr, current_buf_pos, current_instr_len);

			ut8 *hex_str = (ut8*)r_hex_bin2strdup(buf+current_buf_pos, byte_cnt);
			eprintf ("==== current_instr_bytes: %s ",hex_str);

			if (current_instr_len > 0) {
				eprintf ("op.buf_asm: %s\n", op.mnemonic);
			} else {
				eprintf ("op.buf_asm: <invalid>\n");
			}
			free (hex_str);
		}
		// disassembly invalid
		if (current_instr_len == 0 || strstr (op.mnemonic, "invalid")) {
			if (current_instr_len == 0) {
				current_instr_len = 1;
			}
			add_hit_to_sorted_hits(hits, current_instr_addr, current_instr_len, /* is_valid */ false);
			hit_count ++;
			last_num_invalid ++;
		// disassembly perfect
		} else if (current_buf_pos + current_instr_len == next_buf_pos) {
			// i think this may be the only case where an invalid instruction will be
			// added because handle_forward_disassemble and handle_disassembly_overlap
			// are only called in cases where a valid instruction has been found.
			// and they are lazy, since they purge the hit list
			ut32 purge_results = 0;
			ut8 is_valid = true;
			IFDBG eprintf(" handling underlap case: current_instr_addr: 0x%"PFMT64x".\n", current_instr_addr);
			purge_results =  prune_hits_in_addr_range(hits, current_instr_addr, current_instr_len, /* is_valid */ true);
			if (purge_results) {
				handle_forward_disassemble(core, hits, buf, len, current_buf_pos+current_instr_len, current_instr_addr+current_instr_len, addr);
				hit_count = r_list_length(hits);
			}
			add_hit_to_sorted_hits(hits, current_instr_addr, current_instr_len, is_valid);
			//handle_forward_disassemble(core, hits, buf, len, current_buf_pos+current_instr_len, current_instr_addr+current_instr_len, addr/*end_addr*/);
			hit_count ++;
			next_buf_pos = current_buf_pos;
			last_num_invalid = 0;
		// disassembly underlap
		} else if (current_buf_pos + current_instr_len < next_buf_pos) {
			ut32 purge_results = 0;
			ut8 is_valid = true;
			purge_results =  prune_hits_in_addr_range(hits, current_instr_addr, current_instr_len, /* is_valid */ true);
			add_hit_to_sorted_hits(hits, current_instr_addr, current_instr_len, is_valid);

			if (hit_count < purge_results) {
				hit_count = 0; // WTF??
			} else {
				hit_count -= purge_results;
			}

			next_buf_pos = current_buf_pos;
			handle_forward_disassemble(core, hits, buf, len - extra_padding, current_buf_pos+current_instr_len, current_instr_addr+current_instr_len, addr);
			hit_count = r_list_length(hits);
			last_num_invalid = 0;
		// disassembly overlap
		} else if (current_buf_pos + current_instr_len > next_buf_pos) {
			//ut64 value = handle_disassembly_overlap(core, hits, buf, len, current_buf_pos, current_instr_addr);
			next_buf_pos = current_buf_pos;
			hit_count = r_list_length (hits);
			last_num_invalid = 0;
		}

		// walk backwards by one instruction
		IFDBG eprintf(" current_instr_addr: 0x%"PFMT64x" current_instr_len: %d next_instr_addr: 0x%04"PFMT64x"\n",
			current_instr_addr, current_instr_len, next_buf_pos);
		IFDBG eprintf(" hit count: %d \n", hit_count );
		current_instr_addr -= 1;
		current_buf_pos -= 1;

		r_asm_op_fini (&op);
		if (hit_count >= max_hit_count &&
			(last_num_invalid >= max_invalid_b4_exit || last_num_invalid == 0)) {
			break;
		}
	} while (((int) current_buf_pos >= 0) && (int)(len - current_buf_pos) >= 0);

	r_asm_set_pc (core->rasm, addr);
	free (buf);
	return hits;
}

R_API RList *r_core_asm_back_disassemble_instr(RCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding) {
	// extra padding to allow for additional disassembly on border buffer cases
	ut8 disassmble_each_addr  = false;
	return r_core_asm_back_disassemble (core, addr, len, hit_count, disassmble_each_addr, extra_padding);
}

R_API RList *r_core_asm_back_disassemble_byte(RCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding) {
	// extra padding to allow for additional disassembly on border buffer cases
	ut8 disassmble_each_addr  = true;
	return r_core_asm_back_disassemble (core, addr, len, hit_count, disassmble_each_addr, extra_padding);
}

/* Compute the len and the starting address
 * when disassembling `nb` opcodes backward. */
R_API ut32 r_core_asm_bwdis_len(RCore* core, int* instr_len, ut64* start_addr, ut32 nb) {
	ut32 instr_run = 0;
	RCoreAsmHit *hit;
	RListIter *iter = NULL;
	// TODO if length of nb instructions is larger than blocksize
	RList* hits = r_core_asm_bwdisassemble (core, core->offset, nb, core->blocksize);
	if (instr_len) {
		*instr_len = 0;
	}
	if (hits && r_list_length (hits) > 0) {
		hit = r_list_first (hits);
		if (start_addr) {
			*start_addr = hit->addr;
		}
		r_list_foreach (hits, iter, hit) {
			instr_run += hit->len;
		}
		if (instr_len) {
			*instr_len = instr_run;
		}
	}
	r_list_free (hits);
	return instr_run;
}
