/* radare - LGPL - Copyright 2009-2012 - nibble */

#include <r_types.h>
#include <r_core.h>
#include <r_asm.h>

#define IFDBG if (0)

static RCoreAsmHit * find_addr(RList *hits, ut64 addr);
static int prune_hits_in_hit_range(RList *hits, RCoreAsmHit *hit);
static int is_hit_inrange(RCoreAsmHit *hit, ut64 start_range, ut64 end_range);
static int is_addr_in_range(ut64 start, ut64 end, ut64 start_range, ut64 end_range);
static void add_hit_to_hits(RList* hits, ut64 addr, ut64 len, ut8 is_valid);
static int prune_hits_in_addr_range(RList *hits, ut64 addr, ut64 len, ut8 is_valid);

static int rcoreasm_address_comparator(RCoreAsmHit *a, RCoreAsmHit *b){
	if (a->addr == b->addr)
		return 0;
	else if (a->addr < b->addr)
		return -1;
	// a->addr > b->addr
	return 1;

}

R_API RCoreAsmHit *r_core_asm_hit_new() {
	RCoreAsmHit *hit = R_NEW (RCoreAsmHit);
	if (!hit) return NULL;
	hit->code = NULL;
	hit->len = 0;
	hit->addr = -1;
	hit->valid = R_FALSE;
	return hit;
}

R_API RList *r_core_asm_hit_list_new() {
	RList *list = r_list_new ();
	list->free = &r_core_asm_hit_free;
	return list;
}

R_API void r_core_asm_hit_free(void *_hit) {
	RCoreAsmHit *hit = _hit;
	if (hit) {
		if (hit->code)
			free (hit->code);
		free (hit);
	}
}

R_API char* r_core_asm_search(RCore *core, const char *input, ut64 from, ut64 to) {
	RAsmCode *acode;
	char *ret;
	if (!(acode = r_asm_massemble (core->assembler, input)))
		return NULL;
	ret = strdup (acode->buf_hex);
	r_asm_code_free (acode);
	return ret;
}

#define OPSZ 8
// TODO: add support for byte-per-byte opcode search
R_API RList *r_core_asm_strsearch(RCore *core, const char *input, ut64 from, ut64 to) {
	RCoreAsmHit *hit;
	RAsmOp op;
	RList *hits;
	ut64 at, toff = core->offset;
	ut8 *buf;
	char *tok, *tokens[1024], *code = NULL, *ptr;
	int idx, tidx = 0, ret, len;
	int tokcount, matchcount;

	if (!*input)
		return NULL;
	if (core->blocksize<=OPSZ) {
		eprintf ("error: block size too small\n");
		return NULL;
	}
	if (!(buf = (ut8 *)malloc (core->blocksize)))
		return NULL;
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
	for (tokcount=0; tokcount<sizeof (tokens); tokcount++) {
		tok = strtok (tokcount? NULL: ptr, ",");
		if (tok == NULL)
			break;
		tokens[tokcount] = r_str_trim_head_tail (tok);
	}
	tokens[tokcount] = NULL;
	r_cons_break (NULL, NULL);
	for (at = from, matchcount = 0; at < to; at += core->blocksize-OPSZ) {
		if (r_cons_singleton ()->breaked)
			break;
		ret = r_io_read_at (core->io, at, buf, core->blocksize);
		if (ret != core->blocksize)
			break;
		idx = 0, matchcount = 0;
		while (idx<core->blocksize) {
			r_asm_set_pc (core->assembler, at+idx);
			op.buf_asm[0] = 0;
			op.buf_hex[0] = 0;
			if (!(len = r_asm_disassemble (core->assembler, &op, buf+idx, core->blocksize-idx))) {
				idx = (matchcount)? tidx+1: idx+1;
				matchcount = 0;
				continue;
			}
			if (tokens[matchcount] && strstr (op.buf_asm, tokens[matchcount])) {
				code = r_str_concatf (code, "%s", op.buf_asm);
				if (matchcount == tokcount-1) {
					if (tokcount == 1)
						tidx = idx;
					if (!(hit = r_core_asm_hit_new ())) {
						r_list_destroy (hits);
						hits = NULL;
						goto beach;
					}
					hit->addr = at+tidx;
					hit->len = idx+len-tidx;
					if (hit->len == -1) {
						r_core_asm_hit_free (hit);
						goto beach;
					}
					hit->code = strdup (code);
					r_list_append (hits, hit);
					R_FREE (code);
					matchcount = 0;
					idx = tidx+1;
				} else  if (matchcount == 0) {
					tidx = idx;
					matchcount++;
					idx += len;
				} else {
					matchcount++;
					idx += len;
				}
			} else {
				idx = matchcount? tidx+1: idx+1;
				R_FREE (code);
				matchcount = 0;
			}
		}
	}
	r_asm_set_pc (core->assembler, toff);
beach:
	free (buf);
	free (ptr);
	free (code);
	return hits;
}


static void add_hit_to_hits(RList* hits, ut64 addr, ut64 len, ut8 is_valid) {

	RCoreAsmHit *hit = r_core_asm_hit_new();
	if (hit) {
		IFDBG eprintf("*** Inserting instruction (valid?: %d): instr_addr: 0x%llx instr_len: %d\n", is_valid, addr, len );
		hit->addr = addr;
		hit->len = len;
		hit->valid = is_valid;
		hit->code = NULL;
		r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));
	}


}

static int prune_hits_in_addr_range(RList *hits, ut64 addr, ut64 len, ut8 is_valid) {
	RCoreAsmHit hit;

	hit.addr = addr;
	hit.len = len;
	hit.code = NULL;
	hit.valid = is_valid;

	return prune_hits_in_hit_range(hits, &hit);

}


static int prune_hits_in_hit_range(RList *hits, RCoreAsmHit *hit){
	RListIter *iter, *iter_tmp;
	RCoreAsmHit *to_check_hit;
	int result = 0;

	ut64 start_range, end_range;

	if (hit == NULL || hits == NULL) return 0;

	start_range = hit->addr;
	end_range =  hit->addr +  hit->len;
	
	r_list_foreach_safe (hits, iter, iter_tmp, to_check_hit){
		if (to_check_hit && is_hit_inrange(to_check_hit, start_range, end_range)) {
			IFDBG eprintf ("Found hit that clashed (start: 0x%llx - end: 0x%llx ), 0x%llx len: %d (valid: %d 0x%llx - 0x%llx)\n", start_range, end_range, 
					to_check_hit->addr, to_check_hit->len, to_check_hit->valid, to_check_hit->addr, to_check_hit->addr+to_check_hit->len);
			// XXX - could this be a valid decode instruction we are deleting?
			r_list_delete (hits, iter);
			iter->data = NULL;
			to_check_hit = NULL;
			result ++;
		} 
	}
	return result;
}

static RCoreAsmHit * find_addr(RList *hits, ut64 addr) {
	// Find an address in the list of hits
	RListIter *addr_iter = NULL;
	RCoreAsmHit dummy_value;
	dummy_value.addr = addr; 
	addr_iter = r_list_find (hits, &dummy_value, ((RListComparator)rcoreasm_address_comparator));
	return r_list_iter_get_data(addr_iter);
}


static int handle_forward_disassemble(RCore* core, RList *hits, ut8* buf, ut64 len, ut64 current_buf_pos, ut64 current_instr_addr, ut64 end_addr){
	// forward disassemble from the current instruction up to the end address
	ut64 temp_instr_len = 0,
		temp_instr_addr = current_instr_addr,
		tmp_current_buf_pos = current_buf_pos;
	RAsmOp op;
	RCoreAsmHit *hit = NULL, *found_addr = NULL;
	ut8 is_valid = R_FALSE;

	ut64 start = 0,  end = 0, 
		 start_range = current_instr_addr, 
		 end_range = end_addr;
	
	if (end_addr < current_instr_addr)
		return end_addr;

	r_asm_set_pc (core->assembler, current_instr_addr);
	while ( tmp_current_buf_pos < len && temp_instr_addr < end_addr) {
		temp_instr_len = len - tmp_current_buf_pos;
		IFDBG eprintf("Current position: %d instr_addr: 0x%llx \n", tmp_current_buf_pos, temp_instr_addr);
		temp_instr_len = r_asm_disassemble (core->assembler, &op, buf+tmp_current_buf_pos, temp_instr_len);
		
		if (temp_instr_len == 0){
			is_valid = R_FALSE;
			temp_instr_len = 1;
		} else 
			is_valid = R_TRUE;
		
		// check to see if addr exits
		found_addr = find_addr(hits, temp_instr_addr);
		start = temp_instr_addr;
		end = temp_instr_addr + temp_instr_len;

		if (!found_addr) { 
			add_hit_to_hits(hits, temp_instr_addr, temp_instr_len, is_valid);
		} else if (is_valid && !found_addr->valid && is_addr_in_range(start, end, start_range, end_range )) {
			ut32 prune_results = 0;
			prune_results = prune_hits_in_addr_range(hits, temp_instr_addr, temp_instr_len, is_valid);
			add_hit_to_hits(hit, temp_instr_addr, temp_instr_len, is_valid);

			if (prune_results ) {
				r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));
				IFDBG eprintf("Pruned %d hits from list in fwd sweep.\n");
			}else {
				free(hit);
				hit = NULL;
			}


		}

		
		temp_instr_addr += temp_instr_len;
		tmp_current_buf_pos += temp_instr_len;
 
	}
	return temp_instr_addr;
}


static int handle_disassembly_overlap(RCore* core, RList *hits, ut8* buf, ut64 len, ut64 current_buf_pos, ut64 current_instr_addr ) {
	// disassemble over lap means the current instruction decoded using the bytes in a previously decoded instruction
	RCoreAsmHit dummy_value;
	RListIter *stop_hit_addr = NULL;
	RAsmOp op;
	
	ut64 next_buf_pos = current_buf_pos,
		end_addr = current_instr_addr + ( len - current_buf_pos - 1);

	/* Sub optimal method (e.g. easy) */
	handle_forward_disassemble(core, hits, buf, len, current_buf_pos, current_instr_addr, end_addr );
	next_buf_pos = current_buf_pos;
	return next_buf_pos;
}

static int is_addr_in_range(ut64 start, ut64 end, ut64 start_range, ut64 end_range){
	int result = R_FALSE, reverse_range, reverse_addr;
	ut64 rstart_range, rend_range,
		 rstart, rend,
		 base = -1;

	if (start == start_range) {
		return R_TRUE;
	} else if (start < end && start_range < end_range) {
		// ez cases
		if ( start_range <= start &&   start < end_range )
			result = R_TRUE;
		else if (start_range < end && end < end_range )
			result = R_TRUE;
		else if ( start <= start_range && end_range < end )
			result = R_TRUE;
	// XXX - these cases need to be tested
	// (long long) start_range < 0 < end_range
	} else if (start_range > end_range) {
		if (start < end) {
			if (start < end_range)
				result = R_TRUE;
			else if (end <= end_range)
				result = R_TRUE;
			else if ( start_range <= start )
				result = R_TRUE;
			else if ( start_range < end )
				result = R_TRUE;
		// (long long) start < 0 < end
		} else {
			if (end < end_range)
				result = R_TRUE;
			else if (end <= end_range)
				result = R_TRUE;
			else if ( start_range <= start )
				result = R_TRUE;
		}
	// XXX - these cases need to be tested
	// (long long) start < 0 < end
	} else if (start_range < end_range) {
		if ( start < end_range)
			result = R_TRUE;
		else if ( start <= start_range )
			result = R_TRUE;
		else if ( start_range < end)
			result = R_TRUE; 
	} 
	return result;
}

static int is_hit_inrange(RCoreAsmHit *hit, ut64 start_range, ut64 end_range){
	int result = R_FALSE;
	if (hit) {
		result = is_addr_in_range(hit->addr, hit->addr + hit->len, start_range, end_range);
	}
	return result;
}

R_API RList *r_core_asm_bwdisassemble (RCore *core, ut64 addr, int n, int len) {
	RCoreAsmHit *hit;
	RAsmOp op;
	RList *hits = NULL;
	ut8 *buf;
	ut64 at;
	int instrlen, ni, idx;

	if (!(hits = r_core_asm_hit_list_new ())) return NULL;
	buf = (ut8 *)malloc (len);
	if (!buf) {
		r_list_destroy (hits);
		return NULL;
	}
	if (r_io_read_at (core->io, addr-len, buf, len) != len) {
		r_list_destroy (hits);
		free (buf);
		return NULL;
	}
	for (idx = 1; idx < len; idx++) {
		if (r_cons_singleton ()->breaked) break;
		at = addr - idx; ni = 1;
		while (at < addr) {
			r_asm_set_pc (core->assembler, at);
			//XXX HACK We need another way to detect invalid disasm!!
			if (!(instrlen = r_asm_disassemble (core->assembler, &op, buf+(len-(addr-at)), addr-at)) || strstr (op.buf_asm, "invalid")) {
				break;
			} else {
				at += instrlen;
				if (at == addr) {
					if (ni == n) {
						if (!(hit = r_core_asm_hit_new ())) {
							r_list_destroy (hits);
							free (buf);
							return NULL;
						}
						hit->addr = addr-idx;
						hit->len = idx;
						hit->code = NULL;
						r_list_append (hits, hit);
					}
				} else ni++;
			}
		}
	}
	r_asm_set_pc (core->assembler, addr);
	free (buf);
	return hits;
}


static RList * r_core_asm_back_disassemble_all(RCore *core, ut64 addr, ut64 len, ut64 max_hit_count, ut32 extra_padding){
	RList *hits = r_core_asm_hit_list_new ();
	RCoreAsmHit dummy_value;
	RCoreAsmHit *hit = NULL;
	RAsmOp op;
	ut8 *buf = (ut8 *)malloc (len + extra_padding);
	ut64 current_instr_len = 0, 
		 current_instr_addr = addr, 
		 current_buf_pos = len - 1,
		 hit_count = 0;

	memset (&dummy_value, 0, sizeof (RCoreAsmHit));
	
	if (hits == NULL || buf == NULL ){
		if (hits) r_list_destroy (hits);
		if (buf) free (buf); 
		return NULL;
	}

	// added twenty for a little buffer so we can disassemble the initial addr correctly
	if (r_io_read_at (core->io, addr-(len+extra_padding), buf, len+extra_padding) != len+extra_padding) {
		r_list_destroy (hits);
		free (buf);
		return NULL;
	}
	
	if (len == 0){
		return hits;
	}

	current_buf_pos = len - 1;
	
	do {
		
		if (r_cons_singleton ()->breaked) break;

		// reset assembler
		r_asm_set_pc (core->assembler, current_instr_addr);
		current_instr_len = len - current_buf_pos + extra_padding ;		
		IFDBG eprintf("current_buf_pos: 0x%llx, current_instr_len: %d\n", current_buf_pos, current_instr_len);
		current_instr_len = r_asm_disassemble (core->assembler, &op, buf+current_buf_pos, current_instr_len);
		hit = r_core_asm_hit_new ();
		hit->addr = current_instr_addr;
		hit->len = current_instr_len;
		hit->code = NULL;
		r_list_add_sorted (hits, hit, ((RListComparator)rcoreasm_address_comparator));
		
		current_buf_pos--;
		current_instr_addr--;
		hit_count++;

	} while ( ((int) current_buf_pos  >= 0) && (int)(len - current_buf_pos) >= 0 && hit_count <= max_hit_count);

	if (buf) free(buf);
	return hits;

}




static RList *r_core_asm_back_disassemble (RCore *core, ut64 addr, int len, ut64 max_hit_count, ut8 disassmble_each_addr, ut32 extra_padding) {
	RList *hits;;
	RCoreAsmHit *hit = NULL, *found_addr = NULL;
	RAsmOp op;
	ut8 *buf = NULL;
	ut8 added_invalid = R_FALSE,
		max_invalid_b4_exit = 4,
		last_num_invalid = 0;


	ut64 current_instr_addr = addr,
		current_instr_len = 0,
		current_buf_pos = 0,
		next_buf_pos = len,
		end_addr = addr-1 - len;

	RCoreAsmHit dummy_value;

	ut32 hit_count = 0; 


	if (disassmble_each_addr){
		return r_core_asm_back_disassemble_all(core, addr, len, max_hit_count, extra_padding+1);
	}

	hits = r_core_asm_hit_list_new ();
	buf = malloc (len + extra_padding);

	if (hits == NULL || buf == NULL ){
		if (hits) r_list_destroy (hits);
		if (buf) free (buf); 
		return NULL;
	}
	
	// added twenty for a little buffer so we can disassemble the initial addr correctly
	if (r_io_read_at (core->io, (addr + extra_padding)-len, buf, len+extra_padding) != len+extra_padding) {
		r_list_destroy (hits);
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
	current_instr_addr = addr-1;
	do {
		
		if (r_cons_singleton ()->breaked) break;
		
		// reset assembler
		r_asm_set_pc (core->assembler, current_instr_addr);
		current_instr_len = next_buf_pos - current_buf_pos;
		current_instr_len = r_asm_disassemble (core->assembler, &op, buf+current_buf_pos, current_instr_len);
		found_addr = find_addr(hits, current_instr_addr);
		
		IFDBG {
			ut32 byte_cnt =  current_instr_len ? current_instr_len : 1;
			eprintf("current_instr_addr: 0x%llx, current_buf_pos: 0x%llx, current_instr_len: %d \n", current_instr_addr, current_buf_pos, current_instr_len);
			
			ut8 *hex_str = r_hex_bin2strdup(buf+current_buf_pos, byte_cnt);
			eprintf("==== current_instr_bytes: %s ",hex_str);
			
			if (current_instr_len > 0) 
				eprintf("op.buf_asm: %s\n", op.buf_asm);
			else
				eprintf("op.buf_asm: <invalid>\n");

			if (hex_str) free(hex_str);
		}
		
		// disassembly invalid
		if (current_instr_len == 0 || strstr (op.buf_asm, "invalid")) {
			if (current_instr_len == 0) current_instr_len = 1;

			add_hit_to_hits(hits, current_instr_addr, current_instr_len, /* is_valid */ R_FALSE);
			hit_count ++;
			last_num_invalid ++;
		// disassembly perfect
		} else if (current_buf_pos + current_instr_len == next_buf_pos) {
			ut32 purge_results = 0;
			// Disasm perfect

			// i think this may be the only case where an invalid instruction will be
			// added because handle_forward_disassemble and handle_disassembly_overlap
			// are only called in cases where a valid instruction has been found.
			// and they are lazy, since they purge the hit list 
			ut8 is_valid = R_TRUE;
			IFDBG eprintf(" handling underlap case: current_instr_addr: 0x%llx.\n", current_instr_addr);
			purge_results =  prune_hits_in_addr_range(hits, current_instr_addr, current_instr_len, /* is_valid */ R_TRUE);
			if (purge_results) {
				handle_forward_disassemble(core, hits, buf, len, current_buf_pos+current_instr_len, current_instr_addr+current_instr_len, addr);
				hit_count = r_list_length(hits);
			}
			add_hit_to_hits(hits, current_instr_addr, current_instr_len, is_valid);
			
			//handle_forward_disassemble(core, hits, buf, len, current_buf_pos+current_instr_len, current_instr_addr+current_instr_len, addr/*end_addr*/);
			hit_count ++;	
			next_buf_pos = current_buf_pos;  
			last_num_invalid = 0;
		// disassembly underlap
		} else if (current_buf_pos + current_instr_len < next_buf_pos) {
			ut32 purge_results = 0;

			ut8 is_valid = R_TRUE;
			purge_results =  prune_hits_in_addr_range(hits, current_instr_addr, current_instr_len, /* is_valid */ R_TRUE);
			add_hit_to_hits(hits, current_instr_addr, current_instr_len, is_valid);

			if (hit_count < purge_results ) hit_count = 0; // WTF??
			else hit_count -= purge_results;

			next_buf_pos = current_buf_pos;
			handle_forward_disassemble(core, hits, buf, len - extra_padding, current_buf_pos+current_instr_len, current_instr_addr+current_instr_len, addr);
			hit_count = r_list_length(hits);
			last_num_invalid = 0;
		// disassembly overlap
		} else if (current_buf_pos + current_instr_len > next_buf_pos) {
			ut64 value = handle_disassembly_overlap(core, hits, buf, len, current_buf_pos, current_instr_addr);
			next_buf_pos = current_buf_pos;
			hit_count = r_list_length(hits);
			last_num_invalid = 0;
		}

		// walk backwards by one instruction
		IFDBG eprintf(" current_instr_addr: %d current_instr_len: %d next_instr_addr: 0x%04llx \n", current_instr_addr, current_instr_len, next_buf_pos );
		IFDBG eprintf(" hit count: %d \n", hit_count );
		current_instr_addr -= 1;
		current_buf_pos -= 1;

		if ( hit_count >= max_hit_count && 
			 (last_num_invalid >= max_invalid_b4_exit || last_num_invalid == 0))  
			break;

	} while ( ((int) current_buf_pos  >= 0) && (len - current_buf_pos) >= 0 );


	r_asm_set_pc (core->assembler, addr);
	if (buf) free (buf);
	return hits;
}

R_API RList *r_core_asm_back_disassemble_instr (RCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding){
	// extra padding to allow for additional disassembly on border buffer cases
	ut8 disassmble_each_addr  = R_FALSE;
	return r_core_asm_back_disassemble(core, addr, len, hit_count, disassmble_each_addr, extra_padding);
}

R_API RList *r_core_asm_back_disassemble_byte (RCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding){
	ut8 disassmble_each_addr  = R_TRUE;
	// extra padding to allow for additional disassembly on border buffer cases
	return r_core_asm_back_disassemble(core, addr, len, hit_count, disassmble_each_addr, extra_padding);
}
