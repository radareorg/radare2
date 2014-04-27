/*
 * Copyright (C) 2008-2011 -- pancake <@nopcode.org>
 * NOTE: This file has been ported from r1 and relicensed to LGPL
 */

#include "bfvm.h"

static ut8 bfvm_op(BfvmCPU *c) {
	// XXX: this is slow :(
	ut8 buf[4] = {0};
	if (c && c->iob.read_at && !c->iob.read_at (c->iob.io, c->eip, buf, 4))
		return 0xff;
	return buf[0];
}

R_API int bfvm_in_trap(BfvmCPU *c) {
	switch (bfvm_op (c)) {
	case 0x00:
	case 0xcc:
	case 0xff:
		return 1;
	}
	return 0;
}

R_API void bfvm_reset(BfvmCPU *c) {
	memset (c->mem, '\0', c->size);
	memset (c->input_buf, '\0', c->input_size);
	memset (c->screen_buf, '\0', c->screen_size);
	c->base = BFVM_DATA_ADDR;
	c->input = BFVM_INPUT_ADDR;
	c->input_idx = 0;
	c->screen = BFVM_SCREEN_ADDR;
	c->screen_idx = 0;
	c->eip = 0; // TODO look forward nops
	c->ptr = 0;
	c->esp = c->base;
}

R_API int bfvm_init(BfvmCPU *c, ut32 size, int circular) {
	memset (c, '\0', sizeof (BfvmCPU));

	/* data */
	c->mem = (ut8 *)malloc (size);
	if (c->mem == NULL)
		return 0;
	memset (c->mem, '\0', size);

	/* setup */
	c->circular = circular;
	c->size = size;

	// TODO: use RBuffer or so here.. this is spagueti
	/* screen */
	c->screen = BFVM_SCREEN_ADDR;
	c->screen_size = BFVM_SCREEN_SIZE;
	c->screen_buf = (ut8*)malloc (c->screen_size);
	memset (c->screen_buf, '\0', c->screen_size);

	/* input */
	c->input_size = BFVM_INPUT_SIZE;
	c->input_buf = (ut8*)malloc (c->input_size);
	bfvm_reset (c);
	return 1;
}

R_API BfvmCPU *bfvm_new(RIOBind *iob) {
	BfvmCPU *c = R_NEW0 (BfvmCPU);
	bfvm_init (c, 4096, 1);
	memcpy (&c->iob, iob, sizeof (c->iob));
	return c;
}

R_API BfvmCPU *bfvm_free(BfvmCPU *c) {
	free (c->mem);
	c->mem = 0;
	free (c->screen_buf);
	c->screen_buf = 0;
	free (c);
	return NULL;
}

R_API ut8 *bfvm_get_ptr_at(BfvmCPU *c, ut64 at) {
	if (at >= c->base) at -= c->base;
	//if (at<0) at = c->circular? c->size-2: 0;
	else if (at >= c->size) at = c->circular? 0: c->size-1;
	//if (at<0) return c->mem;
	return c->mem+at;
}

R_API ut8 *bfvm_get_ptr(BfvmCPU *c) {
	//return bfvm_cpu.mem;
	return bfvm_get_ptr_at (c, c->ptr);
}

R_API ut8 bfvm_get(BfvmCPU *c) {
	ut8 *ptr = bfvm_get_ptr (c);
	return ptr? *ptr: 0;
}

R_API void bfvm_inc(BfvmCPU *c) {
	ut8 *mem = bfvm_get_ptr (c);
	if (mem != NULL)
		mem[0]++;
}

R_API void bfvm_dec(BfvmCPU *c) {
	ut8 *mem = bfvm_get_ptr (c);
	if (mem != NULL)
		mem[0]--;
}

R_API int bfvm_reg_set(BfvmCPU *c, const char *str) {
	char *ptr = strchr (str, ' ');
	if (ptr == NULL)
		return 0;
	if (strstr (str, "eip"))
		c->eip = r_num_math (NULL, ptr+1);
	else if (strstr (str, "esp"))
		c->esp = r_num_math (NULL, ptr+1);
	else if (strstr (str, "ptr"))
		c->ptr = r_num_math (NULL, ptr+1);
	return 1;
}

/* screen and input */
R_API void bfvm_peek(BfvmCPU *c) {
	int idx = c->input_idx;
	ut8 *ptr = bfvm_get_ptr (c);

	if (idx >= c->input_size)
		idx = 0;

	if (ptr) {
		*ptr = c->input_buf[idx];
		c->input_idx = idx+1;
	}
}

R_API void bfvm_poke(BfvmCPU *c) {
	int idx = c->screen_idx;
	c->screen_buf[idx] = bfvm_get (c);
	c->screen_idx = idx+1;
}

R_API int bfvm_trace_op(BfvmCPU *c, ut8 op) {
	ut8 g;
	switch (op) {
	case '\0':
		eprintf (" ; trap (%02x)\n", op);
	case '.':
	case ',':
	case '+':
	case '-':
	case '>':
	case '<':
		eprintf ("%c", op);
		break;
	case '[':
	case ']':
		g = bfvm_get (c);
		eprintf ("%c  ; [ptr] = %d\n", op, g);
		if (g!= 0)
			eprintf ("[");
		break;
	}
	return 0;
}

#define T if (c->trace)
/* debug */
R_API int bfvm_step(BfvmCPU *c, int over) {
	ut8 op2, op = bfvm_op (c);

	do {
		T bfvm_trace_op (c, op);
		switch (op) {
		case '\0':
			/* trap */
			return 1;
		case '.':
			bfvm_get_ptr (c);
			bfvm_poke (c);
			break;
		case ',':
			bfvm_peek (c);
			/* TODO read */
			break;
		case '+':
			bfvm_inc (c);
			break;
		case '-':
			bfvm_dec (c);
			break;
		case '>':
			c->ptr++;
			break;
		case '<':
			c->ptr--;
			break;
		case '[':
			break;
		case ']':
			if (bfvm_get (c) != 0) {
				do {
					/* control underflow */
					if (c->eip < (c->eip-1)) {
						c->eip = 0;
						break;
					}
					c->eip--;
				} while (bfvm_op (c)!='[');
			}
			break;
		default:
			break;
		}
		c->eip++;
		op2 = bfvm_op (c);
	} while (over && op == op2);

	return 0;
}

R_API int bfvm_contsc(BfvmCPU *c) {
	c->breaked = 0;
	while (!c->breaked) {
		bfvm_step (c, 0);
		if (bfvm_in_trap (c)) {
			eprintf ("Trap instruction at 0x%08"PFMT64x"\n", c->eip);
			break;
		}
		switch (bfvm_op (c)) {
		case ',':
			eprintf("contsc: read from input trap\n");
			c->breaked = 1;
			continue;
		case '.':
			eprintf ("contsc: print to screen trap\n");
			c->breaked = 1;
			continue;
		}
	}
	return 0;
}

R_API int bfvm_cont(BfvmCPU *c, ut64 until) {
	c->breaked = 0;
	while (!c->breaked && c->eip != until) {
		bfvm_step (c, 0);
		if (bfvm_in_trap (c)) {
			eprintf ("Trap instruction at 0x%"PFMT64x"\n", c->eip);
			break;
		}
	}
	return 0;
}

R_API int bfvm_trace(BfvmCPU *c, ut64 until) {
	c->trace=1;
	bfvm_cont (c, until);
	c->trace=0;
	return 0;
}

R_API void bfvm_show_regs(BfvmCPU *c, int rad) {
	if (rad) {
		eprintf ("fs regs\n");
		eprintf ("f eip @ 0x%08"PFMT64x"\n", (ut64)c->eip);
		eprintf ("f esp @ 0x%08"PFMT64x"\n", (ut64)c->esp);
		eprintf ("f ptr @ 0x%08"PFMT64x"\n", (ut64)c->ptr+c->base);
		eprintf ("fs *\n");
	} else {
		ut8 ch = bfvm_get (c);
		eprintf ("  eip  0x%08"PFMT64x"     esp  0x%08"PFMT64x"\n",
			(ut64)c->eip, (ut64)c->esp);
		eprintf ("  ptr  0x%08x     [ptr]  %d = 0x%02x '%c'\n",
			(ut32)c->ptr, ch, ch, IS_PRINTABLE (ch)? ch:' ');
	}
}

R_API void bfvm_maps(BfvmCPU *c, int rad) {
	if (rad) {
		eprintf ("fs sections\n");
		eprintf ("e cmd.vprompt=px@screen\n");
		eprintf ("f section_code @ 0x%08"PFMT64x"\n", (ut64)BFVM_CODE_ADDR);
		eprintf ("f section_code_end @ 0x%08"PFMT64x"\n", (ut64)BFVM_CODE_ADDR+BFVM_CODE_SIZE);
		eprintf ("f section_data @ 0x%08"PFMT64x"\n", (ut64)c->base);
		eprintf ("f section_data_end @ 0x%08"PFMT64x"\n", (ut64)c->base+c->size);
		eprintf ("f screen @ 0x%08"PFMT64x"\n", (ut64)c->screen);
		eprintf ("f section_screen @ 0x%08"PFMT64x"\n", (ut64)c->screen);
		eprintf ("f section_screen_end @ 0x%08"PFMT64x"\n", (ut64)c->screen+c->screen_size);
		eprintf ("f input @ 0x%08"PFMT64x"\n", (ut64)c->input);
		eprintf ("f section_input @ 0x%08"PFMT64x"\n", (ut64)c->input);
		eprintf ("f section_input_end @ 0x%08"PFMT64x"\n", (ut64)c->input+c->input_size);
		eprintf ("fs *\n");
	} else {
		eprintf ("0x%08"PFMT64x" - 0x%08"PFMT64x" rwxu 0x%08"PFMT64x" .code\n",
			(ut64)0, (ut64)c->size, (ut64)c->size);
		eprintf ("0x%08"PFMT64x" - 0x%08"PFMT64x" rw-- 0x%08"PFMT64x" .data\n",
			(ut64)c->base, (ut64)(c->base+c->size), (ut64)c->size);
		eprintf ("0x%08"PFMT64x" - 0x%08"PFMT64x" rw-- 0x%08"PFMT64x" .screen\n",
			(ut64)c->screen, (ut64)(c->screen+c->screen_size), (ut64)c->screen_size);
		eprintf ("0x%08"PFMT64x" - 0x%08"PFMT64x" rw-- 0x%08"PFMT64x" .input\n",
			(ut64)c->input, (ut64)(c->input+c->input_size), (ut64)c->input_size);
	}
}
