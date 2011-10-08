/*
 * Copyright (C) 2008-2011 -- pancake <@nopcode.org>
 * 
 * NOTE: This file has been ported from r1
 *
 * radare is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * radare is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with radare; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "bfvm.h"

static ut8 bfvm_op(BfvmCPU *c) {
	ut8 buf[4] = {0};
	if (c)
	if (!c->iob.read_at (c->iob.io, c->eip, buf, 4))
		return 0xff;
	return buf[0];
}

int bfvm_in_trap(BfvmCPU *c) {
	switch (bfvm_op (c)) {
	case 0x00:
	case 0xff:
		return 1;
	}
	return 0;
}

int bfvm_init(BfvmCPU *c, ut32 size, int circular) {
	memset (c, '\0', sizeof (BfvmCPU));

	/* data */
	c->mem = (ut8 *)malloc (size);
	if (c->mem == NULL)
		return 0;
	c->base = BFVM_DATA_ADDR;
	memset (c->mem, '\0', size);

	/* setup */
	c->circular = circular;
	c->eip = 0; // look forward nops
	c->size = size;

	// TODO: use RBuffer or so here.. this is spagueti
	/* screen */
	c->screen = BFVM_SCREEN_ADDR;
	c->screen_size = BFVM_SCREEN_SIZE;
	c->screen_buf = (ut8*)malloc (c->screen_size);
	memset (c->screen_buf, '\0', c->screen_size);

	/* input */
	c->input = BFVM_INPUT_ADDR;
	c->input_size = BFVM_INPUT_SIZE;
	c->input_buf = (ut8*)malloc (c->input_size);
	memset (c->input_buf, '\0', c->input_size);
	c->esp = c->base;
	return 1;
}

R_API BfvmCPU *bfvm_new(RIOBind *iob) {
	BfvmCPU *c = R_NEW0 (BfvmCPU);
	bfvm_init (c, 4096, 0);
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
	if (at >= c->base)
		at-=c->base;

	if (at<0) {
		if (c->circular)
			at = c->size-2;
		else at=0;
	} else
	if (at >= c->size) {
		if (c->circular)
			at = 0;
		else at = c->size-1;
	}
	if (at<0) return c->mem;
	return c->mem+at;
}

R_API ut8 *bfvm_get_ptr(BfvmCPU *c) {
	//return bfvm_cpu.mem;
	return bfvm_get_ptr_at (c, c->ptr);
}

R_API ut8 bfvm_get(BfvmCPU *c) {
	ut8 *ptr = bfvm_get_ptr (c);
	if (ptr != NULL)
		return ptr[0];
	return 0;
}

R_API void bfvm_inc(BfvmCPU *c) {
	ut8 *mem = bfvm_get_ptr (c);
	if (mem != NULL)
		*mem++;
}

R_API void bfvm_dec(BfvmCPU *c) {
	ut8 *mem = bfvm_get_ptr (c);
	if (mem != NULL)
		*mem--;
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

void bfvm_poke(BfvmCPU *c) {
	int idx = c->screen_idx;
	c->screen_buf[idx] = bfvm_get (c);
	c->screen_idx = idx+1;
}

int bfvm_trace_op(BfvmCPU *c, ut8 op) {
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
	ut8 *buf, op2, op = bfvm_op (c);

	do {
		T bfvm_trace_op (c, op);
		switch (op) {
		case '\0':
			/* trap */
			return 1;
		case '.':
			buf = bfvm_get_ptr (c);
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
					c->eip--;
					/* control underflow */
					if (c->eip<0) {
						c->eip = 0;
						break;
					}
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
	RCons *ci = r_cons_singleton ();
	r_cons_break (NULL, 0);
	while (!ci->breaked) {
		bfvm_step (c, 0);
		if (bfvm_in_trap (c)) {
			eprintf("Trap instruction at 0x%08llx\n", c->eip);
			break;
		}
		switch (bfvm_op (c)) {
		case ',':
			eprintf("contsc: read from input trap\n");
			ci->breaked = 1;
			continue;
		case '.':
			eprintf ("contsc: print to screen trap\n");
			ci->breaked = 1;
			continue;
		}
	}
	r_cons_break_end ();
	return 0;
}

R_API int bfvm_cont(BfvmCPU *c, ut64 until) {
	RCons *ci = r_cons_singleton ();
	r_cons_break (NULL, 0);
	while (!ci->breaked && c->eip != until) {
		bfvm_step (c, 0);
		if (bfvm_in_trap (c)) {
			eprintf ("Trap instruction at 0x%08llx\n", c->eip);
			break;
		}
	}
	r_cons_break_end ();
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
		eprintf ("f eip @ 0x%08llx\n", (ut64)c->eip);
		eprintf ("f esp @ 0x%08llx\n", (ut64)c->esp);
		eprintf ("f ptr @ 0x%08llx\n", (ut64)c->ptr+c->base);
		eprintf ("fs *\n");
	} else {
		ut8 ch = bfvm_get (c);
		eprintf ("  eip  0x%08llx     esp  0x%08llx\n",
			(ut64)c->eip, (ut64)c->esp);
		eprintf ("  ptr  0x%08x     [ptr]  %d = 0x%02x '%c'\n",
			(ut32)c->ptr, ch, ch, IS_PRINTABLE (ch)? ch:' ');
	}
}

R_API void bfvm_maps(BfvmCPU *c, int rad) {
	if (rad) {
		eprintf ("fs sections\n");
		eprintf ("e cmd.vprompt=px@screen\n");
		eprintf ("f section_code @ 0x%08llx\n", (ut64)BFVM_CODE_ADDR);
		eprintf ("f section_code_end @ 0x%08llx\n", (ut64)BFVM_CODE_ADDR+BFVM_CODE_SIZE);
		eprintf ("f section_data @ 0x%08llx\n", (ut64)c->base);
		eprintf ("f section_data_end @ 0x%08llx\n", (ut64)c->base+c->size);
		eprintf ("f screen @ 0x%08llx\n", (ut64)c->screen);
		eprintf ("f section_screen @ 0x%08llx\n", (ut64)c->screen);
		eprintf ("f section_screen_end @ 0x%08llx\n", (ut64)c->screen+c->screen_size);
		eprintf ("f input @ 0x%08llx\n", (ut64)c->input);
		eprintf ("f section_input @ 0x%08llx\n", (ut64)c->input);
		eprintf ("f section_input_end @ 0x%08llx\n", (ut64)c->input+c->input_size);
		eprintf ("fs *\n");
	} else {
		eprintf ("0x%08llx - 0x%08llx rwxu 0x%08llx .code\n",
			(ut64)0, (ut64)c->size, (ut64)c->size);
		eprintf ("0x%08llx - 0x%08llx rw-- 0x%08llx .data\n",
			(ut64)c->base, (ut64)(c->base+c->size), (ut64)c->size);
		eprintf ("0x%08llx - 0x%08llx rw-- 0x%08llx .screen\n",
			(ut64)c->screen, (ut64)(c->screen+c->screen_size), (ut64)c->screen_size);
		eprintf ("0x%08llx - 0x%08llx rw-- 0x%08llx .input\n",
			(ut64)c->input, (ut64)(c->input+c->input_size), (ut64)c->input_size);
	}
}

#if 0
/* PLUGIN CODE */

ut64 cur_seek = 0;

int bfdbg_fd = -1;

int bfdbg_handle_fd(int fd)
{
	return fd == bfdbg_fd;
}

int bfdbg_handle_open(const char *file)
{
	if (!memcmp(file, "bfdbg://", 8))
		return 1;
	return 0;
}

ssize_t bfdbg_write(int fd, const void *buf, size_t count)
{
	if (cur_seek>=bfvm_cpu.screen && cur_seek<=bfvm_cpu.screen+bfvm_cpu.screen_size) {
		memcpy(bfvm_cpu.screen_buf+cur_seek-bfvm_cpu.screen, buf, count);
		return count;
	}
	if (cur_seek>=bfvm_cpu.input && cur_seek<=bfvm_cpu.input+bfvm_cpu.input_size) {
		memcpy(bfvm_cpu.input_buf+cur_seek-bfvm_cpu.input, buf, count);
		return count;
	}
	if (cur_seek>=bfvm_cpu.base) {
		memcpy(bfvm_cpu.mem+cur_seek-bfvm_cpu.base, buf, count);
		return count;
	}
	// TODO: call real read/write here?!?
        return write(fd, buf, count);
}

ssize_t bfdbg_read(int fd, void *buf, size_t count)
{
	if (cur_seek>=bfvm_cpu.screen && cur_seek<=bfvm_cpu.screen+bfvm_cpu.screen_size) {
		memcpy(buf, bfvm_cpu.screen_buf, count);
		return count;
	}
	if (cur_seek>=bfvm_cpu.input && cur_seek<=bfvm_cpu.input+bfvm_cpu.input_size) {
		memcpy(buf, bfvm_cpu.input_buf, count);
		return count;
	}
	if (cur_seek>=bfvm_cpu.base) {
		memcpy(buf, bfvm_cpu.mem, count);
		return count;
	}

        return read(fd, buf, count);
}

int bfdbg_open(const char *pathname, int flags, mode_t mode)
{
	int fd = -1;
	if (bfdbg_handle_open(pathname)) {
		fd = open(pathname+8, flags, mode);
		if (fd != -1) {
			bfvm_init(0xFFFF, 1);
			bfdbg_fd = fd;
		}
	}
	return fd;
}

int bfdbg_system(const char *cmd)
{
	if (!memcmp(cmd, "info",4)) {
		bfvm_step(0);
	} else
	if (!memcmp(cmd, "help",4)) {
		eprintf("Brainfuck debugger help:\n");
		eprintf("20!step       ; perform 20 steps\n");
		eprintf("!step         ; perform a step\n");
		eprintf("!stepo        ; step over rep instructions\n");
		eprintf("!maps         ; show registers\n");
		eprintf("!reg          ; show registers\n");
		eprintf("!cont [addr]  ; continue until address or ^C\n");
		eprintf("!trace [addr] ; trace code execution\n");
		eprintf("!contsc       ; continue until write or read syscall\n");
		eprintf("!reg eip 3    ; force program counter\n");
		eprintf(".!reg*        ; adquire register information into core\n");
	} else
	if (!memcmp(cmd, "contsc",6)) {
		bfvm_contsc();
	} else
	if (!memcmp(cmd, "cont",4)) {
		bfvm_cont(get_math(cmd+4));
	} else
	if (!memcmp(cmd, "trace",5)) {
		bfvm_trace(get_math(cmd+5));
	} else
	if (!memcmp(cmd, "stepo",5)) {
		bfvm_step(1);
	} else
	if (!memcmp(cmd, "maps",4)) {
		bfvm_maps(cmd[4]=='*');
	} else
	if (!memcmp(cmd, "step",4)) {
		bfvm_step(0);
	} else
	if (!memcmp(cmd, "reg",3)) {
		if (strchr(cmd+4,' ')) {
			bfvm_reg_set(cmd+4);
		} else {
			switch (cmd[3]) {
			case 's':
				switch(cmd[4]) {
				case '*':
					bfvm_show_regs(1);
					break;
				default:
					bfvm_show_regs(0);
					break;
				}
				break;
			case '*':
				bfvm_show_regs(1);
				break;
			default:
			//case ' ':
			//case '\0':
				bfvm_show_regs(0);
				break;
			}
		}
	} else eprintf("Invalid debugger command. Try !help\n");
	return 0;
}

int bfdbg_close(int fd)
{
	if (fd == bfdbg_fd)
		bfvm_destroy(&bfvm_cpu);
	return close(fd);
}

ut64 bfdbg_lseek(int fildes, ut64 offset, int whence)
{
	switch(whence) {
	case SEEK_SET:
		cur_seek = offset;
		break;
	case SEEK_CUR:
		cur_seek = config.seek+offset;
		break;
#if 1
	case SEEK_END:
		//if (cur_seek>bfvm_cpu.base)
		cur_seek = 0xffffffff;
		return cur_seek;
#endif
	}
#if __WINDOWS__ 
	return _lseek(fildes,(long)offset,whence);
#else
#if __linux__
	return lseek64(fildes,(off_t)offset,whence);
#else
	return lseek(fildes,(off_t)offset,whence);
#endif
#endif
}

int bfdbg_plugin_init() {
	return bfvm_init(0xFFFF, 1);
}

#if  0
struct debug_t bfdbgt =  {
  /* TODO */
};
#endif

plugin_t bfdbg_plugin = {
	.name        = "bfdbg",
	.desc        = "brainfuck debugger",
	.init        = bfdbg_plugin_init,
	.debug       = NULL, //&bfdbgt,
	.system      = bfdbg_system,
	.widget      = NULL,
	.handle_fd   = bfdbg_handle_fd,
	.handle_open = bfdbg_handle_open,
	.open        = bfdbg_open,
	.read        = bfdbg_read,
	.write       = bfdbg_write,
	.lseek       = bfdbg_lseek,
	.close       = bfdbg_close
};
#endif
