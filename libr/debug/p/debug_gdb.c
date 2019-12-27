/* radare - LGPL - Copyright 2009-2018 - pancake, defragger */

#include <r_core.h>
#include <r_asm.h>
#include <r_debug.h>
#include <libgdbr.h>
#include <gdbclient/commands.h>

typedef struct {
	libgdbr_t desc;
} RIOGdb;

#define UNKNOWN (-1)
#define UNSUPPORTED 0
#define SUPPORTED 1

static RIOGdb ** origriogdb = NULL;
static libgdbr_t *desc = NULL;
static ut8* reg_buf = NULL;
static int buf_size = 0;
static int support_sw_bp = UNKNOWN;
static int support_hw_bp = UNKNOWN;

static int r_debug_gdb_attach(RDebug *dbg, int pid);
static void check_connection (RDebug *dbg) {
	if (!desc) {
		r_debug_gdb_attach (dbg, -1);
	}
}

static int r_debug_gdb_step(RDebug *dbg) {
	check_connection (dbg);
	if (!desc) {
		return R_DEBUG_REASON_UNKNOWN;
	}
	gdbr_step (desc, dbg->tid);
	return true;
}

static RList* r_debug_gdb_threads(RDebug *dbg, int pid) {
	RList *list;
	if ((list = gdbr_threads_list (desc, pid))) {
		list->free = (RListFree) &r_debug_pid_free;
	}
	return list;
}

static RList* r_debug_gdb_pids(RDebug *dbg, int pid) {
	RList *list;
	if ((list = gdbr_pids_list (desc, pid))) {
		list->free = (RListFree) &r_debug_pid_free;
	}
	return list;
}

static int r_debug_gdb_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	int copy_size;
	int buflen = 0;
	check_connection (dbg);
	if (!desc) {
		return R_DEBUG_REASON_UNKNOWN;
	}
	gdbr_read_registers (desc);
	if (!desc || !desc->data) {
		return -1;
	}
	// read the len of the current area
	free (r_reg_get_bytes (dbg->reg, type, &buflen));
	if (size < desc->data_len) {
		eprintf ("r_debug_gdb_reg_read: small buffer %d vs %d\n",
			(int)size, (int)desc->data_len);
		//	return -1;
	}
	copy_size = R_MIN (desc->data_len, size);
	buflen = R_MAX (desc->data_len, buflen);
	if (reg_buf) {
		// if (buf_size < copy_size) { //desc->data_len) {
		if (buflen > buf_size) { //copy_size) {
			ut8* new_buf = realloc (reg_buf, buflen);
			if (!new_buf) {
				return -1;
			}
			reg_buf = new_buf;
			buf_size = buflen;
		}
	} else {
		reg_buf = calloc (buflen, 1);
		if (!reg_buf) {
			return -1;
		}
		buf_size = buflen;
	}
	memset ((void*)(volatile void*)buf, 0, size);
	memcpy ((void*)(volatile void*)buf, desc->data, R_MIN (copy_size, size));
	memset ((void*)(volatile void*)reg_buf, 0, buflen);
	memcpy ((void*)(volatile void*)reg_buf, desc->data, copy_size);
#if 0
	int i;
	//for(i=0;i<168;i++) {
	for(i=0;i<copy_size;i++) {
		if (!(i%16)) printf ("\n0x%08x  ", i);
		printf ("%02x ", buf[i]); //(ut8)desc->data[i]);
	}
	printf("\n");
#endif
	return desc->data_len;
}

static RList *r_debug_gdb_map_get(RDebug* dbg) { //TODO
	check_connection (dbg);
	if (!desc || desc->pid <= 0) {
		return NULL;
	}
	RList *retlist = NULL;
	if (desc->get_baddr) {
		desc->get_baddr = false;
		ut64 baddr;
		if ((baddr = gdbr_get_baddr (desc)) != UINT64_MAX) {
			if (!(retlist = r_list_new ())) {
				return NULL;
			}
			RDebugMap *map;
			if (!(map = r_debug_map_new ("", baddr, baddr, R_PERM_RX, 0))) {
				r_list_free (retlist);
				return NULL;
			}
			r_list_append (retlist, map);
			return retlist;
		}
	}

	// Get file from GDB
	char path[128];
	ut8 *buf;
	int ret;
	// TODO don't hardcode buffer size, get from remote target
	// (I think gdb doesn't do that, it just keeps reading till EOF)
	// fstat info can get file size, but it doesn't work for /proc/pid/maps
	ut64 buflen = 16384;
	// If /proc/%d/maps is not valid for gdbserver, we return NULL, as of now
	snprintf (path, sizeof (path) - 1, "/proc/%d/maps", desc->pid);

#ifdef _MSC_VER
#define GDB_FILE_OPEN_MODE (_S_IREAD | _S_IWRITE)
#else
#define GDB_FILE_OPEN_MODE (S_IRUSR | S_IWUSR | S_IXUSR)
#endif

	if (gdbr_open_file (desc, path, O_RDONLY, GDB_FILE_OPEN_MODE) < 0) {
		return NULL;
	}
	if (!(buf = malloc (buflen))) {
		gdbr_close_file (desc);
		return NULL;
	}
	if ((ret = gdbr_read_file (desc, buf, buflen - 1)) <= 0) {
		gdbr_close_file (desc);
		free (buf);
		return NULL;
	}
	buf[ret] = '\0';

	// Get map list
	int unk = 0, perm, i;
	char *ptr, *pos_1;
	size_t line_len;
	char name[1024], region1[100], region2[100], perms[5];
	RDebugMap *map = NULL;
	region1[0] = region2[0] = '0';
	region1[1] = region2[1] = 'x';
	if (!(ptr = strtok ((char*) buf, "\n"))) {
		gdbr_close_file (desc);
		free (buf);
		return NULL;
	}
	if (!(retlist = r_list_new ())) {
		gdbr_close_file (desc);
		free (buf);
		return NULL;
	}
	while (ptr) {
		ut64 map_start, map_end, offset;
		bool map_is_shared = false;
		line_len = strlen (ptr);
		// maps files should not have empty lines
		if (line_len == 0) {
			break;
		}
		// We assume Linux target, for now, so -
		// 7ffff7dda000-7ffff7dfd000 r-xp 00000000 08:05 265428 /usr/lib/ld-2.25.so
		ret = sscanf (ptr, "%s %s %"PFMT64x" %*s %*s %[^\n]", &region1[2],
			      perms, &offset, name);
		if (ret == 3) {
			name[0] = '\0';
		} else if (ret != 4) {
			eprintf ("%s: Unable to parse \"%s\"\nContent:\n%s\n",
				 __func__, path, buf);
			gdbr_close_file (desc);
			free (buf);
			r_list_free (retlist);
			return NULL;
		}
		if (!(pos_1 = strchr (&region1[2], '-'))) {
			ptr = strtok (NULL, "\n");
			continue;
		}
		strncpy (&region2[2], pos_1 + 1, sizeof (region2) - 2 - 1);
		if (!*name) {
			snprintf (name, sizeof (name), "unk%d", unk++);
		}
		perm = 0;
		for (i = 0; perms[i] && i < 5; i++) {
			switch (perms[i]) {
			case 'r': perm |= R_PERM_R; break;
			case 'w': perm |= R_PERM_W; break;
			case 'x': perm |= R_PERM_X; break;
			case 'p': map_is_shared = false; break;
			case 's': map_is_shared = true; break;
			}
		}
		map_start = r_num_get (NULL, region1);
		map_end = r_num_get (NULL, region2);
		if (map_start == map_end || map_end == 0) {
			eprintf ("%s: ignoring invalid map size: %s - %s\n",
				 __func__, region1, region2);
			ptr = strtok (NULL, "\n");
			continue;
		}
		if (!(map = r_debug_map_new (name, map_start, map_end, perm, 0))) {
			break;
		}
		map->offset = offset;
		map->shared = map_is_shared;
		map->file = strdup (name);
		r_list_append (retlist, map);
		ptr = strtok (NULL, "\n");
	}
	gdbr_close_file (desc);
	free (buf);
	return retlist;
}

static RList* r_debug_gdb_modules_get(RDebug *dbg) {
	char *lastname = NULL;
	RDebugMap *map;
	RListIter *iter, *iter2;
	RList *list, *last;
	bool must_delete;
	if (!(list = r_debug_gdb_map_get (dbg))) {
		return NULL;
	}
	if (!(last = r_list_newf ((RListFree)r_debug_map_free))) {
		r_list_free (list);
		return NULL;
	}
	r_list_foreach_safe (list, iter, iter2, map) {
		const char *file = map->file;
		if (!map->file) {
			file = map->file = strdup (map->name);
		}
		must_delete = true;
		if (file && *file == '/') {
			if (!lastname || strcmp (lastname, file)) {
				must_delete = false;
			}
		}
		if (must_delete) {
			r_list_delete (list, iter);
		} else {
			r_list_append (last, map);
			free (lastname);
			lastname = strdup (file);
		}
	}
	list->free = NULL;
	free (lastname);
	r_list_free (list);
	return last;
}

static int r_debug_gdb_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	check_connection (dbg);
	if (!desc) {
		return R_DEBUG_REASON_UNKNOWN;
	}
	if (!reg_buf) {
		// we cannot write registers before we once read them
		return -1;
	}
	int buflen = 0;
	int bits = dbg->anal->bits;
	const char *pcname = r_reg_get_name (dbg->anal->reg, R_REG_NAME_PC);
	RRegItem *reg = r_reg_get (dbg->anal->reg, pcname, 0);
	if (reg) {
		if (dbg->anal->bits != reg->size) {
			bits = reg->size;
		}
	}
	free (r_reg_get_bytes (dbg->reg, type, &buflen));
	// some implementations of the gdb protocol are acting weird.
	// so winedbg is not able to write registers through the <G> packet
	// and also it does not return the whole gdb register profile after
	// calling <g>
	// so this workaround resizes the small register profile buffer
	// to the whole set and fills the rest with 0
	if (buf_size < buflen) {
		ut8* new_buf = realloc (reg_buf, buflen * sizeof (ut8));
		if (!new_buf) {
			return -1;
		}
		reg_buf = new_buf;
		memset (new_buf + buf_size, 0, buflen - buf_size);
	}

	RRegItem* current = NULL;
	// We default to little endian if there's no way to get the configuration,
	// since this was the behaviour prior to the change.
	RRegArena *arena = dbg->reg->regset[type].arena;
	for (;;) {
		current = r_reg_next_diff (dbg->reg, type, reg_buf, buflen, current, bits);
		if (!current) {
			break;
		}
		gdbr_write_reg (desc, current->name, (char*)arena->bytes + (current->offset / 8), current->size / 8);
	}
	return true;
}

static int r_debug_gdb_continue(RDebug *dbg, int pid, int tid, int sig) {
	check_connection (dbg);
	if (!desc) {
		return R_DEBUG_REASON_UNKNOWN;
	}
	gdbr_continue (desc, pid, -1, sig); // Continue all threads
	if (desc->stop_reason.is_valid && desc->stop_reason.thread.present) {
		//if (desc->tid != desc->stop_reason.thread.tid) {
		//	eprintf ("thread id (%d) in reason differs from current thread id (%d)\n", dbg->pid, dbg->tid);
		//}
		desc->tid = desc->stop_reason.thread.tid;
	}
	return desc->tid;
}

static RDebugReasonType r_debug_gdb_wait(RDebug *dbg, int pid) {
	check_connection (dbg);
	if (!desc) {
		return R_DEBUG_REASON_UNKNOWN;
	}
	if (!desc->stop_reason.is_valid) {
		if (gdbr_stop_reason (desc) < 0) {
			dbg->reason.type = R_DEBUG_REASON_UNKNOWN;
			return R_DEBUG_REASON_UNKNOWN;
		}
	}
	if (desc->stop_reason.thread.present) {
		dbg->reason.tid = desc->stop_reason.thread.tid;
		dbg->pid = desc->stop_reason.thread.pid;
		dbg->tid = desc->stop_reason.thread.tid;
		if (dbg->pid != desc->pid || dbg->tid != desc->tid) {
			//eprintf ("= attach %d %d\n", dbg->pid, dbg->tid);
			gdbr_select (desc, dbg->pid, dbg->tid);
		}
	}
	dbg->reason.signum = desc->stop_reason.signum;
	dbg->reason.type = desc->stop_reason.reason;
	return desc->stop_reason.reason;
}

static int r_debug_gdb_attach(RDebug *dbg, int pid) {
	RIODesc *d = dbg->iob.io->desc;
	// TODO: the core must update the dbg.swstep config var when this var is changed
	dbg->swstep = false;
	//eprintf ("XWJSTEP TOFALSE\n");
	if (d && d->plugin && d->plugin->name && d->data) {
		if (!strcmp ("gdb", d->plugin->name)) {
			RIOGdb *g = d->data;
			origriogdb = (RIOGdb **)&d->data;	//TODO bit of a hack, please improve
			support_sw_bp = UNKNOWN;
			support_hw_bp = UNKNOWN;
			int arch = r_sys_arch_id (dbg->arch);
			int bits = dbg->anal->bits;
			desc = &g->desc;
			switch (arch) {
			case R_SYS_ARCH_X86:
				if (bits == 16 || bits == 32) {
					gdbr_set_architecture (desc, "x86", 32);
				} else if (bits == 64) {
					gdbr_set_architecture (desc, "x86", 64);
				} else {
					eprintf ("Not supported register %s %d profile\n", dbg->arch, bits);
					return false;
				}
				break;
			case R_SYS_ARCH_SH:
				// TODO
				break;
			case R_SYS_ARCH_ARM:
				if (bits == 16 || bits == 32) {
					gdbr_set_architecture (desc, "arm", 32);
				} else if (bits == 64) {
					gdbr_set_architecture (desc, "arm", 64);
				} else {
					eprintf ("Not supported register %s %d profile\n", dbg->arch, bits);
					return false;
				}
				break;
			case R_SYS_ARCH_LM32:
				if (bits == 32) {
					gdbr_set_architecture(desc, "lm32", 32);
				} else {
					eprintf ("Not supported register %s %d profile\n", dbg->arch, bits);
					return false;
				}
				break;
			case R_SYS_ARCH_MIPS:
				if (bits == 32 || bits == 64) {
					gdbr_set_architecture (desc, "mips", bits);
				} else {
					eprintf ("Not supported register %s %d profile\n", dbg->arch, bits);
					return false;
				}
				break;
			case R_SYS_ARCH_AVR:
				gdbr_set_architecture (desc, "avr", 16);
				break;
			case R_SYS_ARCH_V850:
				gdbr_set_architecture (desc, "v850", 32);
				break;
			}
		} else {
			eprintf ("ERROR: Underlying IO descriptor is not a GDB one..\n");
		}
	}
	return true;
}

static int r_debug_gdb_detach(RDebug *dbg, int pid) {
	int ret = 0;

	if (pid <= 0 || !desc->stub_features.multiprocess) {
		ret = gdbr_detach (desc);
	}
	ret = gdbr_detach_pid (desc, pid);

	if (dbg->pid == pid) {
		desc = NULL;
	}
	return ret;
}

static const char *r_debug_gdb_reg_profile(RDebug *dbg) {
	int arch = r_sys_arch_id (dbg->arch);
	int bits = dbg->anal->bits;
	check_connection (dbg);
	if (desc && desc->target.valid && desc->target.regprofile) {
		return strdup (desc->target.regprofile);
	}
	switch (arch) {
	case R_SYS_ARCH_X86:
		if (bits == 16 || bits == 32) {
			return strdup (
				"=PC	eip\n"
				"=SP	esp\n"
				"=BP	ebp\n"
				"=A0	eax\n"
				"=A1	ebx\n"
				"=A2	ecx\n"
				"=A3	edx\n"
				"=SN	oeax\n"
				"gpr	eax	.32	0	0\n"
				"gpr	ecx	.32	4	0\n"
				"gpr	edx	.32	8	0\n"
				"gpr	ebx	.32	12	0\n"
				"gpr	esp	.32	16	0\n"
				"gpr	ebp	.32	20	0\n"
				"gpr	esi	.32	24	0\n"
				"gpr	edi	.32	28	0\n"
				"gpr	eip	.32	32	0\n"
				"gpr	eflags	.32	36	0\n"
				"seg	cs	.32	40	0\n"
				"seg	ss	.32	44	0\n"
				"seg	ds	.32	48	0\n"
				"seg	es	.32	52	0\n"
				"seg	fs	.32	56	0\n"
				"seg	gs	.32	60	0\n"
				"fpu	st0	.80	64	0\n"
				"fpu	st1	.80	74	0\n"
				"fpu	st2	.80	84	0\n"
				"fpu	st3	.80	94	0\n"
				"fpu	st4	.80	104	0\n"
				"fpu	st5	.80	114	0\n"
				"fpu	st6	.80	124	0\n"
				"fpu	st7	.80	134	0\n"
				"gpr	fctrl	.32	144	0\n"
				"gpr	fstat	.32	148	0\n"
				"gpr	ftag	.32	152	0\n"
				"gpr	fiseg	.32	156	0\n"
				"gpr	fioff	.32	160	0\n"
				"gpr	foseg	.32	164	0\n"
				"gpr	fooff	.32	168	0\n"
				"gpr	fop	.32	172	0\n"
				"fpu	xmm0	.128	176	0\n"
				"fpu	xmm1	.128	192	0\n"
				"fpu	xmm2	.128	208	0\n"
				"fpu	xmm3	.128	224	0\n"
				"fpu	xmm4	.128	240	0\n"
				"fpu	xmm5	.128	256	0\n"
				"fpu	xmm6	.128	272	0\n"
				"fpu	xmm7	.128	288	0\n"
				"gpr	mxcsr	.32	304	0\n"
				);
		} else if (dbg->anal->bits == 64) {
			return strdup (
				"=PC	rip\n"
				"=SP	rsp\n"
				"=BP	rbp\n"
				"=A0	rax\n"
				"=A1	rbx\n"
				"=A2	rcx\n"
				"=A3	rdx\n"
				"=SN	orax\n"
				"gpr	fake	.64	795	0\n"
				"gpr	rax	.64	0	0\n"
				"gpr	rbx	.64	8	0\n"
				"gpr	rcx	.64	16	0\n"
				"gpr	rdx	.64	24	0\n"
				"gpr	rsi	.64	32	0\n"
				"gpr	rdi	.64	40	0\n"
				"gpr	rbp	.64	48	0\n"
				"gpr	rsp	.64	56	0\n"
				"gpr	r8	.64	64	0\n"
				"gpr	r9	.64	72	0\n"
				"gpr	r10	.64	80	0\n"
				"gpr	r11	.64	88	0\n"
				"gpr	r12	.64	96	0\n"
				"gpr	r13	.64	104	0\n"
				"gpr	r14	.64	112	0\n"
				"gpr	r15	.64	120	0\n"
				"gpr	rip	.64	128	0\n"
				"gpr	eflags	.32	136	0\n"
				"seg	cs	.32	140	0\n"
				"seg	ss	.32	144	0\n"
				"seg	ds	.32	148	0\n"
				"seg	es	.32	152	0\n"
				"seg	fs	.32	156	0\n"
				"seg	gs	.32	160	0\n"
				"fpu	st0	.80	164	0\n"
				"fpu	st1	.80	174	0\n"
				"fpu	st2	.80	184	0\n"
				"fpu	st3	.80	194	0\n"
				"fpu	st4	.80	204	0\n"
				"fpu	st5	.80	214	0\n"
				"fpu	st6	.80	224	0\n"
				"fpu	st7	.80	234	0\n"
				"gpr	fctrl	.32	244	0\n"
				"gpr	fstat	.32	248	0\n"
				"gpr	ftag	.32	252	0\n"
				"gpr	fiseg	.32	256	0\n"
				"gpr	fioff	.32	260	0\n"
				"gpr	foseg	.32	264	0\n"
				"gpr	fooff	.32	268	0\n"
				"gpr	fop	.32	272	0\n"
				"fpu	xmm0	.128	276	0\n"
				"fpu	xmm1	.128	292	0\n"
				"fpu	xmm2	.128	308	0\n"
				"fpu	xmm3	.128	324	0\n"
				"fpu	xmm4	.128	340	0\n"
				"fpu	xmm5	.128	356	0\n"
				"fpu	xmm6	.128	372	0\n"
				"fpu	xmm7	.128	388	0\n"
				"fpu	xmm8	.128	404	0\n"
				"fpu	xmm9	.128	420	0\n"
				"fpu	xmm10	.128	436	0\n"
				"fpu	xmm11	.128	452	0\n"
				"fpu	xmm12	.128	468	0\n"
				"fpu	xmm13	.128	484	0\n"
				"fpu	xmm14	.128	500	0\n"
				"fpu	xmm15	.128	516	0\n"
				"fpu	mxcsr	.32	532	0\n"
			);
		} else {
			return strdup (
			"=PC	eip\n"
			"=SP	esp\n"
			"=BP	ebp\n"
			"=A0	eax\n"
			"=A1	ebx\n"
			"=A2	ecx\n"
			"=A3	edi\n"
			"gpr	eax	.32	0	0\n"
			"gpr	ecx	.32	4	0\n"
			"gpr	edx	.32	8	0\n"
			"gpr	ebx	.32	12	0\n"
			"gpr	esp	.32	16	0\n"
			"gpr	ebp	.32	20	0\n"
			"gpr	esi	.32	24	0\n"
			"gpr	edi	.32	28	0\n"
			"gpr	eip	.32	32	0\n"
			"gpr	eflags	.32	36	0\n"
			"seg	cs	.32	40	0\n"
			"seg	ss	.32	44	0\n"
			"seg	ds	.32	48	0\n"
			"seg	es	.32	52	0\n"
			"seg	fs	.32	56	0\n"
			"seg	gs	.32	60	0\n"
			);
		}
		break;
	case R_SYS_ARCH_ARM:
		if (bits == 64) {
			return strdup (
			"=PC	pc\n"
			"=SP	sp\n"
			"=BP	x29\n"
			"=A0	x0\n"
			"=A1	x1\n"
			"=A2	x2\n"
			"=A3	x3\n"
			"=ZF	zf\n"
			"=SF	nf\n"
			"=OF	vf\n"
			"=CF	cf\n"
			"=SN	x8\n"
			"gpr	x0	.64	0	0\n"
			"gpr	x1	.64	8	0\n"
			"gpr	x2	.64	16	0\n"
			"gpr	x3	.64	24	0\n"
			"gpr	x4	.64	32	0\n"
			"gpr	x5	.64	40	0\n"
			"gpr	x6	.64	48	0\n"
			"gpr	x7	.64	56	0\n"
			"gpr	x8	.64	64	0\n"
			"gpr	x9	.64	72	0\n"
			"gpr	x10	.64	80	0\n"
			"gpr	x11	.64	88	0\n"
			"gpr	x12	.64	96	0\n"
			"gpr	x13	.64	104	0\n"
			"gpr	x14	.64	112	0\n"
			"gpr	x15	.64	120	0\n"
			"gpr	x16	.64	128	0\n"
			"gpr	x17	.64	136	0\n"
			"gpr	x18	.64	144	0\n"
			"gpr	x19	.64	152	0\n"
			"gpr	x20	.64	160	0\n"
			"gpr	x21	.64	168	0\n"
			"gpr	x22	.64	176	0\n"
			"gpr	x23	.64	184	0\n"
			"gpr	x24	.64	192	0\n"
			"gpr	x25	.64	200	0\n"
			"gpr	x26	.64	208	0\n"
			"gpr	x27	.64	216	0\n"
			"gpr	x28	.64	224	0\n"
			"gpr	x29	.64	232	0\n"
			"gpr	x30	.64	240	0\n"
			"gpr	sp	.64	248	0\n"
			"gpr	pc	.64	256	0\n"
			"gpr	pstate	.64	264	0\n"
			);
		} else {
			return strdup (
#if 0
			"=PC	r15\n"
			"=SP	r14\n" // XXX
			"=A0	r0\n"
			"=A1	r1\n"
			"=A2	r2\n"
			"=A3	r3\n"
			"gpr	lr	.32	56	0\n" // r14
			"gpr	pc	.32	60	0\n" // r15
			"gpr	r0	.32	0	0\n"
			"gpr	r1	.32	4	0\n"
			"gpr	r2	.32	8	0\n"
			"gpr	r3	.32	12	0\n"
			"gpr	r4	.32	16	0\n"
			"gpr	r5	.32	20	0\n"
			"gpr	r6	.32	24	0\n"
			"gpr	r7	.32	28	0\n"
			"gpr	r8	.32	32	0\n"
			"gpr	r9	.32	36	0\n"
			"gpr	r10	.32	40	0\n"
			"gpr	r11	.32	44	0\n"
			"gpr	r12	.32	48	0\n"
			"gpr	r13	.32	52	0\n"
			"gpr	r14	.32	56	0\n"
			"gpr	r15	.32	60	0\n"
			"gpr	f0	.96	64	0\n"
			"gpr	f1	.96	76	0\n"
			"gpr	f2	.96	88	0\n"
			"gpr	f3	.96	100	0\n"
			"gpr	f4	.96	112	0\n"
			"gpr	f5	.96	124	0\n"
			"gpr	f6	.96	136	0\n"
			"gpr	f7	.96	148	0\n"
			"gpr	fps	.96	160	0\n"
			"gpr	cpsr	.32	172	0\n"
#else
			"=PC	pc\n"
			"=SP	sp\n"
			"=A0	r0\n"
			"=A1	r1\n"
			"=A2	r2\n"
			"=A3	r3\n"
			"gpr	r0	.32	0	0\n"
			"gpr	r1	.32	4	0\n"
			"gpr	r2	.32	8	0\n"
			"gpr	r3	.32	12	0\n"
			"gpr	r4	.32	16	0\n"
			"gpr	r5	.32	20	0\n"
			"gpr	r6	.32	24	0\n"
			"gpr	r7	.32	28	0\n"
			"gpr	r8	.32	32	0\n"
			"gpr	r9	.32	36	0\n"
			"gpr	r10	.32	40	0\n"
			"gpr	r11	.32	44	0\n"
			"gpr	r12	.32	48	0\n"
			"gpr	sp	.32	52	0\n" // r13
			"gpr	lr	.32	56	0\n" // r14
			"gpr	pc	.32	60	0\n" // r15
			"gpr	r13	.32	52	0\n"
			"gpr	r14	.32	56	0\n"
			"gpr	r15	.32	60	0\n"
			"gpr	cpsr	.96	64	0\n"
			"mmx	d0	.64	68	0\n" // neon
			"mmx	d1	.64	76	0\n" // neon
			"mmx	d2	.64	84	0\n" // neon
			"mmx	d3	.64	92	0\n" // neon
			"mmx	d4	.64	100	0\n" // neon
			"mmx	d5	.64	108	0\n" // neon
			"mmx	d6	.64	116	0\n" // neon
			"mmx	d7	.64	124	0\n" // neon
			"mmx	d8	.64	132	0\n" // neon
			"mmx	d9	.64	140	0\n" // neon
			"mmx	d10	.64	148	0\n" // neon
			"mmx	d11	.64	156	0\n" // neon
			"mmx	d12	.64	164	0\n" // neon
			"mmx	d13	.64	172	0\n" // neon
			"mmx	d14	.64	180	0\n" // neon
			"mmx	d15	.64	188	0\n" // neon
			"mmx	d16	.64	196	0\n" // neon
			"mmx	d17	.64	204	0\n" // neon
			"mmx	d18	.64	212	0\n" // neon
			"mmx	d19	.64	220	0\n" // neon
			"mmx	d20	.64	228	0\n" // neon
			"mmx	d21	.64	236	0\n" // neon
			"mmx	d22	.64	244	0\n" // neon
			"mmx	d23	.64	252	0\n" // neon
			"mmx	d24	.64	260	0\n" // neon
			"mmx	d25	.64	268	0\n" // neon
			"mmx	d26	.64	276	0\n" // neon
			"mmx	d27	.64	284	0\n" // neon
			"mmx	d28	.64	292	0\n" // neon
			"mmx	d29	.64	300	0\n" // neon
			"mmx	d30	.64	308	0\n" // neon
			"mmx	d31	.64	316	0\n" // neon
			"mmx	fpscr	.32	324	0\n" // neon
#endif
			);
		}
		break;
	case R_SYS_ARCH_SH:
		return strdup (
			"=PC    pc\n"
			"=SP    r15\n"
			"=BP    r14\n"
			"gpr	r0	.32	0	0\n"
			"gpr	r1	.32	4	0\n"
			"gpr	r2	.32	8	0\n"
			"gpr	r3	.32	12	0\n"
			"gpr	r4	.32	16	0\n"
			"gpr	r5	.32	20	0\n"
			"gpr	r6	.32	24	0\n"
			"gpr	r7	.32	28	0\n"
			"gpr	r8	.32	32	0\n"
			"gpr	r9	.32	36	0\n"
			"gpr	r10	.32	40	0\n"
			"gpr	r11	.32	44	0\n"
			"gpr	r12	.32	48	0\n"
			"gpr	r13	.32	52	0\n"
			"gpr	r14	.32	56	0\n"
			"gpr	r15	.32	60	0\n"
			"gpr	pc	.32	64	0\n"
			"gpr	pr	.32	68	0\n"
			"gpr	sr	.32	72	0\n"
			"gpr	gbr	.32	76	0\n"
			"gpr	mach	.32	80	0\n"
			"gpr	macl	.32	84	0\n"
		);
		break;
	case R_SYS_ARCH_LM32:
		return strdup (
			"=PC    PC\n"
			"=SP    sp\n"
			"=BP    gp\n"
			"gpr	r0	.32	0	0\n"
			"gpr	r1	.32	4	0\n"
			"gpr	r2	.32	8	0\n"
			"gpr	r3	.32	12	0\n"
			"gpr	r4	.32	16	0\n"
			"gpr	r5	.32	20	0\n"
			"gpr	r6	.32	24	0\n"
			"gpr	r7	.32	28	0\n"
			"gpr	r8	.32	32	0\n"
			"gpr	r9	.32	36	0\n"
			"gpr	r10	.32	40	0\n"
			"gpr	r11	.32	44	0\n"
			"gpr	r12	.32	48	0\n"
			"gpr	r13	.32	52	0\n"
			"gpr	r14	.32	56	0\n"
			"gpr	r15	.32	60	0\n"
			"gpr	r16	.32	64	0\n"
			"gpr	r17	.32	68	0\n"
			"gpr	r18	.32	72	0\n"
			"gpr	r19	.32	76	0\n"
			"gpr	r20	.32	80	0\n"
			"gpr	r21	.32	84	0\n"
			"gpr	r22	.32	88	0\n"
			"gpr	r23	.32	92	0\n"
			"gpr	r24	.32	96	0\n"
			"gpr	r25	.32	100	0\n"
			"gpr	gp	.32	104	0\n"
			"gpr	fp	.32	108	0\n"
			"gpr	sp	.32	112	0\n"
			"gpr	ra	.32	116	0\n"
			"gpr	ea	.32	120	0\n"
			"gpr	ba	.32	124	0\n"
			"gpr	PC	.32	128	0\n"
			"gpr	EID	.32	132	0\n"
			"gpr	EBA	.32	136	0\n"
			"gpr	DEBA	.32	140	0\n"
			"gpr	IE	.32	144	0\n"
			"gpr	IM	.32	148	0\n"
			"gpr	IP	.32	152	0\n"
		);
		break;
	case R_SYS_ARCH_MIPS:
		return strdup (
			"=PC    pc\n"
			"=SP    sp\n"
			"=BP    gp\n"
			"gpr	zero	.32	0	0\n"
			"gpr	at	.32	4	0\n"
			"gpr	v0	.32	8	0\n"
			"gpr	v1	.32	12	0\n"
			"gpr	a0	.32	16	0\n"
			"gpr	a1	.32	20	0\n"
			"gpr	a2	.32	24	0\n"
			"gpr	a3	.32	28	0\n"
			"gpr	t0	.32	32	0\n"
			"gpr	t1	.32	36	0\n"
			"gpr	t2	.32	40	0\n"
			"gpr	t3	.32	44	0\n"
			"gpr	t4	.32	48	0\n"
			"gpr	t5	.32	52	0\n"
			"gpr	t6	.32	56	0\n"
			"gpr	t7	.32	60	0\n"
			"gpr	s0	.32	64	0\n"
			"gpr	s1	.32	68	0\n"
			"gpr	s2	.32	72	0\n"
			"gpr	s3	.32	76	0\n"
			"gpr	s4	.32	80	0\n"
			"gpr	s5	.32	84	0\n"
			"gpr	s6	.32	88	0\n"
			"gpr	s7	.32	92	0\n"
			"gpr	t8	.32	96	0\n"
			"gpr	t9	.32	100	0\n"
			"gpr	k0	.32	104	0\n"
			"gpr	k1	.32	108	0\n"
			"gpr	gp	.32	112	0\n"
			"gpr	sp	.32	116	0\n"
			"gpr	s8	.32	120	0\n"
			"gpr	ra	.32	124	0\n"
			"gpr	sr	.32	128	0\n"
			"gpr	lo	.32	132	0\n"
			"gpr	hi	.32	134	0\n"
			"gpr	bad	.32	140	0\n"
			"gpr	cause	.32	144	0\n"
			"gpr	pc	.32	148	0\n"
			"gpr	f0	.32	152	0\n"
			"gpr	f1	.32	156	0\n"
			"gpr	f2	.32	160	0\n"
			"gpr	f3	.32	164	0\n"
			"gpr	f4	.32	168	0\n"
			"gpr	f5	.32	172	0\n"
			"gpr	f6	.32	176	0\n"
			"gpr	f7	.32	180	0\n"
			"gpr	f8	.32	184	0\n"
			"gpr	f9	.32	188	0\n"
			"gpr	f10	.32	192	0\n"
			"gpr	f11	.32	196	0\n"
			"gpr	f12	.32	200	0\n"
			"gpr	f13	.32	204	0\n"
			"gpr	f14	.32	208	0\n"
			"gpr	f15	.32	212	0\n"
			"gpr	f16	.32	216	0\n"
			"gpr	f17	.32	220	0\n"
			"gpr	f18	.32	224	0\n"
			"gpr	f19	.32	228	0\n"
			"gpr	f20	.32	232	0\n"
			"gpr	f21	.32	236	0\n"
			"gpr	f22	.32	240	0\n"
			"gpr	f23	.32	244	0\n"
			"gpr	f24	.32	248	0\n"
			"gpr	f25	.32	252	0\n"
			"gpr	f26	.32	256	0\n"
			"gpr	f27	.32	260	0\n"
			"gpr	f28	.32	264	0\n"
			"gpr	f29	.32	268	0\n"
			"gpr	f30	.32	272	0\n"
			"gpr	f31	.32	276	0\n"
			"gpr	fsr	.32	280	0\n"
			"gpr	fir	.32	284	0\n"
			"gpr	unknw	.32	288	0\n" //Not documented what this part of the register packet is
		);
	case R_SYS_ARCH_AVR:
		return strdup (
			"=PC    pc\n"
			"=SP    sp\n"
			"gpr	r0	.8	0	0\n"
			"gpr	r1	.8	1	0\n"
			"gpr	r2	.8	2	0\n"
			"gpr	r3	.8	3	0\n"
			"gpr	r4	.8	4	0\n"
			"gpr	r5	.8	5	0\n"
			"gpr	r6	.8	6	0\n"
			"gpr	r7	.8	7	0\n"
			"gpr	r8	.8	8	0\n"
			"gpr	r9	.8	9	0\n"
			"gpr	r10	.8	10	0\n"
			"gpr	r11	.8	11	0\n"
			"gpr	r12	.8	12	0\n"
			"gpr	r13	.8	13	0\n"
			"gpr	r14	.8	14	0\n"
			"gpr	r15	.8	15	0\n"
			"gpr	r16	.8	16	0\n"
			"gpr	r17	.8	17	0\n"
			"gpr	r18	.8	18	0\n"
			"gpr	r19	.8	19	0\n"
			"gpr	r20	.8	20	0\n"
			"gpr	r21	.8	21	0\n"
			"gpr	r22	.8	22	0\n"
			"gpr	r23	.8	23	0\n"
			"gpr	r24	.8	24	0\n"
			"gpr	r25	.8	25	0\n"
			"gpr	r26	.8	26	0\n"
			"gpr	r27	.8	27	0\n"
			"gpr	r28	.8	28	0\n"
			"gpr	r29	.8	29	0\n"
			"gpr	r30	.8	30	0\n"
			"gpr	r31	.8	31	0\n"
			"gpr	sreg	.8	32	0\n"
			"gpr	sp	.16	33	0\n"
			"gpr	pc2	.32	34	0\n"
			"gpr	pc	.32	35	0\n"
	/*		"gpr	pc	.32	39	0\n" */
	);
	case R_SYS_ARCH_V850:
		return strdup (
			"=PC    pc\n"
			"=SP    sp\n"
			"gpr	r0	.32	0	0\n"
			"gpr	r1	.32	4	0\n"
			"gpr	r2	.32	8	0\n"
			"gpr	sp	.32	12	0\n" // r3
			"gpr	gp	.32	16	0\n" // r4
			"gpr	r5	.32	20	0\n"
			"gpr	r6	.32	24	0\n"
			"gpr	r7	.32	28	0\n"
			"gpr	r8	.32	32	0\n"
			"gpr	r9	.32	36	0\n"
			"gpr	r10	.32	40	0\n"
			"gpr	r11	.32	44	0\n"
			"gpr	r12	.32	48	0\n"
			"gpr	r13	.32	52	0\n"
			"gpr	r14	.32	56	0\n"
			"gpr	r15	.32	60	0\n"
			"gpr	r16	.32	64	0\n"
			"gpr	r17	.32	68	0\n"
			"gpr	r18	.32	72	0\n"
			"gpr	r19	.32	76	0\n"
			"gpr	r20	.32	80	0\n"
			"gpr	r21	.32	84	0\n"
			"gpr	r22	.32	88	0\n"
			"gpr	r23	.32	92	0\n"
			"gpr	r24	.32	96	0\n"
			"gpr	r25	.32	100	0\n"
			"gpr	r26	.32	104	0\n"
			"gpr	r27	.32	108	0\n"
			"gpr	r28	.32	112	0\n"
			"gpr	r29	.32	116	0\n"
			"gpr	ep	.32	120	0\n" // r30
			"gpr	lp	.32	124	0\n" // r31
			"gpr	eipc	.32	128	0\n"
			"gpr	eipsw	.32	132	0\n"
			"gpr	fepc	.32	136	0\n"
			"gpr	fepsw	.32	140	0\n"
			"gpr	ecr	.32	144	0\n"
			"gpr	psw	.32	148	0\n"
			// 5x reserved, sccfg, scbp, eiic, feic, dbic, ctpc, ctpsw, dbpc, dbpsw, ctbp
			// debug stuff, eiwr, fewr, dbwr, bsel
			"gpr	pc	.32	256	0\n"
	);
	}
	return NULL;
}

static int r_debug_gdb_breakpoint (RBreakpoint *bp, RBreakpointItem *b, bool set) {
	int ret = 0, bpsize;
	if (!b) {
		return false;
	}
	bpsize = b->size;
        // TODO handle conditions
	switch (b->perm) {
	case R_BP_PROT_EXEC : {
		if (set) {
			ret = b->hw?
					gdbr_set_hwbp (desc, b->addr, "", bpsize):
					gdbr_set_bp (desc, b->addr, "", bpsize);
		} else {
			ret = b->hw ? gdbr_remove_hwbp (desc, b->addr, bpsize) : gdbr_remove_bp (desc, b->addr, bpsize);
		}
		break;
	}
	// TODO handle size (area of watch in upper layer and then bpsize. For the moment watches are set on exact on byte
	case R_PERM_W: {
		if (set) {
			gdbr_set_hww (desc, b->addr, "", 1);
		} else {
			gdbr_remove_hww (desc, b->addr, 1);
		}
		break;
	}
	case R_PERM_R: {
		if (set) {
			gdbr_set_hwr (desc, b->addr, "", 1);
		} else {
			gdbr_remove_hwr (desc, b->addr, 1);
		}
		break;
	}
	case R_PERM_ACCESS: {
		if (set) {
			gdbr_set_hwa (desc, b->addr, "", 1);
		} else {
			gdbr_remove_hwa (desc, b->addr, 1);
		}
		break;
	}
	}
	return !ret;
}

static bool r_debug_gdb_kill(RDebug *dbg, int pid, int tid, int sig) {
	// TODO kill based on pid and signal
	if (sig != 0) {
		if (gdbr_kill (desc) < 0) {
			return false;
		}
	}
	return true;
}

static int r_debug_gdb_select(RDebug *dbg, int pid, int tid) {
	if (!desc || !*origriogdb) {
		desc = NULL;	//TODO hacky fix, please improve. I would suggest using a **desc instead of a *desc, so it is automatically updated
		return false;
	}

	return gdbr_select (desc, pid, tid) >= 0;
}

static RDebugInfo* r_debug_gdb_info(RDebug *dbg, const char *arg) {
	RDebugInfo *rdi;
	if (!(rdi = R_NEW0 (RDebugInfo))) {
		return NULL;
	}
	RList *th_list;
	bool list_alloc = false;
	if (dbg->threads) {
		th_list = dbg->threads;
	} else {
		th_list = r_debug_gdb_threads (dbg, dbg->pid);
		list_alloc = true;
	}
	RDebugPid *th;
	RListIter *it;
	bool found = false;
	r_list_foreach (th_list, it, th) {
		if (th->pid == dbg->pid) {
			found = true;
			break;
		}
	}
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->exe = gdbr_exec_file_read (desc, dbg->pid);
	rdi->status = found ? th->status : R_DBG_PROC_STOP;
	rdi->uid = found ? th->uid : -1;
	rdi->gid = found ? th->gid : -1;
	if (gdbr_stop_reason (desc) >= 0) {
		eprintf ("signal: %d\n", desc->stop_reason.signum);
		rdi->signum = desc->stop_reason.signum;
	}
	if (list_alloc) {
		r_list_free (th_list);
	}
	return rdi;
}

#include "native/bt.c"

static RList* r_debug_gdb_frames(RDebug *dbg, ut64 at) {
	return r_debug_native_frames (dbg, at);
}

RDebugPlugin r_debug_plugin_gdb = {
	.name = "gdb",
	/* TODO: Add support for more architectures here */
	.license = "LGPL3",
	.arch = "x86,arm,sh,mips,avr,lm32,v850,ba2",
	.bits = R_SYS_BITS_16 | R_SYS_BITS_32 | R_SYS_BITS_64,
	.step = r_debug_gdb_step,
	.cont = r_debug_gdb_continue,
	.attach = &r_debug_gdb_attach,
	.detach = &r_debug_gdb_detach,
	.threads = &r_debug_gdb_threads,
	.pids = &r_debug_gdb_pids,
	.canstep = 1,
	.wait = &r_debug_gdb_wait,
	.map_get = r_debug_gdb_map_get,
	.modules_get = r_debug_gdb_modules_get,
	.breakpoint = &r_debug_gdb_breakpoint,
	.reg_read = &r_debug_gdb_reg_read,
	.reg_write = &r_debug_gdb_reg_write,
	.reg_profile = (void *)r_debug_gdb_reg_profile,
	.kill = &r_debug_gdb_kill,
	.info = &r_debug_gdb_info,
	.select = &r_debug_gdb_select,
	.frames = &r_debug_gdb_frames,
	//.bp_write = &r_debug_gdb_bp_write,
	//.bp_read = &r_debug_gdb_bp_read,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_gdb,
	.version = R2_VERSION
};
#endif
