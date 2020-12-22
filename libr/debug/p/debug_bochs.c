/* debugbochs  - LGPL - Copyright 2016 - SkUaTeR */

#include <r_asm.h>
#include <r_debug.h>
#include <libbochs.h>

static bool bCapturaRegs = true;
static bool bStep = false;
static bool bBreak = false;
static bool bAjusta = true;
static char *saveRegs;
static ut64 ripStop = 0LL;

typedef struct {
	libbochs_t desc;
} RIOBochs;

static libbochs_t *desc = NULL;

static bool isBochs(RDebug *dbg) {
	RIODesc *d = dbg->iob.io->desc;
	if (d && d->plugin && d->plugin->name) {
		if (!strcmp ("bochs", d->plugin->name)) {
			return true;
		}
	}
	eprintf ("error: the iodesc data is not bochs friendly\n");
	return false;
}

static int r_debug_bochs_breakpoint (RBreakpoint *bp, RBreakpointItem *b, bool set) {
	char cmd[64];
	char num[4];
	char addr[19];
	char bufcmd[100];
	ut64 a;
	int  n,i,lenRec;
	//eprintf ("bochs_breakpoint\n");
	if (!b) {
		return false;
	}
	if (set) {
		//eprintf("[set] bochs_breakpoint %016"PFMT64x"\n",bp->addr);
		sprintf (cmd, "lb 0x%x", (ut32)b->addr);
		bochs_send_cmd (desc, cmd, true);
		bCapturaRegs = true;
	} else {
		//eprintf("[unset] bochs_breakpoint %016"PFMT64x"\n",bp->addr);
		/*
		Num Type           Disp Enb Address
		  1 lbreakpoint    keep y   0x0000000000007c00
		  2 lbreakpoint    keep y   0x0000000000007c00
		<bochs:39>
		*/
		bochs_send_cmd (desc,"blist",true);
		lenRec = strlen (desc->data);
		a = -1;
		n = 0;
		if (!strncmp (desc->data, "Num Type", 8)) {
			i = 37;
			do {
				if (desc->data[i + 24] == 'y') {
					strncpy(num, &desc->data[i], 3);
					num[3] = 0;
					strncpy(addr, &desc->data[i + 28], 18);
					addr[18] = 0;
					n = r_num_get (NULL,num);
					a = r_num_get (NULL,addr);
					//eprintf("parseado %x %016"PFMT64x"\n",n,a);
					if (a == b->addr) {
						break;
					}
				}
				i += 48;
			} while (desc->data[i] != '<' && i<lenRec-4);
		}
		if (a == b->addr) {
			snprintf (bufcmd, sizeof (bufcmd), "d %i", n);
			//eprintf("[unset] Break point localizado indice = %x (%x) %s \n",n,(DWORD)a,bufcmd);
			bochs_send_cmd (desc, bufcmd, true);
		}

	}
	return true;
}

static int r_debug_bochs_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	char strReg[19];
	char regname[4];
	char strBase[19];
	char strLimit[19];
	int i = 0, pos = 0, lenRec = 0;
	ut64 val = 0, valRIP = 0; //, posRIP = 0;
	if (!isBochs (dbg)) {
		return 0;
	}

	//eprintf ("bochs_reg_read\n");
	if (bCapturaRegs == true) {
		bochs_send_cmd (desc, "regs", true);
		//r14: 00000000_00000000 r15: 00000000_00000000
		//rip: 00000000_0000e07b
		//eflags 0x00000046: id vip vif ac vm rf nt IOPL=0 of df if tf sf ZF af PF cf
		//<bochs:109>return -1;
		pos = 0x78;
		lenRec = strlen (desc->data);
		while (desc->data[i] != 0 && i < lenRec -4 ) {
			if ( (desc->data[i] == (ut8)'r' && desc->data[i + 3] == (ut8)':')) {
				strncpy (regname, &desc->data[i], 3);
				regname[3] = 0;
				strncpy (&strReg[2], &desc->data[i + 5], 8);
				strncpy (&strReg[10], &desc->data[i + 14], 8);
				strReg[0]='0';
				strReg[1]='x';
				strReg[18] = 0;
				i += 22;
				val = r_num_get (NULL, strReg);
				// eprintf("parseado %s = %s valx64 = %016"PFMT64x"\n", regname, strReg,val);
				memcpy (&buf[pos], &val, 8);
				// guardamos la posicion del rip y su valor para ajustarlo al obtener el CS
				if (!strncmp (regname, "rip", 3)) {
				// UNUSED	posRIP = pos;
					valRIP = val;
				}
				pos+= 8;

			} else {
				i++;
			}
		}

		bochs_send_cmd (desc, "info cpu", true);
		if (strstr (desc->data,"PC_32")) {
			bAjusta = true;
			//eprintf("[modo PC_32]\n");
		} else if (strstr (desc->data,"PC_80")) {
			bAjusta = false;
			//eprintf("[modo PC_80]\n");
		} else if (strstr (desc->data,"PC_64")) {
			bAjusta = false;
			//eprintf("[modo PC_64]\n");
		} else {
			eprintf ("[unknown mode]\n%s\n", desc->data);
		}
		/*
		   es:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
		   Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
		   cs:0xf000, dh=0xff0093ff, dl=0x0000ffff, valid=7
		   Data segment, base=0xffff0000, limit=0x0000ffff, Read/Write, Accessed
		   ss:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
		   Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
		   ds:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
		   Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
		   fs:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
		   Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
		   gs:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
		   Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
		   ldtr:0x0000, dh=0x00008200, dl=0x0000ffff, valid=1
		   tr:0x0000, dh=0x00008b00, dl=0x0000ffff, valid=1
		   gdtr:base=0x0000000000000000, limit=0xffff
		   idtr:base=0x0000000000000000, limit=0xffff
		*/
		bochs_send_cmd (desc, "sreg", true);

		pos = 0x38;
		char * s [] = { "es:0x", "cs:0x","ss:0x","ds:0x","fs:0x","gs:0x",0};
		const char *x;
		int n;
		for (n = 0; s[n] != 0; n++) {
			if ((x = strstr (desc->data,s[n]))) {
				strncpy (&strReg[0], x+3, 7);
				strReg[6] = 0;
				val = r_num_get (NULL, strReg);
				strncpy (regname, s[n], 2);
				regname[2] = 0;
				if ((x = strstr (x, "base="))) {
					strncpy (strBase, x + 5, 10);
					strBase[10] = 0;
					if ((x = strstr (x, "limit="))) {
						strncpy (strLimit, x + 6, 10);
						strLimit[10] = 0;
					}
				}
				//eprintf("%s localizado %s %04x base = %s limit = %s\n",regname,strReg,(WORD)val,strBase,strLimit);
				memcpy (&buf[pos], &val, 2);
				pos += 2;
				if (bAjusta) {
					if (!strncmp (regname,"cs",2)) {
						valRIP += (val*0x10); // desplazamos CS y lo añadimos a RIP
					//eprintf("%016"PFMT64x"\n",valRIP);
					}
				}
			}
		}
		// Cheat para evitar traducciones de direcciones
		if (ripStop != 0) {
			memcpy (&buf[0], &ripStop, 8);
		} else {
			memcpy (&buf[0], &valRIP, 8);	// guardamos el valor cs:ip en el registro virtual "vip"
		}
		//eprintf("guardando regs procesados%x\n",size);
		memcpy (saveRegs,buf,size);
		bCapturaRegs = false;
		//eprintf("bochs_reg_read\n");
	} else {
		memcpy (buf, saveRegs, size);
		//eprintf("[cache] bochs_reg_read\n");
	}
	return size;
}

static int r_debug_bochs_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	//eprintf("bochs_reg_write\n");
	return -1;
}

void map_free(RDebugMap *map) {
	free (map->name);
	free (map);
}

static RList *r_debug_bochs_map_get(RDebug* dbg) { //TODO
	if (!isBochs (dbg)) {
		return NULL;
	}
	//eprintf("bochs_map_getdebug:\n");
	RDebugMap *mr;
	RList *list = r_list_newf ((RListFree)map_free);
	if (!list) {
		return NULL;
	}
	mr = R_NEW0 (RDebugMap);
	if (!mr) {
		r_list_free (list);
		return NULL;
	}
	mr->name = strdup ("fake");
	mr->addr = 0;
	mr->addr_end = UT32_MAX;
	mr->size = UT32_MAX;
	mr->perm = 0;
	mr->user = 0;
	r_list_append (list, mr);
	return list;
}

static int r_debug_bochs_step(RDebug *dbg) {
	if (!isBochs (dbg)) {
		return false;
	}
	//eprintf ("bochs_step\n");
	bochs_send_cmd (desc,"s",true);
	bCapturaRegs = true;
	bStep = true;
	return true;
}

static int r_debug_bochs_continue(RDebug *dbg, int pid, int tid, int sig) {
	//eprintf ("bochs_continue:\n");
	bochs_send_cmd (desc, "c", false);
	bCapturaRegs = true;
	bBreak = false;
	return true;
}

static void bochs_debug_break(void *u) {
	eprintf("bochs_debug_break: Sending break...\n");
	bochs_cmd_stop (desc);
	bBreak = true;
}

static int r_debug_bochs_wait(RDebug *dbg, int pid) {
	if (!isBochs (dbg)) {
		return false;
	}
	char strIP[19];
	int i = 0;
	const char *x;
	char *ini = 0, *fin = 0;

	//eprintf ("bochs_wait:\n");

	if (bStep) {
		bStep = false;
	} else {
		r_cons_break_push (bochs_debug_break, dbg);
		i = 500;
		do {
			bochs_wait (desc);
			if (bBreak) {
				if (desc->data[0]) {
					eprintf ("ctrl+c %s\n", desc->data);
					bBreak = false;
					break;
				}
				i--;
				if (!i) {
					bBreak = false;
					eprintf ("empty ctrl+c.\n");
					break;
				}
			} else if (desc->data[0]) {
				//eprintf("stop on breakpoint%s\n",desc->data);
				break;
			}
		} while(1);
		r_cons_break_pop ();
	}
	//eprintf ("bochs_wait: loop done\n");
	// Next at t=394241428
	// (0) [0x000000337635] 0020:0000000000337635 (unk. ctxt): add eax, esi              ; 03c6
	ripStop = 0;
	if ((x = strstr (desc->data, "Next at"))) {
		if ((ini = strstr (x, "[0x"))) {
			if ((fin = strchr (ini, ']'))) {
				int len = fin - ini - 1;
				strncpy (strIP, ini+1, len);
				strIP[len] = 0;
				//eprintf(" parada EIP = %s\n",strIP);
				ripStop = r_num_get (NULL, strIP);
			}
		}
	}
	desc->data[0] = 0;

	return true;
}

static int r_debug_bochs_stop(RDebug *dbg) {
	//eprintf("bochs_stop:\n");
	//RIOBdescbg *o = dbg->iob.io->desc->data;
	//BfvmCPU *c = o->bfvm;
	//c->breaked = true;
	return true;
}

static int r_debug_bochs_attach(RDebug *dbg, int pid) {
	RIODesc *d = dbg->iob.io->desc;
	//eprintf ("bochs_attach:\n");
	dbg->swstep = false;
	if (d && d->plugin && d->plugin->name && d->data) {
		if (!strcmp ("bochs", d->plugin->name)) {
			RIOBochs *g = d->data;
			//int arch = r_sys_arch_id (dbg->arch);
			// int bits = dbg->anal->bits;
			if (( desc = &g->desc )) {
				eprintf("bochs attach: ok\n");
				saveRegs = malloc(1024);
				bCapturaRegs = true;
				bStep = false;
				bBreak = false;
			}
		}
	}
	return true;
}

static int r_debug_bochs_detach(RDebug *dbg, int pid) {
	//eprintf ("bochs_detach:\n");
	free (saveRegs);
	return true;
}

static const char *r_debug_bochs_reg_profile(RDebug *dbg) {
	int bits = dbg->anal->bits;

	if (bits == 16 || bits == 32 || bits == 64) {
		return strdup (
				"=PC	csip\n"
				"=SP	rsp\n"
				"=BP	rbp\n"
				"=A0	rax\n"
				"=A1	rbx\n"
				"=A2	rcx\n"
				"=A3	rdi\n"

				"seg	es	2	0x038	0	\n"
				"seg	cs	2	0x03A	0	\n"
				"seg	ss	2	0x03C	0	\n"
				"seg	ds	2	0x03E	0	\n"
				"seg	fs	2	0x040	0	\n"
				"seg	gs	2	0x042	0	\n"

				"gpr	rax	8	0x078	0	\n"
				"gpr	eax	4	0x078	0	\n"
				"gpr	ax	2	0x078	0	\n"
				"gpr	al	1	0x078	0	\n"
				"gpr	rcx	8	0x080	0	\n"
				"gpr	ecx	4	0x080	0	\n"
				"gpr	cx	2	0x080	0	\n"
				"gpr	cl	1	0x078	0	\n"
				"gpr	rdx	8	0x088	0	\n"
				"gpr	edx	4	0x088	0	\n"
				"gpr	dx	2	0x088	0	\n"
				"gpr	dl	1	0x088	0	\n"
				"gpr	rbx	8	0x090	0	\n"
				"gpr	ebx	4	0x090	0	\n"
				"gpr	bx	2	0x090	0	\n"
				"gpr	bl	1	0x090	0	\n"
				"gpr	rsp	8	0x098	0	\n"
				"gpr	esp	4	0x098	0	\n"
				"gpr	sp	2	0x098	0	\n"
				"gpr	spl	1	0x098	0	\n"
				"gpr	rbp	8	0x0A0	0	\n"
				"gpr	ebp	4	0x0A0	0	\n"
				"gpr	bp	2	0x0A0	0	\n"
				"gpr	bpl	1	0x0A0	0	\n"
				"gpr	rsi	8	0x0A8	0	\n"
				"gpr	esi	4	0x0A8	0	\n"
				"gpr	si	2	0x0A8	0	\n"
				"gpr	sil	1	0x0A8	0	\n"
				"gpr	rdi	8	0x0B0	0	\n"
				"gpr	edi	4	0x0B0	0	\n"
				"gpr	di	2	0x0B0	0	\n"
				"gpr	dil	1	0x0B0	0	\n"
				"gpr	r8	8	0x0B8	0	\n"
				"gpr	r8d	4	0x0B8	0	\n"
				"gpr	r8w	2	0x0B8	0	\n"
				"gpr	r8b	1	0x0B8	0	\n"
				"gpr	r9	8	0x0C0	0	\n"
				"gpr	r9d	4	0x0C0	0	\n"
				"gpr	r9w	2	0x0C0	0	\n"
				"gpr	r9b	1	0x0C0	0	\n"
				"gpr	r10	8	0x0C8	0	\n"
				"gpr	r10d	4	0x0C8	0	\n"
				"gpr	r10w	2	0x0C8	0	\n"
				"gpr	r10b	1	0x0C8	0	\n"
				"gpr	r11	8	0x0D0	0	\n"
				"gpr	r11d	4	0x0D0	0	\n"
				"gpr	r11w	2	0x0D0	0	\n"
				"gpr	r11b	1	0x0D0	0	\n"
				"gpr	r12	8	0x0D8	0	\n"
				"gpr	r12d	4	0x0D8	0	\n"
				"gpr	r12w	2	0x0D8	0	\n"
				"gpr	r12b	1	0x0D8	0	\n"
				"gpr	r13	8	0x0E0	0	\n"
				"gpr	r13d	4	0x0E0	0	\n"
				"gpr	r13w	2	0x0E0	0	\n"
				"gpr	r13b	1	0x0E0	0	\n"
				"gpr	r14	8	0x0E8	0	\n"
				"gpr	r14d	4	0x0E8	0	\n"
				"gpr	r14w	2	0x0E8	0	\n"
				"gpr	r14b	1	0x0E8	0	\n"
				"gpr	r15	8	0x0F0	0	\n"
				"gpr	r15d	4	0x0F0	0	\n"
				"gpr	r15w	2	0x0F0	0	\n"
				"gpr	r15b	1	0x0F0	0	\n"
				"gpr	rip	8	0x0F8	0	\n"
				"gpr	eip	4	0x0F8	0	\n"
				"gpr	csip	8	0x000	0	\n"
				/*
				"gpr	mxcsr	4	0x034	0	\n"
				"seg	cs	2	0x038	0	\n"
				"seg	ds	2	0x03A	0	\n"
				"seg	es	2	0x03C	0	\n"
				"seg	fs	2	0x03E	0	\n"
				"seg	gs	2	0x040	0	\n"
				"seg	ss	2	0x042	0	\n"
				"gpr	eflags	4	0x044	0	\n"
				"drx	dr0	8	0x048	0	\n"
				"drx	dr1	8	0x050	0	\n"
				"drx	dr2	8	0x058	0	\n"
				"drx	dr3	8	0x060	0	\n"
				"drx	dr6	8	0x068	0	\n"
				"drx	dr7	8	0x070	0	\n"
				"gpr	rax	8	0x078	0	\n"
				"gpr	eax	4	0x078	0	\n"
				"gpr	ax	2	0x078	0	\n"
				"gpr	al	1	0x078	0	\n"
				"gpr	rcx	8	0x080	0	\n"
				"gpr	ecx	4	0x080	0	\n"
				"gpr	cx	2	0x080	0	\n"
				"gpr	cl	1	0x078	0	\n"
				"gpr	rdx	8	0x088	0	\n"
				"gpr	edx	4	0x088	0	\n"
				"gpr	dx	2	0x088	0	\n"
				"gpr	dl	1	0x088	0	\n"
				"gpr	rbx	8	0x090	0	\n"
				"gpr	ebx	4	0x090	0	\n"
				"gpr	bx	2	0x090	0	\n"
				"gpr	bl	1	0x090	0	\n"
				"gpr	rsp	8	0x098	0	\n"
				"gpr	esp	4	0x098	0	\n"
				"gpr	sp	2	0x098	0	\n"
				"gpr	spl	1	0x098	0	\n"
				"gpr	rbp	8	0x0A0	0	\n"
				"gpr	ebp	4	0x0A0	0	\n"
				"gpr	bp	2	0x0A0	0	\n"
				"gpr	bpl	1	0x0A0	0	\n"
				"gpr	rsi	8	0x0A8	0	\n"
				"gpr	esi	4	0x0A8	0	\n"
				"gpr	si	2	0x0A8	0	\n"
				"gpr	sil	1	0x0A8	0	\n"
				"gpr	rdi	8	0x0B0	0	\n"
				"gpr	edi	4	0x0B0	0	\n"
				"gpr	di	2	0x0B0	0	\n"
				"gpr	dil	1	0x0B0	0	\n"
				"gpr	r8	8	0x0B8	0	\n"
				"gpr	r8d	4	0x0B8	0	\n"
				"gpr	r8w	2	0x0B8	0	\n"
				"gpr	r8b	1	0x0B8	0	\n"
				"gpr	r9	8	0x0C0	0	\n"
				"gpr	r9d	4	0x0C0	0	\n"
				"gpr	r9w	2	0x0C0	0	\n"
				"gpr	r9b	1	0x0C0	0	\n"
				"gpr	r10	8	0x0C8	0	\n"
				"gpr	r10d	4	0x0C8	0	\n"
				"gpr	r10w	2	0x0C8	0	\n"
				"gpr	r10b	1	0x0C8	0	\n"
				"gpr	r11	8	0x0D0	0	\n"
				"gpr	r11d	4	0x0D0	0	\n"
				"gpr	r11w	2	0x0D0	0	\n"
				"gpr	r11b	1	0x0D0	0	\n"
				"gpr	r12	8	0x0D8	0	\n"
				"gpr	r12d	4	0x0D8	0	\n"
				"gpr	r12w	2	0x0D8	0	\n"
				"gpr	r12b	1	0x0D8	0	\n"
				"gpr	r13	8	0x0E0	0	\n"
				"gpr	r13d	4	0x0E0	0	\n"
				"gpr	r13w	2	0x0E0	0	\n"
				"gpr	r13b	1	0x0E0	0	\n"
				"gpr	r14	8	0x0E8	0	\n"
				"gpr	r14d	4	0x0E8	0	\n"
				"gpr	r14w	2	0x0E8	0	\n"
				"gpr	r14b	1	0x0E8	0	\n"
				"gpr	r15	8	0x0F0	0	\n"
				"gpr	r15d	4	0x0F0	0	\n"
				"gpr	r15w	2	0x0F0	0	\n"
				"gpr	r15b	1	0x0F0	0	\n"
				"gpr	rip	8	0x0F8	0	\n"
				"gpr	cf	.1	.544	0	carry\n"
				"gpr	pf	.1	.546	0	parity\n"
				"gpr	af	.1	.548	0	adjust\n"
				"gpr	zf	.1	.550	0	zero\n"
				"gpr	sf	.1	.551	0	sign\n"
				"gpr	tf	.1	.552	0	trap\n"
				"gpr	if	.1	.553	0	interrupt\n"
				"gpr	df	.1	.554	0	direction\n"
				"gpr	of	.1	.555	0	overflow\n"
				*/
				);
	}
	return NULL;
}

RDebugPlugin r_debug_plugin_bochs = {
	.name = "bochs",
	.license = "LGPL3",
	.arch = "x86",
	.bits = R_SYS_BITS_16 | R_SYS_BITS_32 | R_SYS_BITS_64,
	.step = r_debug_bochs_step,
	.cont = r_debug_bochs_continue,
	.attach = &r_debug_bochs_attach,
	.detach = &r_debug_bochs_detach,
	.canstep = 1,
	.stop = &r_debug_bochs_stop,
	.wait = &r_debug_bochs_wait,
	.map_get = r_debug_bochs_map_get,
	.breakpoint = r_debug_bochs_breakpoint,
	.reg_read = &r_debug_bochs_reg_read,
	.reg_write = &r_debug_bochs_reg_write,
	.reg_profile = (void *)r_debug_bochs_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_bochs,
	.version = R2_VERSION
};
#endif
