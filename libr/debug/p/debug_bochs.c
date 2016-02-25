/* radare - LGPL - Copyright 2009-2016 - pancake, defragger */

#include <r_asm.h>
#include <r_debug.h>
#include <libbochs.h>
static bool bCaptura = TRUE;
static char * saveRegs;
typedef struct {
	//libgdbr_t desc;
	libbochs_t desc; 
} RIOBochs;

//static libgdbr_t *desc = NULL;
static libbochs_t *desc = NULL;

static int r_debug_bochs_breakpoint (RBreakpointItem *bp, int set, void *user) {
	char cmd[50];
	if (!bp) return false;
	if (set) {
		sprintf(cmd,"lb 0x%x",(DWORD)bp->addr);
		EnviaComando_(desc,cmd);
		eprintf("[set]bochs_breakpoint %016"PFMT64x" %s \n",bp->addr,cmd);
		bCaptura = TRUE;
	}
	else
	{
		eprintf("[unset]bochs_breakpoint %016"PFMT64x" %s \n",bp->addr,cmd);
	}
	return true;
}

static int r_debug_bochs_step(RDebug *dbg) {
	EnviaComando_(desc,"s");
	bCaptura = TRUE;
	return true;
}

static int r_debug_bochs_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	char strReg[19];
	char regname[4];
	int i = 0,pos = 0, lenRec = 0, posRIP = 0;;
	ut64 val=0, valRIP = 0;
	if (bCaptura==TRUE) {
		EnviaComando_(desc,"regs");
		//r14: 00000000_00000000 r15: 00000000_00000000
		//rip: 00000000_0000e07b
		//eflags 0x00000046: id vip vif ac vm rf nt IOPL=0 of df if tf sf ZF af PF cf
		//<bochs:109>return -1;
		pos=0x78;
		lenRec = strlen(desc->data);
		while (desc->data[i] != 0 && i < lenRec -4 ) {

			if ( (desc->data[i] == (BYTE)'r' && desc->data[i + 3] == (BYTE)':')) {
				strncpy(regname, &desc->data[i], 3);
				regname[3] = 0;
				strncpy(&strReg[2], &desc->data[i + 5], 8);
				strncpy(&strReg[10], &desc->data[i + 14], 8);
				strReg[0]='0';
				strReg[1]='x';
				strReg[18] = 0;
				i += 22;
				val = r_num_get(NULL,strReg);
				// eprintf("parseado %s = %s valx64 = %016"PFMT64x"\n", regname, strReg,val);
				memcpy(&buf[pos],&val,8);
				// guardamos la posicion del rip y su valor para ajustarlo al obtener el CS
				if (!strncmp(regname,"rip",3))
				{
					posRIP = pos;
					valRIP = val;
				}
				pos+=8;

			}
			else
				i++;
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
		EnviaComando_(desc,"sreg");
		i=0;
		pos=0x38;
		lenRec = strlen(desc->data);
		ut16 val1=0;
		while (desc->data[i] != 0 && i < lenRec -7 ) {

			if ( (desc->data[i+1] == (BYTE)'s' && desc->data[i + 2] == (BYTE)':')) {
				strncpy(regname, &desc->data[i], 2);
				regname[2] = 0;
				strncpy(&strReg[0], &desc->data[i + 3], 5);
				strReg[6] = 0;
				i += 119;
				val = r_num_get(NULL,strReg);
				val1=(ut16)val;
				//eprintf("parseado %s = %s valx64 = %016"PFMT64x"\n", regname, strReg,val);
				memcpy(&buf[pos],&val1,2);
				pos+=2;
				// ajustamos el RIP para que refleje el segmento
				if (!strncmp(regname,"cs",2)) {
					valRIP+=(val*0x10);
					//eprintf("%016"PFMT64x"\n",valRIP);
					memcpy(&buf[posRIP],&valRIP,8);	
				}

			}
			else
				i++;
		}
		//eprintf("guardando regs procesados%x\n",size);
		memcpy(saveRegs,buf,size);
		bCaptura = FALSE;
	} else {
		memcpy(buf,saveRegs,size);
	}
	return size;		
}

static int r_debug_bochs_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	return -1;
}
void map_free(RDebugMap *map) {
	free (map->name);
	free (map);
}


static RList *r_debug_bochs_map_get(RDebug* dbg) { //TODO
	eprintf("bochs debug map\n");
	RDebugMap *mr;
	RList *list = r_list_new();
	if (!list) 
		return NULL;	
	list->free=(RListFree)map_free;
	
	mr = R_NEW0 (RDebugMap);
	mr->name = strdup ("fake");
	mr->addr = 0;
	mr->addr_end = 0xffffffff;
	mr->size = 0xffffffff;
	mr->perm = 0;
	mr->user = 0;
	if (mr != NULL) r_list_append (list, mr);
	return list;
}

static int r_debug_bochs_continue(RDebug *dbg, int pid, int tid, int sig) {
	eprintf("bochs continue\n");
	EnviaComando_(desc,"c");
	bCaptura=TRUE;
	return true;
}

static int r_debug_bochs_wait(RDebug *dbg, int pid) {
	return true;
}

static int r_debug_bochs_attach(RDebug *dbg, int pid) {
	eprintf("r_debug_bochs_attach: invocado\n");
	RIODesc *d = dbg->iob.io->desc;
	dbg->swstep = false;
	if (d && d->plugin && d->plugin->name && d->data) {
		if (!strcmp ("bochs", d->plugin->name)) {
			RIOBochs *g = d->data;
			int arch = r_sys_arch_id (dbg->arch);
			int bits = dbg->anal->bits;
			if (( desc = &g->desc )) {
				eprintf("bochs attach: ok");
				saveRegs = malloc(1024);
			}
		}
	}
	return true;
}

static int r_debug_bochs_detach(RDebug *dbg, int pid) {
	free(saveRegs);
	return true;
}

static const char *r_debug_bochs_reg_profile(RDebug *dbg) {
	int bits = dbg->anal->bits;
	
	if (bits == 16 || bits == 32 || bits == 64) {
		return strdup(
				"=PC	rip\n"
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


struct r_debug_plugin_t r_debug_plugin_bochs = {
	.name = "bochs",
	/* TODO: Add support for more architectures here */
	.license = "LGPL3",
	.arch = "x86",
	.bits = R_SYS_BITS_16 | R_SYS_BITS_32 | R_SYS_BITS_64,
	.step = r_debug_bochs_step,
	.cont = r_debug_bochs_continue,
	.attach = &r_debug_bochs_attach,
	.detach = &r_debug_bochs_detach,
	.canstep = 1,
	.wait = &r_debug_bochs_wait,
	.map_get = r_debug_bochs_map_get,
	.breakpoint = &r_debug_bochs_breakpoint,
	.reg_read = &r_debug_bochs_reg_read,
	.reg_write = &r_debug_bochs_reg_write,
	.reg_profile = (void *)r_debug_bochs_reg_profile,
	//.bp_write = &r_debug_gdb_bp_write,
	//.bp_read = &r_debug_gdb_bp_read,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_bochs,
	.version = R2_VERSION
};
#endif
