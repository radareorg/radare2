// Copyright (c) 2014, The Lemon Man, All rights reserved. LGPLv3

// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this library.

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <r_list.h>
#include "transport.h"
#include "wind.h"
#include "kd.h"

enum {
	K_PaeEnabled			= 0x036,
	K_PsActiveProcessHead	= 0x050,
	K_CmNtCSDVersion		= 0x268,
};

enum {
	E_ActiveProcessLinks,	// EPROCESS
	E_UniqueProcessId,		// EPROCESS
	E_Peb,					// EPROCESS
	E_ImageFileName,		// EPROCESS
	E_VadRoot,				// EPROCESS
	P_DirectoryTableBase,	// PCB
	P_ImageBaseAddress,		// PEB
	P_ProcessParameters,	// PEB
	R_ImagePathName,		// RTL_USER_PROCESS_PARAMETERS
	O_Max,
};

#define O_FLAG_XPVAD 1

typedef struct {
	int build;
	int sp;
	int bits;
	int flags;
	int f[O_Max];
} Profile;

#define O_(n) ctx->os_profile->f[n]

#include "profiles.h"

Profile *p_table[] = {
	&XP_SP2_X86,
	&XP_SP3_X86,
	&WIN7_SP0_X86,
	&WIN7_SP1_X86,
	&WIN7_SP0_X64,
	&WIN7_SP1_X64,
	&VISTA_SP0_X86,
	&VISTA_SP0_X64,
	&VISTA_SP1_X86,
	&VISTA_SP1_X64,
	&VISTA_SP2_X86,
	&VISTA_SP2_X64,
	&WIN2003_SP0_X86,
	&WIN2003_SP1_X86,
	&WIN2003_SP1_X64,
	&WIN2003_SP2_X86,
	&WIN2003_SP2_X64,
	NULL,
};

Profile *
wind_get_profile (int bits, int build, int sp) {
	int i;

	for (i = 0; p_table[i]; i++) {
		if (p_table[i]->build == build && p_table[i]->sp == sp && p_table[i]->bits == bits)
			return p_table[i];
	}

	return NULL;
}

// #define WIND_LOG 0

#define LOG_PKT(p) \
{ \
	fprintf(stderr, "Leader\t: %08x\nType\t: %08x\nLenght\t: %08x\nID\t: %08x\nCheck\t: %08x [%s]\n", \
		(p)->leader, \
		(p)->type, \
		(p)->length, \
		(p)->id, \
		(p)->checksum, \
		(kd_data_checksum((p)->data, (p)->length) == (p)->checksum)?"Ok":"Wrong" \
	); \
}
#define LOG_REQ(r) \
{ \
	fprintf(stderr, "Request : %08x\nProcessor : %08x\nReturn : %08x\n", \
		(r)->req, \
		(r)->cpu, \
		(r)->ret \
	); \
}

struct _WindCtx {
	void *io_ptr;
	uint32_t seq_id;
	int syncd;
	int cpu_count;
	int cpu;
	int pae;
	int is_x64;
	Profile *os_profile;
	RList *plist_cache;
	uint64_t dbg_addr;
	WindProc *target;
};

int
wind_get_cpus (WindCtx *ctx) {
	if (!ctx)
		return -1;
	return ctx->cpu_count;
}

int
wind_set_cpu (WindCtx *ctx, int cpu) {
	if (!ctx || cpu > ctx->cpu_count)
		return 0;
	ctx->cpu = cpu;
	return 1;
}

int
wind_get_cpu (WindCtx *ctx) {
	if (!ctx)
		return -1;
	return ctx->cpu;
}

int
wind_set_target (WindCtx *ctx, uint32_t pid) {
	RList *l = wind_list_process(ctx);
	WindProc *p;
	RListIter *it;

	if (pid == 0) {
		ctx->target = NULL;
		return 1;
	}

	r_list_foreach (l, it, p) {
		if (p->uniqueid == pid) {
			ctx->target = p;
			return 1;
		}
	}

	return 0;
}

uint32_t
wind_get_target (WindCtx *ctx) {
	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return 0;

	return ctx->target?
		ctx->target->uniqueid:
		0;
}

uint64_t
wind_get_target_base (WindCtx *ctx) {
	uint64_t ppeb;
	uint64_t base = 0;

	if (!ctx || !ctx->io_ptr || !ctx->syncd || !ctx->target)
		return 0;

	if (!wind_va_to_pa(ctx, ctx->target->peb, &ppeb))
		return 0;

	if (!wind_read_at_phys(ctx, (uint8_t *)&base, ppeb + O_(P_ImageBaseAddress), 4 << ctx->is_x64))
		return 0;

	return base;
}

WindCtx *
wind_ctx_new (void *io_ptr) {
	WindCtx *ctx = calloc(1, sizeof(WindCtx));

	if (!ctx)
		return NULL;

	ctx->io_ptr = io_ptr;

	return ctx;
}

void
wind_ctx_free (WindCtx *ctx) {
	if (!ctx)
		return;
	r_list_free(ctx->plist_cache);
	iob_close(ctx->io_ptr);
	free(ctx);
}

#define PKT_REQ(p) ( (kd_req_t *)((kd_packet_t *)(p)->data) )
#define PKT_STC(p) ( (kd_stc_64 *)((kd_packet_t *)(p)->data) )

static void
dump_stc (kd_packet_t *p) {
	kd_stc_64 *stc = PKT_STC(p);

	fprintf(stderr, "New state : %08x\n", stc->state);
	fprintf(stderr, "eip : %016llx kthread : %016llx\n",
			stc->pc,
			stc->kthread);
	fprintf(stderr, "On cpu %i/%i\n", stc->cpu + 1, stc->cpu_count);

	if (stc->state == 0x3030) {
		fprintf(stderr, "ex\n");
		fprintf(stderr, "\tCode   : %08x\n", stc->exception.code);
		fprintf(stderr, "\tFlags  : %08x\n", stc->exception.flags);
		fprintf(stderr, "\tRecord : %016llx\n", stc->exception.ex_record);
		fprintf(stderr, "\tAddr   : %016llx\n", stc->exception.ex_addr);
	}
}

static int
do_io_reply (WindCtx *ctx, kd_packet_t *pkt)
{
	kd_ioc_t ioc;
	int ret;

	(void)pkt;

	memset(&ioc, 0, sizeof(kd_ioc_t));

	ioc.req = 0x3430;
	ioc.ret = KD_RET_ENOENT;

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_IO, (ctx->seq_id ^= 1), (uint8_t *)&ioc,
			sizeof(kd_ioc_t), NULL, 0);
	if (ret != KD_E_OK)
		return 0;

#ifdef WIND_LOG
	fprintf(stderr, "Waiting for io_reply ack...\n");
#endif
	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return 0;
#ifdef WIND_LOG
	fprintf(stderr, "Ack received, restore flow\n");
#endif

	return 1;
}

int wind_wait_packet (WindCtx *ctx, const uint32_t type, kd_packet_t **p) {
	kd_packet_t *pkt;
	int ret, retries = 10;

	// r_sys_backtrace();

	pkt = NULL;

	do {
		free(pkt);
		// Try to read a whole packet
		ret = kd_read_packet(ctx->io_ptr, &pkt);
		// fprintf(stderr, "kd_read_packet() = %i\n", ret);
		if (ret != KD_E_OK)
			break;

		// fprintf(stderr, "Received %08x, expected %08x\n", pkt->type, type);
		if (pkt->leader == KD_PACKET_DATA && pkt->type == KD_PACKET_TYPE_STATE_CHANGE)
			dump_stc(pkt);
		if (pkt->leader == KD_PACKET_DATA && pkt->type == KD_PACKET_TYPE_IO)
			do_io_reply(ctx, pkt);

		// Check for RESEND
		// The host didn't like our request
		if (pkt->leader == KD_PACKET_CTRL && pkt->type == KD_PACKET_TYPE_RESEND) {
			ret = KD_E_MALFORMED;
			break;
		}
	} while(pkt->type != type && retries--);

	if (ret != KD_E_OK) {
		free(pkt);
		return ret;
	}

	if (p) {
		*p = pkt;
	} else {
		free (pkt);
		*p = 0;
	}

	return KD_E_OK;
}

// http://dfrws.org/2007/proceedings/p62-dolan-gavitt.pdf
typedef struct {
	char tag[4];
	uint32_t start_vpn;
	uint32_t end_vpn;
	uint32_t parent;
	uint32_t left, right;
	uint32_t flags;
} __attribute__((packed)) mmvad_short;

int
wind_walk_vadtree (WindCtx *ctx, uint64_t address, uint64_t parent) {
	mmvad_short entry = {0};
	uint64_t start, end;
	int prot;

	if (wind_read_at(ctx, (uint8_t *)&entry, address - 0x4, sizeof(mmvad_short)) != sizeof (mmvad_short)) {
		fprintf(stderr, "%llx Could not read the node!\n", address);
		return 0;
	}

	if (parent != UT64_MAX && entry.parent != parent) {
		fprintf(stderr, "Wrong parent!\n");
		return 0;
	}

	start = entry.start_vpn << 12;
	end = ((entry.end_vpn + 1) << 12) - 1;
	prot = (entry.flags >> 24)&0x1F;

	eprintf ("Start 0x%016"PFMT64x" End 0x%016"PFMT64x" Prot 0x%08"PFMT64x"\n",
		(uint64_t)start, (uint64_t)end, (uint64_t)prot);

	if (entry.left)
		wind_walk_vadtree(ctx, entry.left, address);
	if (entry.right)
		wind_walk_vadtree(ctx, entry.right, address);

	return 1;
}

RList*
wind_list_process (WindCtx *ctx) {
	RList *ret;
	uint64_t ptr, base;
	int i;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return NULL;

	if (ctx->plist_cache)
		return ctx->plist_cache;

	ptr = 0;
	// Grab the PsActiveProcessHead from _KDDEBUGGER_DATA64
	wind_read_at(ctx, (uint8_t *)&ptr, ctx->dbg_addr + K_PsActiveProcessHead, 4 << ctx->is_x64);

	base = ptr;

#ifdef WIND_LOG
	fprintf(stderr, "Process list head : 0x%016llx\n", ptr);
#endif

	// Walk the LIST_ENTRY
	wind_read_at(ctx, (uint8_t *)&ptr, ptr, 4 << ctx->is_x64);

	ret = r_list_newf(free);

	do {
		uint8_t buf[17];
		uint64_t next;

		next = 0;
		// Read the ActiveProcessLinks entry
		wind_read_at(ctx, (uint8_t *)&next, ptr, 4 << ctx->is_x64);

		// This points to the 'ActiveProcessLinks' list, adjust the ptr so that it point to the
		// EPROCESS base
		ptr -= O_(E_ActiveProcessLinks);

		// Read the short name
		wind_read_at(ctx, (uint8_t *)&buf, ptr + O_(E_ImageFileName), 16);
		buf[16] = '\0';

		uint64_t vadroot = 0;
		uint64_t uniqueid = 0;
		uint64_t peb = 0;
		uint64_t dir_base_table = 0;

		wind_read_at(ctx, (uint8_t *)&vadroot, ptr + O_(E_VadRoot), 4 << ctx->is_x64);
		wind_read_at(ctx, (uint8_t *)&uniqueid, ptr + O_(E_UniqueProcessId), 4 << ctx->is_x64);
		wind_read_at(ctx, (uint8_t *)&peb, ptr + O_(E_Peb), 4 << ctx->is_x64);
		wind_read_at(ctx, (uint8_t *)&dir_base_table, ptr + O_(P_DirectoryTableBase), 4 << ctx->is_x64);

		WindProc *proc = calloc(1, sizeof(WindProc));

		strcpy(proc->name, (const char *)buf);
		proc->vadroot = vadroot;
		proc->uniqueid = uniqueid;
		proc->dir_base_table = dir_base_table;
		proc->peb = peb;

		r_list_append(ret, proc);

		// wind_walk_vadtree(ctx, vadroot, -1);
		ptr = next;
	} while(ptr != base);

	ctx->plist_cache = ret;

	return ret;
}

#define PTE_VALID		0x0001
#define PTE_LARGEPAGE	0x0080
#define PTE_PROTOTYPE	0x0400

// http://blogs.msdn.com/b/ntdebugging/archive/2010/02/05/understanding-pte-part-1-let-s-get-physical.aspx
// http://blogs.msdn.com/b/ntdebugging/archive/2010/04/14/understanding-pte-part2-flags-and-large-pages.aspx
// http://blogs.msdn.com/b/ntdebugging/archive/2010/06/22/part-3-understanding-pte-non-pae-and-x64.aspx
int
wind_va_to_pa (WindCtx *ctx, uint64_t va, uint64_t *pa) {
	uint64_t pml4i, pdpi, pdi, pti;
	uint64_t tmp, mask;

	// We shouldn't really reach this
	if (!ctx->target)
		return 0;

#ifdef WIND_LOG
	fprintf(stderr, "VA   : %016llx\n", va);
#endif

	if (ctx->is_x64) {
		pti   = (va >> 12)&0x1ff;
		pdi   = (va >> 21)&0x1ff;
		pdpi  = (va >> 30)&0x1ff;
		pml4i = (va >> 39)&0x1ff;
		// Grab the PageFrameNumber field off the _HARDWARE_PTE entry
		mask  = 0x000000fffffff000;
	} else {
		if (ctx->pae) {
			pti   = (va >> 12)&0x1ff;
			pdi   = (va >> 21)&0x1ff;
			pdpi  = (va >> 30)&0x3;
			pml4i = 0;
		} else {
			pti   = (va >> 12)&0x3ff;
			pdi   = (va >> 22)&0x3ff;
			pdpi  = 0;
			pml4i = 0;
		}
		// Grab the PageFrameNumber field off the _HARDWARE_PTE entry
		mask  = 0xfffff000;
	}

	tmp = ctx->target->dir_base_table;
	tmp &= ~0x1f;

#ifdef WIND_LOG
	fprintf(stderr ,"cr3  : %016llx\n", tmp);
#endif

	if (ctx->is_x64) {
		// PML4 lookup
		if (!wind_read_at_phys(ctx, (uint8_t *)&tmp, tmp + pml4i * 8, 8))
			return 0;
		tmp &= mask;
#ifdef WIND_LOG
		fprintf(stderr ,"PML4 : %016llx\n", tmp);
#endif
	}

	if (ctx->pae) {
		// PDPT lookup
		if (!wind_read_at_phys(ctx, (uint8_t *)&tmp, tmp + pdpi * 8, 8))
			return 0;
		tmp &= mask;
#ifdef WIND_LOG
		fprintf(stderr ,"PDPE : %016llx\n", tmp);
#endif
	}

	// PDT lookup
	if (!wind_read_at_phys(ctx, (uint8_t *)&tmp, tmp + pdi * (4 << ctx->pae), 4 << ctx->pae))
		return 0;
#ifdef WIND_LOG
	fprintf(stderr ,"PDE  : %016llx\n", tmp);
#endif

	// Large page entry
	// The page size differs between pae and non-pae systems, the former points to 2MB pages while
	// the latter points to 4MB pages
	if (tmp & PTE_LARGEPAGE) {
		*pa = ctx->pae ?
			(tmp&(~0x1fffff)) | (va&0x1fffff):
			(tmp&(~0x3fffff)) | (va&0x3fffff);

		return 1;
	}

	// PT lookup
	if (!wind_read_at_phys(ctx, (uint8_t *)&tmp, (tmp&mask) + pti * (4 << ctx->pae), 4 << ctx->pae))
		return 0;
#ifdef WIND_LOG
	fprintf(stderr ,"PTE  : %016llx\n", tmp);
#endif

	if (tmp & PTE_VALID) {
		*pa = (tmp&mask) | (va&0xfff);
		return 1;
	}

	if (tmp & PTE_PROTOTYPE) {
		// TODO : prototype PTE support
		fprintf(stderr, "Prototype PTE lookup is currently missing!\n");
	}

	return 0;
}

int
wind_read_ver (WindCtx *ctx) {
	kd_req_t req;
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return 0;

	memset(&req, 0, sizeof(kd_req_t));

	req.req = 0x3146;
	req.cpu = ctx->cpu;

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (uint8_t *)&req,
			sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_MANIP, &pkt);
	if (ret != KD_E_OK)
		return 0;

	kd_req_t *rr = PKT_REQ(pkt);

	/* LOG_PKT(pkt); */
	/* LOG_REQ(rr); */

	if (rr->ret) {
#ifdef WIND_LOG
		fprintf(stderr, "%s : req returned %08x\n", __FUNCTION__, rr->ret);
#endif
		free(pkt);
		return 0;
	}

#ifdef WIND_LOG
	fprintf(stderr, "Major : %i Minor %i\n", rr->r_ver.major, rr->r_ver.minor);
	fprintf(stderr, "Protocol version : %i.%i\n", rr->r_ver.proto_major, rr->r_ver.proto_minor);
	fprintf(stderr, "Flags : %08x\n", rr->r_ver.flags);
	fprintf(stderr, "Machine : %08x\n", rr->r_ver.machine);
	fprintf(stderr, "Module list : %016llx\n", rr->r_ver.mod_addr);
	fprintf(stderr, "Debug block : %016llx\n", rr->r_ver.dbg_addr);
#endif

	if (rr->r_ver.machine != KD_MACH_I386 && rr->r_ver.machine != KD_MACH_AMD64) {
		fprintf(stderr, "Unsupported target host\n");
		free(pkt);
		return 0;
	}

	if (!(rr->r_ver.flags&DBGKD_VERS_FLAG_DATA)) {
		fprintf(stderr, "No _KDDEBUGGER_DATA64 pointer has been supplied by the debugee!\n");
		free(pkt);
		return 0;
	}

	ctx->is_x64 = (rr->r_ver.machine == KD_MACH_AMD64);

	uint64_t ptr = 0;
	if (!wind_read_at(ctx, (uint8_t *)&ptr, rr->r_ver.dbg_addr, 4 << ctx->is_x64)) {
		free(pkt);
		return 0;
	}

	ctx->dbg_addr = ptr;

#ifdef WIND_LOG
	fprintf(stderr, "_KDDEBUGGER_DATA64 at 0x%016llx\n", ctx->dbg_addr);
#endif

	// Thanks to this we don't have to find a way to read the cr4
	uint16_t pae_enabled;
	if (!wind_read_at(ctx, (uint8_t *)&pae_enabled, ctx->dbg_addr + K_PaeEnabled, sizeof(uint16_t))) {
		free(pkt);
		return 0;
	}

	// Grab the CmNtCSDVersion field to extract the Service Pack number
	wind_read_at(ctx, (uint8_t *)&ptr, ctx->dbg_addr + K_CmNtCSDVersion, 8);
	wind_read_at(ctx, (uint8_t *)&ptr, ptr, 4 << ctx->is_x64);

	ctx->pae = pae_enabled&1;
	ctx->os_profile = wind_get_profile(32 << ctx->is_x64, rr->r_ver.minor, (ptr >> 8)&0xff);
	if (!ctx->os_profile) {
		fprintf(stderr, "Could not find a suitable profile for the target OS\n");
		free(pkt);
		return 0;
	}

	free(pkt);

	return 1;
}

int
wind_sync (WindCtx *ctx) {
	int ret;
	kd_packet_t *s;

	if (!ctx || !ctx->io_ptr)
		return 0;

	// Send the breakin packet
	if (iob_write (ctx->io_ptr, (const uint8_t*)"b", 1) != 1)
		return 0;

	// Reset the host
	ret = kd_send_ctrl_packet(ctx->io_ptr, KD_PACKET_TYPE_RESET, 0);
	if (ret != KD_E_OK)
		return 0;

	// Wait for the response
	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_RESET, NULL);
	if (ret != KD_E_OK)
		return 0;

	// Syncronize with the first KD_PACKET_TYPE_STATE_CHANGE packet
	wind_wait_packet(ctx, KD_PACKET_TYPE_STATE_CHANGE, &s);

	// Reset the sequence id
	ctx->seq_id = 0x80800001;

	ctx->cpu = PKT_STC(s)->cpu;
	ctx->cpu_count = PKT_STC(s)->cpu_count;
	ctx->target = NULL;
	ctx->plist_cache = NULL;
	ctx->pae = 0;
	// We're ready to go
	ctx->syncd = 1;

	free(s);

	fprintf(stderr, "Sync done! (%i cpus found)\n", ctx->cpu_count);

	return 1;
}

int
wind_continue (WindCtx *ctx) {
	kd_req_t req;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return 0;

	memset(&req, 0, sizeof(kd_req_t));

	req.req = 0x313C;
	req.cpu = ctx->cpu;

	req.r_cont.reason = 0x10001;
	// The meaning of 0x400 is unknown, but Windows doesn't behave like suggested by ReactOS source
	req.r_cont.tf = 0x400;

#ifdef WIND_LOG
	fprintf (stderr, "Sending continue...\n");
#endif

	ret = kd_send_data_packet (ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (uint8_t *)&req,
			sizeof (kd_req_t), NULL, 0);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet (ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return 0;

	r_list_free (ctx->plist_cache);
	ctx->plist_cache = NULL;
#ifdef WIND_LOG
	fprintf (stderr, "Done!\n");
#endif

	return 1;
}

int
wind_write_reg (WindCtx *ctx, uint8_t *buf, int size) {
	kd_packet_t *pkt;
	kd_req_t req;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return 0;

	memset(&req, 0, sizeof(kd_req_t));

	req.req = 0x3133;
	req.cpu = ctx->cpu;

	req.r_ctx.flags = 0x1003F;

#ifdef WIND_LOG
	fprintf(stderr, "Regwrite() size : %x\n", size);
#endif

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (uint8_t *)&req,
			sizeof(kd_req_t), buf, size);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_MANIP, &pkt);
	if (ret != KD_E_OK)
		return 0;

	kd_req_t *rr = PKT_REQ(pkt);

	// LOG_PKT(pkt);
	// LOG_REQ(rr);

	if (rr->ret) {
#ifdef WIND_LOG
		fprintf(stderr, "%s : req returned %08x\n", __FUNCTION__, rr->ret);
#endif
		free(pkt);
		return 0;
	}

	free(pkt);

	return size;
}

int
wind_read_reg (WindCtx *ctx, uint8_t *buf, int size) {
	kd_req_t req;
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return 0;

	memset(&req, 0, sizeof(kd_req_t));

	req.req = 0x3132;
	req.cpu = ctx->cpu;

	req.r_ctx.flags = 0x1003F;

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (uint8_t *)&req,
			sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_MANIP, &pkt);
	if (ret != KD_E_OK)
		return 0;

	kd_req_t *rr = PKT_REQ(pkt);

	// LOG_PKT(pkt);
	// LOG_REQ(rr);

	if (rr->ret) {
#ifdef WIND_LOG
		fprintf(stderr, "%s : req returned %08x\n", __FUNCTION__, rr->ret);
#endif
		free(pkt);
		return 0;
	}

	memcpy(buf, rr->data, size);

	free(pkt);

	return size;
}

int
wind_query_mem (WindCtx *ctx, const uint64_t addr, int *address_space, int *flags) {
	kd_req_t req;
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return 0;

	memset(&req, 0, sizeof(kd_req_t));

	req.req = 0x315c;
	req.cpu = ctx->cpu;

	req.r_query_mem.addr = addr;
	req.r_query_mem.address_space = 0; // Tells the kernel that 'addr' is a virtual address

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (uint8_t *)&req,
			sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_MANIP, &pkt);
	if (ret != KD_E_OK)
		return 0;

	kd_req_t *rr = PKT_REQ(pkt);

	// LOG_PKT(pkt);
	// LOG_REQ(rr);

	if (rr->ret) {
#ifdef WIND_LOG
		fprintf(stderr, "%s : req returned %08x\n", __FUNCTION__, rr->ret);
#endif
		free(pkt);
		return 0;
	}

	if (address_space)
		*address_space = rr->r_query_mem.address_space;
	if (flags)
		*flags = rr->r_query_mem.flags;

	free(pkt);

	return ret;

}

int
wind_bkpt (WindCtx *ctx, const uint64_t addr, const int set, const int hw, int *handle) {
	kd_req_t req;
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return 0;

	memset(&req, 0, sizeof(kd_req_t));

	req.req = set? 0x3134: 0x3135;
	req.cpu = ctx->cpu;

	if (set)
		req.r_set_bp.addr = addr;
	else
		req.r_del_bp.handle = *handle;

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (uint8_t *)&req,
			sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_MANIP, &pkt);
	if (ret != KD_E_OK)
		return 0;

	kd_req_t *rr = PKT_REQ(pkt);

	// LOG_PKT(pkt);
	// LOG_REQ(rr);

	if (rr->ret) {
#ifdef WIND_LOG
		fprintf(stderr, "%s : req returned %08x\n", __FUNCTION__, rr->ret);
#endif
		free(pkt);
		return 0;
	}

	*handle = rr->r_set_bp.handle;

	ret = !!rr->ret;

	free(pkt);

	return ret;
}

int
wind_read_at_phys (WindCtx *ctx, uint8_t *buf, const uint64_t offset, const int count) {
	kd_req_t req;
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return 0;

	memset(&req, 0, sizeof(kd_req_t));

	req.req = 0x313D;
	req.cpu = ctx->cpu;

	req.r_mem.addr = offset;
	req.r_mem.length = R_MIN(count, KD_MAX_PAYLOAD);
	req.r_mem.read = 0; // Default caching option

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (uint8_t *)&req,
			sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_MANIP, &pkt);
	if (ret != KD_E_OK)
		return 0;

	kd_req_t *rr = PKT_REQ(pkt);

	// LOG_PKT(pkt);
	// LOG_REQ(rr);

	if (rr->ret) {
#ifdef WIND_LOG
		fprintf(stderr, "%s : req returned %08x\n", __FUNCTION__, rr->ret);
#endif
		free(pkt);
		return 0;
	}

	memcpy(buf, rr->data, rr->r_mem.read);

	ret = rr->r_mem.read;

	free(pkt);

	return ret;
}

int
wind_read_at (WindCtx *ctx, uint8_t *buf, const uint64_t offset, const int count) {
	kd_req_t req;
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return 0;

	memset(&req, 0, sizeof(kd_req_t));

	req.req = 0x3130;
	req.cpu = ctx->cpu;

	req.r_mem.addr = offset;
	req.r_mem.length = R_MIN(count, KD_MAX_PAYLOAD);

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (uint8_t *)&req,
			sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_MANIP, &pkt);
	if (ret != KD_E_OK)
		return 0;

	kd_req_t *rr = PKT_REQ(pkt);

	// LOG_PKT(pkt);
	// LOG_REQ(rr);

	if (rr->ret) {
#ifdef WIND_LOG
		fprintf(stderr, "%s : req returned %08x\n", __FUNCTION__, rr->ret);
#endif
		free(pkt);
		return 0;
	}

	memcpy(buf, rr->data, rr->r_mem.read);

	ret = rr->r_mem.read;

	free(pkt);

	return ret;
}

int
wind_write_at (WindCtx *ctx, uint8_t *buf, const uint64_t offset, const int count) {
	kd_packet_t *pkt;
	kd_req_t req;
	int ret;
	int payload;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return 0;

	payload = R_MIN(count, KD_MAX_PAYLOAD - sizeof(kd_req_t));

	memset(&req, 0, sizeof(kd_req_t));

	req.req = 0x3131;
	req.cpu = ctx->cpu;

	req.r_mem.addr = offset;
	req.r_mem.length = payload;

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (uint8_t *)&req,
			sizeof(kd_req_t), buf, payload);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_MANIP, &pkt);
	if (ret != KD_E_OK)
		return 0;

	kd_req_t *rr = PKT_REQ(pkt);

	// LOG_PKT(pkt);
	// LOG_REQ(rr);

	if (rr->ret) {
#ifdef WIND_LOG
		fprintf(stderr, "%s : req returned %08x\n", __FUNCTION__, rr->ret);
#endif
		free(pkt);
		return 0;
	}

	ret = rr->r_mem.read;

	free(pkt);

	return ret;
}

int
wind_write_at_phys (WindCtx *ctx, uint8_t *buf, const uint64_t offset, const int count) {
	kd_packet_t *pkt;
	kd_req_t req;
	int ret;
	int payload;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return 0;

	payload = R_MIN(count, KD_MAX_PAYLOAD - sizeof(kd_req_t));

	memset(&req, 0, sizeof(kd_req_t));

	req.req = 0x313e;
	req.cpu = ctx->cpu;

	req.r_mem.addr = offset;
	req.r_mem.length = payload;
	req.r_mem.read = 0; // Default caching option

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (uint8_t *)&req,
			sizeof(kd_req_t), buf, payload);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return 0;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_MANIP, &pkt);
	if (ret != KD_E_OK)
		return 0;

	kd_req_t *rr = PKT_REQ(pkt);

	// LOG_PKT(pkt);
	// LOG_REQ(rr);

	if (rr->ret) {
#ifdef WIND_LOG
		fprintf(stderr, "%s : req returned %08x\n", __FUNCTION__, rr->ret);
#endif
		free(pkt);
		return 0;
	}

	ret = rr->r_mem.read;

	free(pkt);

	return ret;
}
