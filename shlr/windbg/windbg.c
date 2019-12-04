// Copyright (c) 2014-2017, The Lemon Man, All rights reserved. LGPLv3
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <r_util.h>
#include <r_cons.h>
#include <r_list.h>
#include "transport.h"
#include "windbg.h"
#include "kd.h"

#define O_FLAG_XPVAD 1
#define WIND_DBG if (false)
#define O_(n) ctx->os_profile->f[n]
#include "profiles.h"

Profile *p_table[] = {
	&XP_SP2_X86,
	&XP_SP3_X86,
	&WIN7_SP0_X86,
	&WIN7_SP1_X86,
	&WIN7_SP0_X64,
	&WIN7_SP1_X64,
	&WIN8_SP0_X86,
	&WIN8_SP1_X86,
	&WIN8_SP0_X64,
	&WIN8_SP1_X64,
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
	&WIN10_RS1_X64, // Windows 10 (Anniversary Update)
	&WIN10_RS4_X64, // Windows 10 (April 2018 Update)
	NULL,
};

Profile *windbg_get_profile(int bits, int build, int sp) {
	int i;
	for (i = 0; p_table[i]; i++) {
		if (p_table[i]->build != build) {
			continue;
		}
		if (p_table[i]->sp != sp) {
			continue;
		}
		if (p_table[i]->bits != bits) {
			continue;
		}
		return p_table[i];
	}
	return NULL;
}

#define LOG_REQ(r) {							\
		eprintf ("Request : %08x\nProcessor : %08x\nReturn : %08x\n",\
			(r)->req,					\
			(r)->cpu,					\
			(r)->ret					\
		);							\
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
	RList *tlist_cache;
	ut64 dbg_addr;
	WindProc *target;
	RThreadLock *dontmix;
};

bool windbg_lock_enter(WindCtx *ctx) {
	r_cons_break_push (windbg_break, ctx);
	r_th_lock_enter (ctx->dontmix);
	return true;
}

bool windbg_lock_tryenter(WindCtx *ctx) {
	if (!r_th_lock_tryenter (ctx->dontmix)) {
		return false;
	}
	r_cons_break_push (windbg_break, ctx);
	return true;
}

bool windbg_lock_leave(WindCtx *ctx) {
	r_cons_break_pop ();
	r_th_lock_leave (ctx->dontmix);
	return true;
}

int windbg_get_bits(WindCtx *ctx) {
	return ctx->is_x64 ? R_SYS_BITS_64 : R_SYS_BITS_32;
}

int windbg_get_cpus(WindCtx *ctx) {
	if (!ctx) {
		return -1;
	}
	return ctx->cpu_count;
}

bool windbg_set_cpu(WindCtx *ctx, int cpu) {
	if (!ctx || cpu > ctx->cpu_count) {
		return false;
	}
	ctx->cpu = cpu;
	return true;
}

int windbg_get_cpu(WindCtx *ctx) {
	if (!ctx) {
		return -1;
	}
	return ctx->cpu;
}

bool windbg_set_target(WindCtx *ctx, uint32_t pid) {
	WindProc *p;
	RListIter *it;
	if (pid) {
		RList *l = windbg_list_process (ctx);
		r_list_foreach (l, it, p) {
			if (p->uniqueid == pid) {
				ctx->target = p;
				return true;
			}
		}
		return false;
	}
	ctx->target = NULL;
	return true;
}

uint32_t windbg_get_target(WindCtx *ctx) {
	if (!ctx || !ctx->io_ptr || !ctx->syncd) {
		return 0;
	}
	return ctx->target? ctx->target->uniqueid: 0;
}

ut64 windbg_get_target_base(WindCtx *ctx) {
	ut64 base = 0;

	if (!ctx || !ctx->io_ptr || !ctx->syncd || !ctx->target) {
		return 0;
	}

	if (!windbg_read_at_uva (ctx, (uint8_t *) &base,
		    ctx->target->peb + O_(P_ImageBaseAddress), 4 << ctx->is_x64)) {
		return 0;
	}

	return base;
}

WindCtx *windbg_ctx_new(void *io_ptr) {
	WindCtx *ctx = calloc (1, sizeof(WindCtx));
	if (!ctx) {
		return NULL;
	}
	ctx->dontmix = r_th_lock_new (true);
	ctx->io_ptr = io_ptr;
	return ctx;
}

void windbg_ctx_free(WindCtx **ctx) {
	if (!ctx || !*ctx) {
		return;
	}
	r_list_free ((*ctx)->plist_cache);
	r_list_free ((*ctx)->tlist_cache);
	iob_close ((*ctx)->io_ptr);
	r_th_lock_free ((*ctx)->dontmix);
	R_FREE (*ctx);
}

#define PKT_REQ(p) ((kd_req_t *) (((kd_packet_t *) p)->data))
#define PKT_STC(p) ((kd_stc_64 *) (((kd_packet_t *) p)->data))

#if 0
static void dump_stc(kd_packet_t *p) {
	kd_stc_64 *stc = PKT_STC (p);

	eprintf ("New state: %08x\n", stc->state);
	eprintf ("EIP: 0x%016"PFMT64x " Kthread: 0x%016"PFMT64x "\n",
		(ut64) stc->pc, (ut64) stc->kthread);
	eprintf ("On cpu %i/%i\n", stc->cpu + 1, stc->cpu_count);

	if (stc->state == DbgKdExceptionStateChange) {
		eprintf ("Exception\n");
		eprintf (" Code   : %08x\n", stc->exception.code);
		eprintf (" Flags  : %08x\n", stc->exception.flags);
		eprintf (" Record : %016"PFMT64x "\n", (ut64) stc->exception.ex_record);
		eprintf (" Addr   : %016"PFMT64x "\n", (ut64) stc->exception.ex_addr);
	}
}
#endif

static int do_io_reply(WindCtx *ctx, kd_packet_t *pkt) {
	kd_ioc_t ioc = {
		0
	};
	static int id = 0;
	if (id == pkt->id) {
		WIND_DBG eprintf("Host resent io packet, ignoring.\n");
		return true;
	}
	int ret;
	ioc.req = 0x3430;
	ioc.ret = KD_RET_ENOENT;
	windbg_lock_enter (ctx);
	id = pkt->id;
	ret = kd_send_data_packet (ctx->io_ptr, KD_PACKET_TYPE_FILE_IO,
		(ctx->seq_id ^= 1), (uint8_t *) &ioc, sizeof (kd_ioc_t), NULL, 0);
	if (ret != KD_E_OK) {
		goto error;
	}
	WIND_DBG eprintf("Waiting for io_reply ack...\n");
	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}
	id = 0;
	windbg_lock_leave (ctx);
	WIND_DBG eprintf("Ack received, restore flow\n");
	return true;
error:
	id = 0;
	windbg_lock_leave (ctx);
	return 0;
}

int windbg_wait_packet(WindCtx *ctx, const uint32_t type, kd_packet_t **p) {
	kd_packet_t *pkt = NULL;
	int ret;
	int retries = 10;

	do {
		if (pkt) {
			R_FREE (pkt);
		}
		// Try to read a whole packet
		ret = kd_read_packet (ctx->io_ptr, &pkt);
		if (ret != KD_E_OK || !pkt) {
			break;
		}

		// eprintf ("Received %08x\n", pkt->type);
		if (pkt->type != type) {
			WIND_DBG eprintf ("We were not waiting for this... %08x\n", pkt->type);
		}
		if (pkt->leader == KD_PACKET_DATA && pkt->type == KD_PACKET_TYPE_STATE_CHANGE64) {
			// dump_stc (pkt);
			WIND_DBG eprintf ("State64\n");
		}
		if (pkt->leader == KD_PACKET_DATA && pkt->type == KD_PACKET_TYPE_FILE_IO) {
			WIND_DBG eprintf ("Replying IO\n");
			do_io_reply (ctx, pkt);
		}

		// Check for RESEND
		// The host didn't like our request
		if (pkt->leader == KD_PACKET_CTRL && pkt->type == KD_PACKET_TYPE_RESEND) {
			r_sys_backtrace ();
			WIND_DBG eprintf ("Waoh. You probably sent a malformed packet !\n");
			ret = KD_E_MALFORMED;
			break;
		}
	} while (pkt->type != type && retries--);

	if (ret != KD_E_OK) {
		free (pkt);
		return ret;
	}

	if (p) {
		*p = pkt;
	} else {
		free (pkt);
	}

	return KD_E_OK;
}

// http://dfrws.org/2007/proceedings/p62-dolan-gavitt.pdf
R_PACKED (
	typedef struct {
	char tag[4];
	uint32_t start_vpn;
	uint32_t end_vpn;
	uint32_t parent;
	uint32_t left;
	uint32_t right;
	uint32_t flags;
}) mmvad_short;

int windbg_walk_vadtree(WindCtx *ctx, ut64 address, ut64 parent) {
	mmvad_short entry = { { 0 } };
	ut64 start, end;
	int prot;

	if (windbg_read_at (ctx, (uint8_t *) &entry, address - 0x4, sizeof(mmvad_short)) != sizeof (mmvad_short)) {
		eprintf ("0x%"PFMT64x " Could not read the node!\n", (ut64) address);
		return 0;
	}

	if (parent != UT64_MAX && entry.parent != parent) {
		eprintf ("Wrong parent!\n");
		return 0;
	}

	start = entry.start_vpn << 12;
	end = ((entry.end_vpn + 1) << 12) - 1;
	prot = (entry.flags >> 24) & 0x1F;

	eprintf ("Start 0x%016"PFMT64x " End 0x%016"PFMT64x " Prot 0x%08"PFMT64x "\n",
		(ut64) start, (ut64) end, (ut64) prot);

	if (entry.left) {
		windbg_walk_vadtree (ctx, entry.left, address);
	}
	if (entry.right) {
		windbg_walk_vadtree (ctx, entry.right, address);
	}

	return 1;
}

RList *windbg_list_process(WindCtx *ctx) {
	RList *ret;
	ut64 ptr, base;

	if (!ctx || !ctx->io_ptr || !ctx->syncd) {
		return NULL;
	}

	if (ctx->plist_cache) {
		return ctx->plist_cache;
	}

	ptr = 0;
	// Grab the PsActiveProcessHead from _KDDEBUGGER_DATA64
	windbg_read_at (ctx, (uint8_t *) &ptr, ctx->dbg_addr + K_PsActiveProcessHead,
		4 << ctx->is_x64);

	base = ptr;
	WIND_DBG eprintf("Process list head : 0x%016"PFMT64x "\n", ptr);

	// Walk the LIST_ENTRY
	windbg_read_at (ctx, (uint8_t *) &ptr, ptr, 4 << ctx->is_x64);

	ret = r_list_newf (free);

	do {
		uint8_t buf[17];
		ut64 next;

		next = 0;
		// Read the ActiveProcessLinks entry
		windbg_read_at (ctx, (uint8_t *) &next, ptr, 4 << ctx->is_x64);

		// This points to the 'ActiveProcessLinks' list, adjust the ptr so that it point to the
		// EPROCESS base
		ptr -= O_(E_ActiveProcessLinks);

		// Read the short name
		windbg_read_at (ctx, (uint8_t *) &buf, ptr + O_(E_ImageFileName), 16);
		buf[16] = '\0';

		ut64 vadroot = 0;
		ut64 uniqueid = 0;
		ut64 peb = 0;
		ut64 dir_base_table = 0;

		windbg_read_at (ctx, (uint8_t *) &vadroot, ptr + O_(E_VadRoot), 4 << ctx->is_x64);
		windbg_read_at (ctx, (uint8_t *) &uniqueid, ptr + O_(E_UniqueProcessId), 4 << ctx->is_x64);
		windbg_read_at (ctx, (uint8_t *) &peb, ptr + O_(E_Peb), 4 << ctx->is_x64);
		windbg_read_at (ctx, (uint8_t *) &dir_base_table, ptr + O_(P_DirectoryTableBase), 4 << ctx->is_x64);

		WindProc *proc = calloc (1, sizeof(WindProc));

		strcpy (proc->name, (const char *) buf);
		proc->eprocess = ptr;
		proc->vadroot = vadroot;
		proc->uniqueid = uniqueid;
		proc->dir_base_table = dir_base_table;
		proc->peb = peb;

		r_list_append (ret, proc);

		// windbg_walk_vadtree(ctx, vadroot, -1);
		ptr = next;
	} while (ptr != base);

	ctx->plist_cache = ret;

	return ret;
}

int windbg_write_at_uva(WindCtx *ctx, const uint8_t *buf, ut64 offset, int count) {
	ut64 pa;
	ut32 totwritten = 0;
	while (totwritten < count) {
		if (!windbg_va_to_pa (ctx, offset, &pa)) {
			return 0;
		}
		ut32 restOfPage = 0x1000 - (offset & 0xfff);
		int written = windbg_write_at_phys (ctx, buf + totwritten, pa, R_MIN (count - totwritten, restOfPage));
		if (!written) {
			break;
		}
		offset += written;
		totwritten += written;
	}
	return totwritten;
}

int windbg_read_at_uva(WindCtx *ctx, uint8_t *buf, ut64 offset, int count) {
	ut64 pa;
	ut32 totread = 0;
	while (totread < count) {
		if (!windbg_va_to_pa (ctx, offset, &pa)) {
			return 0;
		}
		ut32 restOfPage = 0x1000 - (offset & 0xfff);
		int read = windbg_read_at_phys (ctx, buf + totread, pa, R_MIN (count - totread, restOfPage));
		if (!read) {
			break;
		}
		offset += read;
		totread += read;
	}
	return totread;
}

RList *windbg_list_modules(WindCtx *ctx) {
	RList *ret;
	ut64 ptr, base;

	if (!ctx || !ctx->io_ptr || !ctx->syncd) {
		return NULL;
	}

	if (!ctx->target) {
		eprintf ("No target process\n");
		return NULL;
	}

	ptr = ctx->target->peb;
	if (!ptr) {
		eprintf ("No PEB\n");
		return NULL;
	}

	ut64 ldroff = ctx->is_x64 ? 0x18 : 0xC;

	// Grab the _PEB_LDR_DATA from PEB
	windbg_read_at_uva (ctx, (uint8_t *) &ptr, ctx->target->peb + ldroff, 4 << ctx->is_x64);

	WIND_DBG eprintf("_PEB_LDR_DATA : 0x%016"PFMT64x "\n", ptr);

	// LIST_ENTRY InMemoryOrderModuleList
	ut64 mlistoff = ctx->is_x64 ? 0x20 : 0x14;
	
	base = ptr + mlistoff;

	windbg_read_at_uva (ctx, (uint8_t *) &ptr, base, 4 << ctx->is_x64);

	WIND_DBG eprintf ("InMemoryOrderModuleList : 0x%016"PFMT64x "\n", ptr);

	ret = r_list_newf (free);

	const ut64 baseoff = ctx->is_x64 ? 0x30 : 0x18;
	const ut64 sizeoff = ctx->is_x64 ? 0x40 : 0x20;
	const ut64 nameoff = ctx->is_x64 ? 0x48 : 0x24;

	do {

		ut64 next = 0;
		windbg_read_at_uva (ctx, (uint8_t *) &next, ptr, 4 << ctx->is_x64);
		WIND_DBG eprintf ("_LDR_DATA_TABLE_ENTRY : 0x%016"PFMT64x "\n", next);

		if (!next) {
			eprintf ("Corrupted InMemoryOrderModuleList found at: 0x%"PFMT64x"\n", ptr);
			break;
		}

		ptr -= (4 << ctx->is_x64) * 2;

		WindModule *mod = R_NEW0 (WindModule);
		if (!mod) {
			break;
		}
		windbg_read_at_uva (ctx, (uint8_t *) &mod->addr, ptr + baseoff, 4 << ctx->is_x64);
		windbg_read_at_uva (ctx, (uint8_t *) &mod->size, ptr + sizeoff, 4 << ctx->is_x64);

		ut16 length;
		windbg_read_at_uva (ctx, (uint8_t *) &length, ptr + nameoff, sizeof (ut16));

		ut64 bufferaddr = 0;
		windbg_read_at_uva (ctx, (uint8_t *) &bufferaddr, ptr + nameoff + sizeof (ut32), 4 << ctx->is_x64);

		wchar_t *unname = calloc ((ut64)length + 2, 1);
		if (!unname) {
			break;
		}

		windbg_read_at_uva (ctx, (uint8_t *)unname, bufferaddr, length);

		mod->name = calloc ((ut64)length + 1, 1);
		if (!mod->name) {
			break;
		}
		wcstombs (mod->name, unname, length);
		free (unname);
		ptr = next;

		r_list_append (ret, mod);

	} while (ptr != base);

	return ret;
}

RList *windbg_list_threads(WindCtx *ctx) {
	RList *ret;
	ut64 ptr, base;

	if (!ctx || !ctx->io_ptr || !ctx->syncd) {
		return NULL;
	}

	if (ctx->tlist_cache) {
		return ctx->tlist_cache;
	}

	if (!ctx->target) {
		eprintf ("No target process\n");
		return NULL;
	}

	ptr = ctx->target->eprocess;
	if (!ptr) {
		eprintf ("No _EPROCESS\n");
		return NULL;
	}

	// Grab the ThreadListHead from _EPROCESS
	windbg_read_at (ctx, (uint8_t *) &ptr, ptr + O_(E_ThreadListHead), 4 << ctx->is_x64);
	if (!ptr) {
		return NULL;
	}

	base = ptr;

	ret = r_list_newf (free);

	do {
		ut64 next = 0;

		windbg_read_at (ctx, (uint8_t *) &next, ptr, 4 << ctx->is_x64);
		if (!next) {
			eprintf ("Corrupted ThreadListEntry found at: 0x%"PFMT64x"\n", ptr);
			break;
		}

		// Adjust the ptr so that it points to the ETHREAD base
		ptr -= O_(ET_ThreadListEntry);

		ut64 entrypoint = 0;
		windbg_read_at (ctx, (uint8_t *) &entrypoint, ptr + O_(ET_Win32StartAddress), 4 << ctx->is_x64);

		ut64 uniqueid = 0;
		windbg_read_at (ctx, (uint8_t *) &uniqueid, ptr + O_(ET_Cid) + O_(C_UniqueThread), 4 << ctx->is_x64);
		if (uniqueid) {
			WindThread *thread = calloc (1, sizeof(WindThread));
			thread->uniqueid = uniqueid;
			thread->status = 's';
			thread->runnable = true;
			thread->ethread = ptr;
			thread->entrypoint = entrypoint;

			r_list_append (ret, thread);
		}

		ptr = next;
	} while (ptr != base);

	ctx->tlist_cache = ret;

	return ret;
}

#define PTE_VALID       0x0001
#define PTE_LARGEPAGE   0x0080
#define PTE_PROTOTYPE   0x0400

// http://blogs.msdn.com/b/ntdebugging/archive/2010/02/05/understanding-pte-part-1-let-s-get-physical.aspx
// http://blogs.msdn.com/b/ntdebugging/archive/2010/04/14/understanding-pte-part2-flags-and-large-pages.aspx
// http://blogs.msdn.com/b/ntdebugging/archive/2010/06/22/part-3-understanding-pte-non-pae-and-x64.aspx
bool windbg_va_to_pa(WindCtx *ctx, ut64 va, ut64 *pa) {
	ut64 pml4i, pdpi, pdi, pti;
	ut64 tmp, mask;

	// We shouldn't really reach this
	if (!ctx->target) {
		return 0;
	}

	WIND_DBG eprintf("VA   : %016"PFMT64x "\n", va);

	if (ctx->is_x64) {
		pti = (va >> 12) & 0x1ff;
		pdi = (va >> 21) & 0x1ff;
		pdpi = (va >> 30) & 0x1ff;
		pml4i = (va >> 39) & 0x1ff;
		// Grab the PageFrameNumber field off the _HARDWARE_PTE entry
		mask = 0x000000fffffff000;
	} else {
		if (ctx->pae) {
			pti = (va >> 12) & 0x1ff;
			pdi = (va >> 21) & 0x1ff;
			pdpi = (va >> 30) & 0x3;
			pml4i = 0;
		} else {
			pti = (va >> 12) & 0x3ff;
			pdi = (va >> 22) & 0x3ff;
			pdpi = 0;
			pml4i = 0;
		}
		// Grab the PageFrameNumber field off the _HARDWARE_PTE entry
		mask = 0xfffff000;
	}

	tmp = ctx->target->dir_base_table;
	tmp &= ~0x1f;

	WIND_DBG eprintf("CR3  : %016"PFMT64x "\n", tmp);

	if (ctx->is_x64) {
		// PML4 lookup
		if (!windbg_read_at_phys (ctx, (uint8_t *) &tmp, tmp + pml4i * 8, 8)) {
			return false;
		}
		tmp &= mask;
		WIND_DBG eprintf("PML4 : %016"PFMT64x "\n", tmp);
	}

	if (ctx->pae) {
		// PDPT lookup
		if (!windbg_read_at_phys (ctx, (uint8_t *) &tmp, tmp + pdpi * 8, 8)) {
			return false;
		}
		tmp &= mask;
		WIND_DBG eprintf("PDPE : %016"PFMT64x "\n", tmp);
	}

	// PDT lookup
	if (!windbg_read_at_phys (ctx, (uint8_t *) &tmp, tmp + pdi * (4 << ctx->pae), 4 << ctx->pae)) {
		return false;
	}
	WIND_DBG eprintf("PDE  : %016"PFMT64x "\n", tmp);

	// Large page entry
	// The page size differs between pae and non-pae systems, the former points to 2MB pages while
	// the latter points to 4MB pages
	if (tmp & PTE_LARGEPAGE) {
		*pa = ctx->pae?
		      (tmp & (~0x1fffff)) | (va & 0x1fffff):
		      (tmp & (~0x3fffff)) | (va & 0x3fffff);
		return true;
	}

	// PT lookup
	if (!windbg_read_at_phys (ctx, (uint8_t *) &tmp, (tmp & mask) + pti * (4 << ctx->pae), 4 << ctx->pae)) {
		return false;
	}
	WIND_DBG eprintf("PTE  : %016"PFMT64x "\n", tmp);

	if (tmp & PTE_VALID) {
		*pa = (tmp & mask) | (va & 0xfff);
		return true;
	}

	if (tmp & PTE_PROTOTYPE) {
		// TODO : prototype PTE support
		eprintf ("Prototype PTE lookup is currently missing!\n");
	}

	return false;
}

bool windbg_read_ver(WindCtx *ctx) {
	kd_req_t req = {
		0
	};
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd) {
		return false;
	}

	req.req = 0x3146;
	req.cpu = ctx->cpu;

	windbg_lock_enter (ctx);

	ret = kd_send_data_packet (ctx->io_ptr, KD_PACKET_TYPE_STATE_MANIPULATE,
		(ctx->seq_id ^= 1), (uint8_t *) &req, sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		goto error;
	}

	windbg_lock_leave (ctx);

	kd_req_t *rr = PKT_REQ (pkt);

	if (rr->ret) {
		WIND_DBG eprintf("%s : req returned %08x\n", __FUNCTION__, rr->ret);
		free (pkt);
		return 0;
	}

	WIND_DBG {
		eprintf ("Major : %i Minor %i\n", rr->r_ver.major, rr->r_ver.minor);
		eprintf ("Protocol version : %i.%i\n", rr->r_ver.proto_major, rr->r_ver.proto_minor);
		eprintf ("Flags : %08x\n", rr->r_ver.flags);
		eprintf ("Machine : %08x\n", rr->r_ver.machine);
		eprintf ("Module list : %016"PFMT64x "\n", (ut64) rr->r_ver.mod_addr);
		eprintf ("Debug block : %016"PFMT64x "\n", (ut64) rr->r_ver.dbg_addr);
	}

	if (rr->r_ver.machine != KD_MACH_I386 && rr->r_ver.machine != KD_MACH_AMD64) {
		eprintf ("Unsupported target host\n");
		free (pkt);
		return 0;
	}

	if (!(rr->r_ver.flags & DBGKD_VERS_FLAG_DATA)) {
		eprintf ("No _KDDEBUGGER_DATA64 pointer has been supplied by the debugee!\n");
		free (pkt);
		return 0;
	}

	ctx->is_x64 = (rr->r_ver.machine == KD_MACH_AMD64);

	ut64 ptr = 0;
	if (!windbg_read_at (ctx, (uint8_t *) &ptr, rr->r_ver.dbg_addr, 4 << ctx->is_x64)) {
		free (pkt);
		return false;
	}

	ctx->dbg_addr = ptr;

	WIND_DBG eprintf("_KDDEBUGGER_DATA64 at 0x%016"PFMT64x "\n", ctx->dbg_addr);

	// Thanks to this we don't have to find a way to read the cr4
	uint16_t pae_enabled;
	if (!windbg_read_at (ctx, (uint8_t *) &pae_enabled, ctx->dbg_addr + K_PaeEnabled, sizeof(uint16_t))) {
		free (pkt);
		return false;
	}

	// Grab the CmNtCSDVersion field to extract the Service Pack number
	windbg_read_at (ctx, (uint8_t *) &ptr, ctx->dbg_addr + K_CmNtCSDVersion, 8);
	windbg_read_at (ctx, (uint8_t *) &ptr, ptr, 4 << ctx->is_x64);

	ctx->pae = pae_enabled & 1;
	ctx->os_profile = windbg_get_profile (32 << ctx->is_x64, rr->r_ver.minor, (ptr >> 8) & 0xff);
	if (!ctx->os_profile) {
		eprintf ("Could not find a suitable profile for the target OS\n");
		free (pkt);
		return false;
	}
	free (pkt);
	return true;
error:
	windbg_lock_leave (ctx);
	return 0;
}

int windbg_sync(WindCtx *ctx) {
	int ret = -1;
	kd_packet_t *s;

	if (!ctx || !ctx->io_ptr) {
		return 0;
	}

	if (ctx->syncd) {
		return 1;
	}

	windbg_lock_enter (ctx);

	// Send the breakin packet
	if (iob_write (ctx->io_ptr, (const uint8_t *) "b", 1) != 1) {
		ret = 0;
		goto end;
	}

	// Reset the host
	ret = kd_send_ctrl_packet (ctx->io_ptr, KD_PACKET_TYPE_RESET, 0);
	if (ret != KD_E_OK) {
		ret = 0;
		goto end;
	}

	// Wait for the response
	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_RESET, NULL);
	if (ret != KD_E_OK) {
		ret = 0;
		goto end;
	}

	// Syncronize with the first KD_PACKET_TYPE_STATE_CHANGE64 packet
	windbg_wait_packet (ctx, KD_PACKET_TYPE_STATE_CHANGE64, &s);

	// Reset the sequence id
	ctx->seq_id = 0x80800001;

	kd_stc_64 *stc64 = (kd_stc_64*)s->data;
	ctx->cpu = stc64->cpu;
	ctx->cpu_count = stc64->cpu_count;
	ctx->target = NULL;
	r_list_free (ctx->plist_cache);
	ctx->plist_cache = NULL;
	r_list_free (ctx->tlist_cache);
	ctx->tlist_cache = NULL;
	ctx->pae = 0;
	// We're ready to go
	ctx->syncd = 1;

	free (s);
	eprintf ("Sync done! (%i cpus found)\n", ctx->cpu_count);
	ret = 1;

end:
	windbg_lock_leave (ctx);
	return ret;
}

int windbg_continue(WindCtx *ctx) {
	kd_req_t req = {
		0
	};
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd) {
		return 0;
	}
	req.req = DbgKdContinueApi;
	req.cpu = ctx->cpu;
	req.r_cont.reason = 0x10001;
	// The meaning of 0x400 is unknown, but Windows doesn't
	// behave like suggested by ReactOS source
	req.r_cont.tf = 0x400;

	windbg_lock_enter (ctx);

	ret = kd_send_data_packet (ctx->io_ptr, KD_PACKET_TYPE_STATE_MANIPULATE,
		(ctx->seq_id ^= 1), (uint8_t *) &req, sizeof (kd_req_t), NULL, 0);
	if (ret == KD_E_OK) {
		ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
		if (ret == KD_E_OK) {
			r_list_free (ctx->plist_cache);
			ctx->plist_cache = NULL;
			ret = true;
			goto end;
		}
	}
	ret = false;

end:
	windbg_lock_leave (ctx);
	return ret;
}

bool windbg_write_reg(WindCtx *ctx, const uint8_t *buf, int size) {
	kd_packet_t *pkt;
	kd_req_t req = {
		0
	};
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd) {
		return false;
	}
	req.req = DbgKdSetContextApi;
	req.cpu = ctx->cpu;
	req.r_ctx.flags = 0x1003F;

	WIND_DBG eprintf("Regwrite() size: %x\n", size);

	windbg_lock_enter (ctx);

	ret = kd_send_data_packet (ctx->io_ptr, KD_PACKET_TYPE_STATE_MANIPULATE,
		(ctx->seq_id ^= 1), (uint8_t *) &req, sizeof(kd_req_t), buf, size);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		goto error;
	}

	windbg_lock_leave (ctx);

	kd_req_t *rr = PKT_REQ (pkt);

	if (rr->ret) {
		WIND_DBG eprintf("%s: req returned %08x\n", __FUNCTION__, rr->ret);
		free (pkt);
		return 0;
	}

	free (pkt);

	return size;
error:
	windbg_lock_leave (ctx);
	return 0;
}

int windbg_read_reg(WindCtx *ctx, uint8_t *buf, int size) {
	kd_req_t req;
	kd_packet_t *pkt = NULL;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd) {
		return 0;
	}

	memset (&req, 0, sizeof(kd_req_t));

	req.req = DbgKdGetContextApi;
	req.cpu = ctx->cpu;

	req.r_ctx.flags = 0x1003F;

	// Don't wait on the lock in read_reg since it's frequently called. Otherwise the user
	// will be forced to interrupt exit read_reg constantly while another task is in progress
	if (!windbg_lock_tryenter (ctx)) {
		goto error;
	}

	ret = kd_send_data_packet (ctx->io_ptr, KD_PACKET_TYPE_STATE_MANIPULATE, (ctx->seq_id ^= 1), (uint8_t *) &req,
		sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		goto error;
	}

	windbg_lock_leave (ctx);

	kd_req_t *rr = PKT_REQ (pkt);

	if (rr->ret) {
		WIND_DBG eprintf("%s: req returned %08x\n", __FUNCTION__, rr->ret);
		free (pkt);
		return 0;
	}

	memcpy (buf, rr->data, R_MIN (size, pkt->length - sizeof (rr)));

	free (pkt);

	return size;
error:
	windbg_lock_leave (ctx);
	return 0;
}

int windbg_query_mem(WindCtx *ctx, const ut64 addr, int *address_space, int *flags) {
	kd_req_t req;
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd) {
		return 0;
	}

	memset (&req, 0, sizeof(kd_req_t));

	req.req = DbgKdQueryMemoryApi;
	req.cpu = ctx->cpu;

	req.r_query_mem.addr = addr;
	req.r_query_mem.address_space = 0;	// Tells the kernel that 'addr' is a virtual address

	windbg_lock_enter (ctx);

	ret = kd_send_data_packet (ctx->io_ptr, KD_PACKET_TYPE_STATE_MANIPULATE, (ctx->seq_id ^= 1), (uint8_t *) &req,
		sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		goto error;
	}

	windbg_lock_leave (ctx);

	kd_req_t *rr = PKT_REQ (pkt);

	if (rr->ret) {
		free (pkt);
		return 0;
	}

	if (address_space) {
		*address_space = rr->r_query_mem.address_space;
	}
	if (flags) {
		*flags = rr->r_query_mem.flags;
	}

	free (pkt);

	return ret;
error:
	windbg_lock_leave (ctx);
	return 0;

}

int windbg_bkpt(WindCtx *ctx, const ut64 addr, const int set, const int hw, int *handle) {
	kd_req_t req = {
		0
	};
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd) {
		return 0;
	}

	req.req = set? DbgKdWriteBreakPointApi: DbgKdRestoreBreakPointApi;
	req.cpu = ctx->cpu;

	if (set) {
		req.r_set_bp.addr = addr;
	} else {
		req.r_del_bp.handle = *handle;
	}

	windbg_lock_enter (ctx);

	ret = kd_send_data_packet (ctx->io_ptr, KD_PACKET_TYPE_STATE_MANIPULATE, (ctx->seq_id ^= 1), (uint8_t *) &req,
		sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		goto error;
	}

	windbg_lock_leave (ctx);

	kd_req_t *rr = PKT_REQ (pkt);

	if (rr->ret) {
		free (pkt);
		return 0;
	}
	*handle = rr->r_set_bp.handle;
	ret = !!rr->ret;
	free (pkt);
	return ret;
error:
	windbg_lock_leave (ctx);
	return 0;
}

int windbg_read_at_phys(WindCtx *ctx, uint8_t *buf, const ut64 offset, const int count) {
	kd_req_t req = {
		0
	}, *rr;
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd) {
		return 0;
	}
	req.req = DbgKdReadPhysicalMemoryApi;
	req.cpu = ctx->cpu;
	req.r_mem.addr = offset;
	req.r_mem.length = R_MIN (count, KD_MAX_PAYLOAD);
	req.r_mem.read = 0;	// Default caching option

	// Don't wait on the lock in read_reg since it's frequently called. Otherwise the user
	// will be forced to interrupt exit read_at_phys constantly while another task is in progress
	if (!windbg_lock_tryenter (ctx)) {
		goto error;
	}

	ret = kd_send_data_packet (ctx->io_ptr, KD_PACKET_TYPE_STATE_MANIPULATE, (ctx->seq_id ^= 1),
		(uint8_t *) &req, sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		goto error;
	}

	windbg_lock_leave (ctx);

	rr = PKT_REQ (pkt);

	if (rr->ret) {
		free (pkt);
		return 0;
	}

	memcpy (buf, rr->data, rr->r_mem.read);
	ret = rr->r_mem.read;
	free (pkt);
	return ret;
error:
	windbg_lock_leave (ctx);
	return 0;
}

int windbg_read_at(WindCtx *ctx, uint8_t *buf, const ut64 offset, const int count) {
	kd_req_t *rr, req = {
		0
	};
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd) {
		return 0;
	}
	req.req = DbgKdReadVirtualMemoryApi;
	req.cpu = ctx->cpu;
	req.r_mem.addr = offset;
	req.r_mem.length = R_MIN (count, KD_MAX_PAYLOAD);

	// Don't wait on the lock in read_at since it's frequently called, including each
	// time "enter" is pressed. Otherwise the user will be forced to interrupt exit
	// read_registers constantly while another task is in progress
	if (!windbg_lock_tryenter (ctx)) {
		goto error;
	}

	ret = kd_send_data_packet (ctx->io_ptr, KD_PACKET_TYPE_STATE_MANIPULATE,
		(ctx->seq_id ^= 1), (uint8_t *) &req, sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}
	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		return 0;
	}

	windbg_lock_leave (ctx);

	rr = PKT_REQ (pkt);

	if (rr->ret) {
		free (pkt);
		return 0;
	}

	memcpy (buf, rr->data, rr->r_mem.read);
	ret = rr->r_mem.read;
	free (pkt);
	return ret;
error:
	windbg_lock_leave (ctx);
	return 0;
}

int windbg_write_at(WindCtx *ctx, const uint8_t *buf, const ut64 offset, const int count) {
	kd_packet_t *pkt;
	kd_req_t req = {
		0
	}, *rr;
	int payload, ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd) {
		return 0;
	}

	payload = R_MIN (count, KD_MAX_PAYLOAD - sizeof(kd_req_t));
	req.req = DbgKdWriteVirtualMemoryApi;
	req.cpu = ctx->cpu;
	req.r_mem.addr = offset;
	req.r_mem.length = payload;

	windbg_lock_enter (ctx);

	ret = kd_send_data_packet (ctx->io_ptr, KD_PACKET_TYPE_STATE_MANIPULATE,
		(ctx->seq_id ^= 1), (uint8_t *) &req,
		sizeof(kd_req_t), buf, payload);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		goto error;
	}

	windbg_lock_leave (ctx);

	rr = PKT_REQ (pkt);

	if (rr->ret) {
		free (pkt);
		return 0;
	}

	ret = rr->r_mem.read;
	free (pkt);
	return ret;
error:
	windbg_lock_leave (ctx);
	return 0;
}

int windbg_write_at_phys(WindCtx *ctx, const uint8_t *buf, const ut64 offset, const int count) {
	kd_packet_t *pkt;
	kd_req_t req;
	int ret;
	int payload;

	if (!ctx || !ctx->io_ptr || !ctx->syncd) {
		return 0;
	}

	payload = R_MIN (count, KD_MAX_PAYLOAD - sizeof(kd_req_t));

	memset (&req, 0, sizeof(kd_req_t));

	req.req = DbgKdWritePhysicalMemoryApi;
	req.cpu = ctx->cpu;

	req.r_mem.addr = offset;
	req.r_mem.length = payload;
	req.r_mem.read = 0;	// Default caching option

	windbg_lock_enter (ctx);

	ret = kd_send_data_packet (ctx->io_ptr, KD_PACKET_TYPE_STATE_MANIPULATE,
		(ctx->seq_id ^= 1), (uint8_t *) &req, sizeof(kd_req_t), buf, payload);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = windbg_wait_packet (ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		goto error;
	}

	windbg_lock_leave (ctx);

	kd_req_t *rr = PKT_REQ (pkt);

	if (rr->ret) {
		free (pkt);
		return 0;
	}
	ret = rr->r_mem.read;
	free (pkt);
	return ret;
error:
	windbg_lock_leave (ctx);
	return 0;
}

void windbg_break(void *arg) {
	// This command shouldn't be wrapped by locks since it can always be sent and we don't
	// want break queued up after another background task
	WindCtx *ctx = (WindCtx *)arg;
	(void)iob_write (ctx->io_ptr, (const uint8_t *)"b", 1);
}

int windbg_break_read(WindCtx *ctx) {
#if __WINDOWS__ && !defined(_MSC_VER)
	static BOOL WINAPI (*w32_CancelIoEx)(HANDLE, LPOVERLAPPED) = NULL;
	if (!w32_CancelIoEx) {
		w32_CancelIoEx = (BOOL WINAPI (*)(HANDLE, LPOVERLAPPED))
				 GetProcAddress (GetModuleHandle (TEXT ("kernel32")),
			"CancelIoEx");
	}
	if (w32_CancelIoEx) {
		w32_CancelIoEx (ctx->io_ptr, NULL);
	}
#endif
	return 1;
}
