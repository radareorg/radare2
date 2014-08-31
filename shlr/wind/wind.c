#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <r_types.h>
#include "wind.h"
#include "kd.h"

#define LOG_PKT(p) \
{ \
	eprintf("Leader\t: %08x\nType\t: %08x\nLenght\t: %08x\nID\t: %08x\nCheck\t: %08x [%s]\n", \
		(p)->leader, \
		(p)->type, \
		(p)->lenght, \
		(p)->id, \
		(p)->checksum, \
		(kd_data_checksum((p)->data, (p)->lenght) == (p)->checksum)?"Ok":"Wrong" \
	); \
}
#define LOG_REQ(r) \
{ \
	eprintf("Request : %08x\nProcessor : %08x\nReturn : %08x\n", \
		(r)->req, \
		(r)->cpu, \
		(r)->ret \
	); \
}

wind_ctx_t *
wind_ctx_new (void *io_ptr) {
	wind_ctx_t *ctx = R_NEW0(wind_ctx_t);

	ctx->io_ptr = io_ptr;

	return ctx;
}

void
wind_ctx_free (wind_ctx_t *ctx) {
	if (!ctx)
		return;
	iob_close(ctx->io_ptr);
	free(ctx);
}

#define PKT_REQ(p) ( (kd_req_t *)((kd_packet_t *)(p)->data) )
#define PKT_STC(p) ( (kd_stc_64 *)((kd_packet_t *)(p)->data) )

static void
dump_stc (kd_packet_t *p) {
	kd_stc_64 *stc = PKT_STC(p);

	eprintf("New state : %08x\n", stc->state);
	eprintf("eip : %016llx kthread : %016llx\n",
			stc->pc,
			stc->kthread);
	eprintf("On cpu %i/%i\n", stc->cpu + 1, stc->cpu_count);

	if (stc->state == 0x3030) {
		eprintf("ex\n");
		eprintf("\tCode   : %08x\n", stc->exception.code);
		eprintf("\tFlags  : %08x\n", stc->exception.flags);
		eprintf("\tRecord : %016llx\n", stc->exception.ex_record);
		eprintf("\tAddr   : %016llx\n", stc->exception.ex_addr);
	}

	// r_print_hexdump(NULL, 0, stc, p->lenght, 16, 16);
}

static int
do_io_reply (wind_ctx_t *ctx, kd_packet_t *pkt)
{
	kd_ioc_t ioc;
	int ret;

	(void)pkt;

	printf("%s@%s:%d\n", __FUNCTION__, __FILE__, __LINE__);

	memset(&ioc, 0, sizeof(kd_ioc_t));

	ioc.req = 0x3430;
	ioc.ret = KD_RET_ENOENT;

	// r_print_hexdump(NULL, 0, &ioc, sizeof(ioc), 16, 16);

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_IO, (ctx->seq_id ^= 1), (ut8 *)&ioc,
			sizeof(kd_ioc_t), NULL, 0);
	if (ret != KD_E_OK)
		return R_FALSE;

	eprintf("Waiting for io_reply ack...\n");
	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return R_FALSE;
	eprintf("Ack received, restore flow\n");

	return R_TRUE;
}

int wind_wait_packet (wind_ctx_t *ctx, const ut32 type, kd_packet_t **p) {
	kd_packet_t *pkt;
	int ret, retries = 10;

	// r_sys_backtrace();

	pkt = NULL;

	do {
		free(pkt);
		// Try to read a whole packet
		ret = kd_read_packet(ctx->io_ptr, &pkt);
		// eprintf("kd_read_packet() = %i\n", ret);
		if (ret != KD_E_OK)
			break;

		// eprintf("Received %08x, expected %08x\n", pkt->type, type);
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

	p? *p = pkt: free(pkt);

	return KD_E_OK;
}

int
wind_read_ver (wind_ctx_t *ctx) {
	kd_req_t req;
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return R_FALSE;

	memset(&req, 0, sizeof(kd_req_t));

	req.req = 0x3146;
	req.cpu = ctx->cpu;

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (ut8 *)&req,
			sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK)
		return R_FALSE;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return R_FALSE;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_MANIP, &pkt);
	if (ret != KD_E_OK)
		return R_FALSE;

	kd_req_t *rr = PKT_REQ(pkt);

	/* LOG_PKT(pkt); */
	/* LOG_REQ(rr); */

	if (rr->ret) {
		eprintf("%s : req returned %08x\n", __FUNCTION__, rr->ret);
		free(pkt);
		return R_FALSE;
	}

	eprintf("Protocol version : %i.%i\n", rr->r_ver.proto_major, rr->r_ver.proto_minor);
	eprintf("Flags : %08x\n", rr->r_ver.flags);
	eprintf("Machine : %08x\n", rr->r_ver.machine);
	eprintf("Module list : %016llx\n", rr->r_ver.mod_addr);
	eprintf("Kernel : %016llx\n", rr->r_ver.dbg_addr);

#if 0
	ut32 ptr, base;

	wind_read_at(ctx, (ut8 *)&ptr, rr->r_ver.dbg_addr, 4);
	eprintf("Ptr : %08x\n", ptr);
	// This point to the debugger data block
	wind_read_at(ctx, (ut8 *)&ptr, ptr + 0x50, 4);
	eprintf("Process list head : %08x\n", ptr);

	struct llist {
		ut32 next;
		ut32 prev;
	} __attribute__((packed));

	// This points to the 'ActiveProcessLinks' list
	// winxp - (at 0x88)
	// win7  - (at 0xb8)
	base = ptr;
	do {
		struct llist l;
		ut8 buf[17];

		memset(buf, 0, sizeof(buf));
		wind_read_at(ctx, (ut8 *)&l, ptr, sizeof(struct llist));
		wind_read_at(ctx, (ut8 *)&buf, ptr + 0xEC, 16);

		buf[16] = '\0';

		eprintf("Next : %08x Prev : %08x\n", l.next, l.prev);
		eprintf("%s\n", buf);

		ptr = l.next;
	} while(ptr != base);
#if 0

	struct unis {
		ut16 lenght;
		ut16 max;
		ut32 ptr;
	} __attribute__((packed));

	struct mod {
		struct llist lo_list;
		struct llist mo_list;
		struct llist io_list;
		ut32 base;
		ut32 ep;
		ut32 size;
		struct unis fname;
		struct unis bname;
	} __attribute__((packed));

	struct mod m;

	ut32 ptr, base;
	wind_read_at(ctx->io_ptr, &ptr, rr->r_ver.mod_addr&0xffffffff, 4);
	base = rr->r_ver.mod_addr&0xffffffff;

	eprintf("Start @ %08x\n", ptr);

	while (ptr != base) {
		wind_read_at(ctx->io_ptr, &m, ptr, 0x30);

		eprintf("next : %08x\n", m.lo_list.next);
		eprintf("prev : %08x\n", m.lo_list.prev);
		eprintf("base : %08x\n", base);

		char tmp[m.fname.lenght + 1];
		wind_read_at(ctx->io_ptr, tmp, m.fname.ptr, m.fname.lenght);
		tmp[m.fname.lenght] = '\0';

		int i;
		for (i = 0; i < m.fname.lenght; i+=2)
			eprintf("%c", tmp[i]);
		eprintf("\n");

		ptr = m.lo_list.next;
	}
#endif
#endif

	free(pkt);

	return R_TRUE;
}

int
wind_sync (wind_ctx_t *ctx) {
	int ret;
	kd_packet_t *s;

	if (!ctx || !ctx->io_ptr)
		return R_FALSE;

	// Send the breakin packet
	iob_write(ctx->io_ptr, "b", 1);

	// Reset the host
	ret = kd_send_ctrl_packet(ctx->io_ptr, KD_PACKET_TYPE_RESET, 0);
	if (ret != KD_E_OK)
		return R_FALSE;

	// Wait for the response
	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_RESET, NULL);
	if (ret != KD_E_OK)
		return R_FALSE;

	// Syncronize with the first KD_PACKET_TYPE_STATE_CHANGE packet
	wind_wait_packet(ctx, KD_PACKET_TYPE_STATE_CHANGE, &s);

	// Reset the sequence id
	ctx->seq_id = 0x80800001;

	ctx->cpu = 0;
	ctx->cpu_count = PKT_STC(s)->cpu_count;
	// We're ready to go
	ctx->syncd = R_TRUE;

	free(s);

	eprintf("Sync done! (%i cpus found)\n", ctx->cpu_count);

	return R_TRUE;
}

int
wind_continue (wind_ctx_t *ctx) {
	kd_req_t req;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return R_FALSE;

	memset(&req, 0, sizeof(kd_req_t));

	req.req = 0x313C;
	req.cpu = ctx->cpu;

	req.ret = 0x10001;
	req.r_cont.reason = 0x10001;

	printf("Sending continue...\n");

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (ut8 *)&req,
			sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK)
		return R_FALSE;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return R_FALSE;

	printf("Done!\n");

	return R_TRUE;
}

int
wind_write_reg (wind_ctx_t *ctx, ut8 *buf, int size) {
	kd_packet_t *pkt;
	kd_req_t req;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return R_FALSE;

	memset(&req, 0, sizeof(kd_req_t));

	req.req = 0x3133;
	req.cpu = ctx->cpu;

	req.r_ctx.flags = 0x1003F;

	eprintf("Regwrite() size : %x\n", size);

	// *((ut32 *)buf) = 0x0001003F;

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (ut8 *)&req,
			sizeof(kd_req_t), buf, size);
	if (ret != KD_E_OK)
		return R_FALSE;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return R_FALSE;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_MANIP, &pkt);
	if (ret != KD_E_OK)
		return R_FALSE;

	kd_req_t *rr = PKT_REQ(pkt);

	// LOG_PKT(pkt);
	// LOG_REQ(rr);

	if (rr->ret) {
		eprintf("%s : req returned %08x\n", __FUNCTION__, rr->ret);
		free(pkt);
		return R_FALSE;
	}

	free(pkt);

	return size;
}

int
wind_read_reg (wind_ctx_t *ctx, ut8 *buf, int size) {
	kd_req_t req;
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return R_FALSE;

	memset(&req, 0, sizeof(kd_req_t));

	req.req = 0x3132;
	req.cpu = ctx->cpu;

	req.r_ctx.flags = 0x1003F;

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (ut8 *)&req,
			sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK)
		return R_FALSE;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return R_FALSE;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_MANIP, &pkt);
	if (ret != KD_E_OK)
		return R_FALSE;

	kd_req_t *rr = PKT_REQ(pkt);

	// LOG_PKT(pkt);
	// LOG_REQ(rr);
	// eprintf("Context tag : %08x\n", *((ut32 *)rr->data));

	if (rr->ret) {
		eprintf("%s : req returned %08x\n", __FUNCTION__, rr->ret);
		free(pkt);
		return R_FALSE;
	}

	// memset(buf, 0, size);
	// r_print_hexdump(NULL, 0, rr->data, pkt->lenght - sizeof(kd_req_t), 16, 16);
	// eprintf("reg() size %i (%i)\n", pkt->lenght - sizeof(kd_req_t), size);
	memcpy(buf, rr->data, size);

	free(pkt);

	return size;
}

int
wind_bkpt (wind_ctx_t *ctx, const ut64 addr, const int set, const int hw, int *handle) {
	kd_req_t req;
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return R_FALSE;

	memset(&req, 0, sizeof(kd_req_t));

	req.req = set? 0x3134: 0x3135;
	req.cpu = ctx->cpu;

	if (set)
		req.r_set_bp.addr = addr;
	else
		req.r_del_bp.handle = *handle;

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (ut8 *)&req,
			sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK)
		return R_FALSE;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return R_FALSE;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_MANIP, &pkt);
	if (ret != KD_E_OK)
		return R_FALSE;

	kd_req_t *rr = PKT_REQ(pkt);

	// LOG_PKT(pkt);
	// LOG_REQ(rr);

	if (rr->ret) {
		eprintf("%s : req returned %08x\n", __FUNCTION__, rr->ret);
		free(pkt);
		return R_FALSE;
	}

	*handle = rr->r_set_bp.handle;

	ret = !!rr->ret;

	free(pkt);

	return ret;
}

int
wind_read_at (wind_ctx_t *ctx, ut8 *buf, const ut64 offset, const int count) {
	kd_req_t req;
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return R_FALSE;

	memset(&req, 0, sizeof(kd_req_t));

	req.req = 0x3130;
	req.cpu = ctx->cpu;

	req.r_mem.addr = offset;
	req.r_mem.lenght = R_MIN(count, KD_MAX_PAYLOAD);

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (ut8 *)&req,
			sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK)
		return R_FALSE;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return R_FALSE;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_MANIP, &pkt);
	if (ret != KD_E_OK)
		return R_FALSE;

	kd_req_t *rr = PKT_REQ(pkt);

	// LOG_PKT(pkt);
	// LOG_REQ(rr);
	// eprintf("read @ %08x : %08x\n", offset, rr->r_mem.read);

	if (rr->ret) {
		eprintf("%s : req returned %08x\n", __FUNCTION__, rr->ret);
		free(pkt);
		return R_FALSE;
	}

	memcpy(buf, rr->data, rr->r_mem.read);

	ret = rr->r_mem.read;

	free(pkt);

	return ret;
}

int
wind_write_at (wind_ctx_t *ctx, ut8 *buf, const ut64 offset, const int count) {
	kd_packet_t *pkt;
	kd_req_t req;
	int ret;
	int payload;

	if (!ctx || !ctx->io_ptr || !ctx->syncd)
		return R_FALSE;

	payload = R_MIN(count, KD_MAX_PAYLOAD - sizeof(kd_req_t));

	// eprintf("Offset : %016x\n", offset);
	// eprintf("Payload size : %i bytes\n", payload);

	memset(&req, 0, sizeof(kd_req_t));

	req.req = 0x3131;
	req.cpu = ctx->cpu;

	req.r_mem.addr = offset;
	req.r_mem.lenght = payload;

	ret = kd_send_data_packet(ctx->io_ptr, KD_PACKET_TYPE_MANIP, (ctx->seq_id ^= 1), (ut8 *)&req,
			sizeof(kd_req_t), buf, payload);
	if (ret != KD_E_OK)
		return R_FALSE;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_ACK, NULL);
	if (ret != KD_E_OK)
		return R_FALSE;

	ret = wind_wait_packet(ctx, KD_PACKET_TYPE_MANIP, &pkt);
	if (ret != KD_E_OK)
		return R_FALSE;

	kd_req_t *rr = PKT_REQ(pkt);

	// LOG_PKT(pkt);
	// LOG_REQ(rr);

	if (rr->ret) {
		eprintf("%s : req returned %08x\n", __FUNCTION__, rr->ret);
		free(pkt);
		return R_FALSE;
	}

	ret = rr->r_mem.read;

	free(pkt);

	return ret;
}
