#include <r_util.h>
#include "transport.h"
#include "kd.h"
#include "winkd.h"
#include "minunit.h"

#if R2__UNIX__ && !__wasi__

// Feeds a fixed byte stream to kd_read_packet and swallows every write (acks).
typedef struct {
	const ut8 *buf;
	size_t len;
	size_t pos;
} mock_feed;

static int mock_read(void *fp, uint8_t *buf, const uint64_t count, const int timeout) {
	mock_feed *f = fp;
	size_t left = f->len - f->pos;
	size_t n = R_MIN ((size_t)count, left);
	if (n == 0) {
		return -1;
	}
	memcpy (buf, f->buf + f->pos, n);
	f->pos += n;
	return (int)n;
}

static int mock_write(void *fp, const uint8_t *buf, const uint64_t count, const int timeout) {
	return (int)count;
}

static bool mock_close(void *fp) {
	return true;
}

static io_backend_t mock_backend = {
	.name = "mock",
	.type = KD_IO_NET, // net has no 0xAA pipe trailer
	.read = mock_read,
	.write = mock_write,
	.close = mock_close,
};

// Build a KD data packet header with the given type and payload length.
static void put_packet(ut8 *out, ut16 type, ut16 length, const ut8 *payload, ut32 checksum) {
	r_write_le32 (out, KD_PACKET_DATA);
	r_write_le16 (out + 4, type);
	r_write_le16 (out + 6, length);
	r_write_le32 (out + 8, 0); // id
	r_write_le32 (out + 12, checksum);
	if (payload && length) {
		memcpy (out + 16, payload, length);
	}
}

static WindCtx *ctx_with_feed(mock_feed *feed) {
	io_desc_t *desc = io_desc_new (&mock_backend, feed);
	return winkd_ctx_new (desc);
}

// A STATE_MANIPULATE data packet whose payload is shorter than kd_req_t must be
// rejected: every PKT_REQ consumer reads a full kd_req_t out of pkt->data, so a
// truncated payload is a heap out-of-bounds read.
static bool test_winkd_rejects_truncated_req(void) {
	ut8 pkt[16];
	put_packet (pkt, KD_PACKET_TYPE_STATE_MANIPULATE, 0, NULL, 0);
	mock_feed feed = { pkt, sizeof (pkt), 0 };
	WindCtx *ctx = ctx_with_feed (&feed);
	mu_assert_notnull (ctx, "ctx");

	kd_packet_t *got = NULL;
	int ret = winkd_wait_packet (ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &got);
	mu_assert_neq (ret, (int)KD_E_OK, "truncated STATE_MANIPULATE must not be accepted");
	mu_assert_null (got, "no packet returned for a truncated payload");

	winkd_ctx_free (&ctx);
	mu_end;
}

// Same guard for the STATE_CHANGE64 stop packet, cast to kd_stc_64 by callers.
static bool test_winkd_rejects_truncated_stc(void) {
	ut8 pkt[16];
	put_packet (pkt, KD_PACKET_TYPE_STATE_CHANGE64, 0, NULL, 0);
	mock_feed feed = { pkt, sizeof (pkt), 0 };
	WindCtx *ctx = ctx_with_feed (&feed);
	mu_assert_notnull (ctx, "ctx");

	kd_packet_t *got = NULL;
	int ret = winkd_wait_packet (ctx, KD_PACKET_TYPE_STATE_CHANGE64, &got);
	mu_assert_neq (ret, (int)KD_E_OK, "truncated STATE_CHANGE64 must not be accepted");
	mu_assert_null (got, "no packet returned for a truncated payload");

	winkd_ctx_free (&ctx);
	mu_end;
}

// A full-size kd_req_t payload still parses and is handed back to the caller,
// which then reads the whole structure safely.
static bool test_winkd_accepts_full_req(void) {
	ut8 payload[sizeof (kd_req_t)];
	memset (payload, 0, sizeof (payload));
	ut32 cksum = kd_data_checksum (payload, sizeof (payload));
	ut8 pkt[16 + sizeof (kd_req_t)];
	put_packet (pkt, KD_PACKET_TYPE_STATE_MANIPULATE, sizeof (kd_req_t), payload, cksum);
	mock_feed feed = { pkt, sizeof (pkt), 0 };
	WindCtx *ctx = ctx_with_feed (&feed);
	mu_assert_notnull (ctx, "ctx");

	kd_packet_t *got = NULL;
	int ret = winkd_wait_packet (ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &got);
	mu_assert_eq (ret, (int)KD_E_OK, "a full kd_req_t payload is accepted");
	mu_assert_notnull (got, "packet returned");
	if (got) {
		kd_req_t *rr = (kd_req_t *)got->data;
		volatile ut32 touch = rr->ret + (ut32)rr->r_ver.dbg_addr;
		(void)touch;
		free (got);
	}

	winkd_ctx_free (&ctx);
	mu_end;
}

#endif

int all_tests(void) {
#if R2__UNIX__ && !__wasi__
	mu_run_test (test_winkd_rejects_truncated_req);
	mu_run_test (test_winkd_rejects_truncated_stc);
	mu_run_test (test_winkd_accepts_full_req);
	return tests_passed != tests_run;
#else
	return 0;
#endif
}

int main(int argc, char **argv) {
	return all_tests ();
}
