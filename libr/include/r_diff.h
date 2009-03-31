#ifndef _INCLUDE_DIFF_H_
#define _INCLUDE_DIFF_H_

#include <r_types.h>
#include <r_util.h>

struct r_diff_op_t {
	/* file A */
	u64 a_off;
	const u8 *a_buf;
	int a_len;

	/* file B */
	u64 b_off;
	const u8 *b_buf;
	int b_len;
};

struct r_diff_t {
	u64 off_a;
	u64 off_b;
	int delta;
	void *user;
	int (*callback)(struct r_diff_t *d, void *user,
		struct r_diff_op_t *op);
};

struct r_diff_t *r_diff_new(u64 off_a, u64 off_b);
int r_diff_init(struct r_diff_t *d, u64 off_a, u64 off_b);
struct r_diff_t *r_diff_free(struct r_diff_t *d);
int r_diff_buffers(struct r_diff_t *d, const u8 *a, u32 la, const u8 *b, u32 lb);
int r_diff_set_callback(struct r_diff_t *d,
	int (*callback)(struct r_diff_t *d, void *user, struct r_diff_op_t *op),
	void *user);
int r_diff_buffers_distance(struct r_diff_t *d,
	const u8 *a, u32 la, const u8 *b, u32 lb, u32 *distance,
	float *similarity);

#endif
