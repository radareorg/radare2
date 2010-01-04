#ifndef _INCLUDE_DIFF_H_
#define _INCLUDE_DIFF_H_

#include <r_types.h>
#include <r_util.h>

typedef struct r_diff_op_t {
	/* file A */
	ut64 a_off;
	const ut8 *a_buf;
	int a_len;

	/* file B */
	ut64 b_off;
	const ut8 *b_buf;
	int b_len;
} rDiffOp;

typedef struct r_diff_t {
	ut64 off_a;
	ut64 off_b;
	int delta;
	void *user;
	int (*callback)(struct r_diff_t *d, void *user,
		struct r_diff_op_t *op);
} rDiff;

/* XXX: this api needs to be reviewed , constructor with offa+offb?? */
#ifdef R_API
R_API struct r_diff_t *r_diff_new(ut64 off_a, ut64 off_b);
R_API int r_diff_init(struct r_diff_t *d, ut64 off_a, ut64 off_b);
R_API struct r_diff_t *r_diff_free(struct r_diff_t *d);

R_API int r_diff_buffers(struct r_diff_t *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb);
R_API int r_diff_buffers_static(struct r_diff_t *d, const ut8 *a, int la, const ut8 *b, int lb);
R_API int r_diff_buffers_delta(struct r_diff_t *d, const ut8 *a, int la, const ut8 *b, int lb);
R_API int r_diff_buffers(struct r_diff_t *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb);
R_API int r_diff_set_callback(struct r_diff_t *d,
	int (*callback)(struct r_diff_t *d, void *user, struct r_diff_op_t *op),
	void *user);
R_API int r_diff_buffers_distance(struct r_diff_t *d,
	const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance,
	double *similarity);
/* static method !??! */
R_API int r_diff_lines(const char *file1, const char *sa, int la, const char *file2, const char *sb, int lb);
R_API int r_diff_set_delta(struct r_diff_t *d, int delta);
#endif

#endif
