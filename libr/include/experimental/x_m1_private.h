#ifndef X_M1_PRIVATE
#define X_M1_PRIVATE

#ifdef __cplusplus
extern "C" {
#endif

#ifndef UNIT_TEST
  #define TEST_STATIC static
#else
  #define TEST_STATIC R_API
#endif

typedef struct r_bin_x_s1_t {
	ut64 off;
	bool start;
	int s_id;
} RBinXS1;

typedef struct r_bin_x_s2_t {
	ut64 from;
	ut64 to;
	int s_id;
} RBinXS2;

typedef struct r_bin_x_s3_t {
	int l;
	int *s;
	ut64 off;
} RBinXS3;

typedef struct r_bin_x_s4_t {
	ut64 from;
	ut64 to;
	int *s;
	int l;
} RBinXS4;

typedef struct r_bin_x_s5_t {
	RBinXS4 *d;
	int u;
	RBinXS4 *sections;
	int lru;
} RBinXS5;

typedef int (*RBinXComp) (const void *a, const void *b);

TEST_STATIC void r_bin_x_f2 (RBinXS1 *b, int n, RBinXS3 **out, int *out_len);
TEST_STATIC int _r_bin_x_f2 (RBinXS1 *b, int n, int dry, RBinXS3 **out, int out_len);
TEST_STATIC int r_bin_x_f3 (RBinXS3 *c, int m, RBinXS4 **out);
TEST_STATIC void r_bin_x_f1 (RBinObject *o);
TEST_STATIC void r_bin_x_f5 (RBinObject *o);
TEST_STATIC void r_bin_x_f6_bt (RBinXS5 *e, ut64 off, int va);
TEST_STATIC RBinXS4 * r_bin_x_f8_get_all (RBinXS5 *e, int va);
TEST_STATIC RBinSection *r_bin_x_f7_get_first (RBinObject *o, int va);
TEST_STATIC int r_bin_x_cmp1_less (RBinXS1 const *x, RBinXS1 const *y);
TEST_STATIC int r_bin_x_cmp2 (RBinXS1 const *x, RBinXS1 const *y);
TEST_STATIC int r_bin_x_cmp3 (RBinXS4 const *d, ut64 const *off);
TEST_STATIC int r_bin_x_binary_search (void *b, void *e, int t_s, RBinXComp c, void *g);

TEST_STATIC int x_m1_status (RBinObject *o);

#ifdef TEST_STATIC
R_API int r_bin_x_cmp3_count;
#endif TEST_STATIC

#ifdef __cplusplus
}
#endif

#endif
