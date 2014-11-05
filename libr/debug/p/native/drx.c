#include <r_types.h>

/* -------------------- drx.h ------------------- */
#define DRXN 8
#define DR_STATUS 6
#define DR_CONTROL 7

#define DR_LOCAL_ENABLE_SHIFT   0 /* Extra shift to the local enable bit.  */
#define DR_GLOBAL_ENABLE_SHIFT  1 /* Extra shift to the global enable bit.  */
#define DR_ENABLE_SIZE          2 /* Two enable bits per debug register.  */

/* Fields reserved by Intel.  This includes the GD (General Detect
   Enable) flag, which causes a debug exception to be generated when a
   MOV instruction accesses one of the debug registers.

   FIXME: My Intel manual says we should use 0xF800, not 0xFC00.  */
#define DR_CONTROL_RESERVED     (0xFC00)

#define I386_DR_CONTROL_MASK    (~DR_CONTROL_RESERVED)

#define DR_LOCAL_SLOWDOWN       (0x100)
#define DR_GLOBAL_SLOWDOWN      (0x200)

/* DR7 fields */
/* How many bits to skip in DR7 to get to R/W and LEN fields.  */
#define DR_CONTROL_SHIFT 16
/* How many bits in DR7 per R/W and LEN field for each watchpoint.  */
#define DR_CONTROL_SIZE 4

#define DR_RW_EXECUTE   (0x0)   /* Break on instruction execution.  */
#define DR_RW_WRITE     (0x1)   /* Break on data writes.  */
#define DR_RW_IORW      (0x2)   /* Break on I/O reads or writes (not supported (2001)  */
#define DR_RW_READ      (0x3)   /* Break on data reads or writes.  */

/* Debug registers' indices.  */
#define DR_NADDR        4       /* The number of debug address registers.  */
#define DR_STATUS       6       /* Index of debug status register (DR6).  */
#define DR_CONTROL      7       /* Index of debug control register (DR7). */

// 32 for 32bits and 64 for 64bits
#define drxt size_t

#define DR_LEN_1 (0<<2) /* 1-byte region watch or breakpoint.  */
#define DR_LEN_2 (1<<2) /* 2-byte region watch.  */
#define DR_LEN_4 (3<<2) /* 4-byte region watch.  */
#define DR_LEN_8 (2<<2) /* 8-byte region watch (AMD64).  */

#define I386_DR_CONTROL_MASK    (~DR_CONTROL_RESERVED)

/* unused */
#define I386_DR_VACANT(control, i) \
  ((control & (3 << (DR_ENABLE_SIZE * (i)))) == 0)
/* local/global */
#define I386_DR_LOCAL_ENABLE(control, i) \
  control |= (1 << (DR_LOCAL_ENABLE_SHIFT + DR_ENABLE_SIZE * (i)))
#define I386_DR_GLOBAL_ENABLE(control, i) \
  control |= (1 << (DR_GLOBAL_ENABLE_SHIFT + DR_ENABLE_SIZE * (i)))

#define I386_DR_IS_LOCAL_ENABLED(control, i) \
  (control & (1 << (DR_LOCAL_ENABLE_SHIFT + DR_ENABLE_SIZE * (i))))
/* enable/disable */
#define I386_DR_IS_ENABLED(control, i) \
  control & (3 << (DR_ENABLE_SIZE * (i)))

#define I386_DR_ENABLE(control, i) \
  control |= (3 << (DR_ENABLE_SIZE * (i)))
#define I386_DR_DISABLE(control, i) \
  control &= ~(3 << (DR_ENABLE_SIZE * (i)))

#define I386_DR_SET_RW_LEN(control, i,rwlen) \
  do { \
    control &= ~(0x0f << (DR_CONTROL_SHIFT+DR_CONTROL_SIZE*(i)));   \
    control |= ((rwlen) << (DR_CONTROL_SHIFT+DR_CONTROL_SIZE*(i))); \
  } while (0)
#define I386_DR_GET_RW_LEN(control, i) \
  ((control >> (DR_CONTROL_SHIFT + DR_CONTROL_SIZE * (i))) & 0x0f)

/* ----------------------------- */

int drx_set(drxt *drx, int n, ut64 addr, int len, int rwx, int global) {
	ut32 control = drx[DR_CONTROL];
	if (n<0 || n>4) {
		eprintf ("Invalid DRX index (0-4)\n");
		return R_FALSE;
	}
	switch (rwx) {
		case 1: rwx=0; break;
		case 2: rwx=1; break;
		case 4: rwx=2; break;
		default:
			rwx=0;
	}
	switch (len) {
	case 1: len = 0; break;
	case 2: len = 1<<2; break;
	case 4: len = 3<<2; break;
	case 8: len = 2<<2; break; // AMD64 only
	default:
		eprintf ("Invalid DRX length (%d) must be 1, 2, 4, 8 bytes\n", len);
		return R_FALSE;
	}
	I386_DR_SET_RW_LEN (control, n, len|rwx);
	if (global) {
		I386_DR_GLOBAL_ENABLE (control, n);
  		//control |= DR_GLOBAL_SLOWDOWN;
	} else {
		I386_DR_LOCAL_ENABLE (control, n);
  		//control |= DR_LOCAL_SLOWDOWN; // XXX: This is wrong
	}
  	control &= I386_DR_CONTROL_MASK;
	drx[n] = addr;
//eprintf ("drx[DR_CONTROL] = %x \n", drx[DR_CONTROL]);	
	drx[DR_CONTROL] = control;
//eprintf ("CONTROL = %x\n", control);


	return R_TRUE;
}

ut64 drx_get(drxt *drx, int n, int *rwx, int *len, int *global, int *enabled) {
	int ret = I386_DR_GET_RW_LEN (drx[DR_CONTROL], n);
	if (global) *global = I386_DR_IS_LOCAL_ENABLED (drx[7], n);
	if (len) {
		switch ((ret&3)<<2) {
		case DR_LEN_1: *len = 1; break;
		case DR_LEN_2: *len = 2; break;
		case DR_LEN_4: *len = 4; break;
		case DR_LEN_8: *len = 8; break;
		default: *len = 0; break;
		}
	}
	if (enabled) *enabled = I386_DR_IS_ENABLED (drx[7], n);
	if (rwx) *rwx = ret & 0x3;
	return (ut64)drx[n];
}

int drx_next(drxt *drx) {
	int i;
	for(i=0; i<4; i++)
		if (!drx[i])
			return i;
	return -1;
}

void drx_list(drxt *drx) {
	ut64 addr;
	int i, rwx, len, g, en;
	for (i=0; i<8; i++) {
		if (i==4 || i == 5) 
			continue;
		rwx = len = g = en = 0;
		addr = drx_get (drx, i, &rwx, &len, &g, &en);
		printf ("%c dr%d %c%c 0x%08"PFMT64x" %d\n",
			en?'*':'-', i, g?'G':'L',
			(rwx==DR_RW_READ)?'r':
			(rwx==DR_RW_WRITE)?'w':
			(rwx==DR_RW_EXECUTE)?'x':
			(rwx==DR_RW_IORW)?'i':'?',
			addr, len);
	}
}

void drx_init(drxt *r) {
	memset (r, 0, sizeof (drxt)*(DRXN+1));
}

void drx_enable(drxt *r, int n, int enabled) {
	if (enabled) I386_DR_ENABLE (r[DR_CONTROL], n);
	else I386_DR_DISABLE (r[DR_CONTROL], n);
}

#if MAIN
int main() {
	drxt regs[DRXN+1];
	drx_init (regs);
	drx_set (regs, 1, 0x8048123, 1, DR_RW_EXECUTE, 0);
	drx_set (regs, 0, 0x8048123, 4, DR_RW_READ, 1);
	//drx_enable (regs, 0, R_TRUE);
//	drx_enable (regs, 0, R_FALSE);
	drx_list (regs);
}
#endif
