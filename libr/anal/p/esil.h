#ifndef _UDIS86_ESIL_H
#define _UDIS86_ESIL_H

#include "udis86/extern.h"
/* This may be useful for other architectures */
#define esilprintf(op, fmt, arg...) r_strbuf_setf (&op->esil, fmt, ##arg)

#define UDIS86_ESIL_ARGUMENTS const UDis86OPInfo *info, RAnalOp *op, const char *dst, const char *src, const char *src2

typedef struct udis86_op_info {
	ut64 n;
	int  bits;
	ut64 bitmask;
	int  regsz;
	int  oplen;
	const char *pc;
	const char *sp;
	const char *bp;
} UDis86OPInfo;

typedef struct udis86_esil_t {
        int argc;
        void (*callback) (UDIS86_ESIL_ARGUMENTS);
} UDis86Esil;

#define _JOIN(a1, a2) a1 ## a2
#define JOIN(a1, a2) _JOIN (a1, a2)

#define UDIS86_ESIL_HANDLER(name) JOIN (JOIN (__x86_, name), _to_esil)
#define UDIS86_ESIL_PROTO(name) void UDIS86_ESIL_HANDLER (name) (UDIS86_ESIL_ARGUMENTS)
#define UDIS86_ESIL(name, fmt, arg...) UDIS86_ESIL_PROTO (name) { esilprintf (op, fmt, ##arg); }

UDis86Esil *udis86_esil_get_handler (enum ud_mnemonic_code);

#endif /* _UDIS86_ESIL_H */
