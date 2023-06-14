#include <r_types.h>

#define	GB_IS_VIRTUAL(x)	(x/0x10000)
#define GB_R_MBC_ADDR(x)	(x%0x10000)
#define GB_SOFTCAST(x,y)	(x+(y*0x100))
#define GB_IS_RAM_DST(x,y)	(GB_SOFTCAST(x,y)/0x8000)
#define	GB_VBANK_ADDR(x)	((x/0x10000)*0x10000+0x4000)
#define GB_IB_DST(x,y,z)	(GB_SOFTCAST(x,y)-0x4000+GB_VBANK_ADDR(z))
#define GB_IS_VBANK(x)		(x>(GB_VBANK_ADDR(x)-1) && x<(GB_VBANK_ADDR(x)+0x4000))
#define GB_IS_VBANK_DST(x,y)	(GB_IS_VBANK(GB_SOFTCAST(x,y)))
