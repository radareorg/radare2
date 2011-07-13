#ifndef _INCLUDE_GDBWRAPPER_H_
#define _INCLUDE_GDBWRAPPER_H_

/* File to include to use the wrapper. */

#ifndef IRAPI
#define IRAPI
#endif

#include "r_types.h"
#if __UNIX__
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#endif
#if __WINDOWS__
#include <windows.h>
#endif
#include <errno.h>
#include "libaspect.h"

#if __WINDOWS__
typedef unsigned char uint8_t;
#endif

typedef struct  gdbwrap_gdbreg32
{
  ureg32   eax;
  ureg32   ecx;
  ureg32   edx;
  ureg32   ebx;
  ureg32   esp;
  ureg32   ebp;
  ureg32   esi;
  ureg32   edi;
  ureg32   eip;
  ureg32   eflags;
  ureg32   cs;
  ureg32   ss;
  ureg32   ds;
  ureg32   es;
  ureg32   fs;
  ureg32   gs;
} gdbwrap_gdbreg32;


typedef struct gdbwrap_t
{
  char             *packet;
  int              fd;
  unsigned         max_packet_size;
  ut8 		   *regs;
  unsigned	   num_registers;
  unsigned 	   reg_size;
  Bool             is_active;
  Bool             erroroccured;
  Bool             interrupted;
  Bool             pmode;
} gdbwrap_t;

typedef struct meminfo_t
{
  char             *type;
  u_int              start;
  u_int              length;
  u_int              blocksize;
} meminfo_t;

typedef struct gdbmemap_t
{
  meminfo_t        ram;
  meminfo_t        rom;
  meminfo_t        flash;
} gdbmemap_t;


typedef struct
{
  gdbwrap_t *gdbwrapptr;
} gdbwrapworld_t;

IRAPI Bool             gdbwrap_erroroccured(gdbwrap_t *desc);
IRAPI Bool             gdbwrap_cmdnotsup(gdbwrap_t *desc);
IRAPI unsigned         gdbwrap_atoh(const char * str, unsigned size);
IRAPI unsigned         gdbwrap_lastsignal(gdbwrap_t *desc);
IRAPI Bool             gdbwrap_is_active(gdbwrap_t *desc);
IRAPI gdbwrapworld_t   gdbwrap_current_set(gdbwrap_t *world);
IRAPI gdbwrap_t        *gdbwrap_current_get(void);
IRAPI gdbwrap_t        *gdbwrap_init(int fd, ut32 num, ut32 size);
IRAPI void             gdbwrap_close(gdbwrap_t *desc);
IRAPI void             gdbwrap_hello(gdbwrap_t *desc);
IRAPI void             gdbwrap_bye(gdbwrap_t *desc);
IRAPI void             gdbwrap_reason_halted(gdbwrap_t *desc);
IRAPI char             *gdbwrap_own_command(gdbwrap_t *desc, char *command);
IRAPI ut8		 *gdbwrap_readgenreg(gdbwrap_t *desc);
IRAPI void             gdbwrap_continue(gdbwrap_t *desc);
IRAPI void             gdbwrap_setbp(gdbwrap_t *desc, la32 linaddr, void *datasaved);
IRAPI int		 gdbwrap_simplesetbp(gdbwrap_t *desc, la32 linaddr);
IRAPI void             gdbwrap_delbp(gdbwrap_t *desc, la32 linaddr, void *datasaved);
IRAPI int             gdbwrap_simpledelbp(gdbwrap_t *desc, la32 linaddr);
IRAPI char             *gdbwrap_readmem(gdbwrap_t *desc, la32 linaddr, unsigned bytes);
IRAPI void             gdbwrap_writemem(gdbwrap_t *desc, la32 linaddr, void *value, unsigned bytes);
IRAPI void             gdbwrap_writereg(gdbwrap_t *desc, ureg32 regnum, la32 val);
IRAPI char             *gdbwrap_shipallreg(gdbwrap_t *desc);
IRAPI void             gdbwrap_ctrl_c(gdbwrap_t *desc);
IRAPI void             gdbwrap_signal(gdbwrap_t *desc, int signal);
IRAPI void             gdbwrap_stepi(gdbwrap_t *desc);
IRAPI char             *gdbwrap_remotecmd(gdbwrap_t *desc, char *cmd);
IRAPI u_char           gdbwrap_lasterror(gdbwrap_t *desc);
IRAPI gdbmemap_t       gdbwrap_memorymap_get();
IRAPI ut64 gdbwrap_getreg(gdbwrap_t *desc, ut32 idx);
IRAPI void gdbwrap_getreg_buffer(gdbwrap_t *desc, unsigned char *buf, ut32 size);
IRAPI void gdbwrap_setreg(gdbwrap_t *desc, ut32 idx, ut64 value);
IRAPI void gdbwrap_setreg_buffer(gdbwrap_t *desc, const unsigned char *buf, ut32 size);
#endif
