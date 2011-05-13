#ifndef _INCLUDE_GDBWRAPPER_H_
#define _INCLUDE_GDBWRAPPER_H_

/* File to include to use the wrapper. */

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

Bool             gdbwrap_erroroccured(gdbwrap_t *desc);
Bool             gdbwrap_cmdnotsup(gdbwrap_t *desc);
unsigned         gdbwrap_atoh(const char * str, unsigned size);
unsigned         gdbwrap_lastsignal(gdbwrap_t *desc);
Bool             gdbwrap_is_active(gdbwrap_t *desc);
gdbwrapworld_t   gdbwrap_current_set(gdbwrap_t *world);
gdbwrap_t        *gdbwrap_current_get(void);
gdbwrap_t        *gdbwrap_init(int fd, ut32 num, ut32 size);
void             gdbwrap_close(gdbwrap_t *desc);
void             gdbwrap_hello(gdbwrap_t *desc);
void             gdbwrap_bye(gdbwrap_t *desc);
void             gdbwrap_reason_halted(gdbwrap_t *desc);
char             *gdbwrap_own_command(gdbwrap_t *desc, char *command);
ut8		 *gdbwrap_readgenreg(gdbwrap_t *desc);
void             gdbwrap_continue(gdbwrap_t *desc);
void             gdbwrap_setbp(gdbwrap_t *desc, la32 linaddr, void *datasaved);
int		 gdbwrap_simplesetbp(gdbwrap_t *desc, la32 linaddr);
void             gdbwrap_delbp(gdbwrap_t *desc, la32 linaddr, void *datasaved);
int             gdbwrap_simpledelbp(gdbwrap_t *desc, la32 linaddr);
char             *gdbwrap_readmem(gdbwrap_t *desc, la32 linaddr, unsigned bytes);
void             gdbwrap_writemem(gdbwrap_t *desc, la32 linaddr, void *value,
				  unsigned bytes);
void             gdbwrap_writereg(gdbwrap_t *desc, ureg32 regnum, la32 val);
char             *gdbwrap_shipallreg(gdbwrap_t *desc);
void             gdbwrap_ctrl_c(gdbwrap_t *desc);
void             gdbwrap_signal(gdbwrap_t *desc, int signal);
void             gdbwrap_stepi(gdbwrap_t *desc);
char             *gdbwrap_remotecmd(gdbwrap_t *desc, char *cmd);
u_char           gdbwrap_lasterror(gdbwrap_t *desc);
gdbmemap_t       gdbwrap_memorymap_get();
ut64		 gdbwrap_getreg(gdbwrap_t *desc, ut32 idx);
void		 gdbwrap_getreg_buffer(gdbwrap_t *desc, unsigned char *buf, ut32 size);
void		 gdbwrap_setreg(gdbwrap_t *desc, ut32 idx, ut64 value);
void		 gdbwrap_setreg_buffer(gdbwrap_t *desc, const unsigned char *buf, ut32 size);
#endif
