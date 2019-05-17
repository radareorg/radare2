/*_______
 |   |   |
 |___|___|
 |   |   |
 |___|___|
*/

#include <r_types.h>
#include <r_debug.h>

// APIs
int w32_init(RDebug *dbg);

int w32_reg_read(RDebug *dbg, int type, ut8 *buf, int size);
int w32_reg_write(RDebug *dbg, int type, const ut8 *buf, int size);

int w32_attach(RDebug *dbg, int pid);
int w32_step(RDebug *dbg);

int w32_continue(RDebug *dbg, int pid, int tid, int sig);
RDebugMap *w32_map_alloc(RDebug *dbg, ut64 addr, int size);
int w32_map_dealloc (RDebug *dbg, ut64 addr, int size);
int w32_map_protect(RDebug *dbg, ut64 addr, int size, int perms);
RDebugInfo *w32_info(RDebug *dbg, const char *arg);
