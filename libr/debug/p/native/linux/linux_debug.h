/*  __
 -=(o '.
    \.-.\
    /|  \\
    '|  ||
     _\_):,_
*/

#include <limits.h>
#include <sys/ptrace.h>

struct user_regs_struct_x86_64 {
  ut64 r15; ut64 r14; ut64 r13; ut64 r12; ut64 rbp; ut64 rbx; ut64 r11;
  ut64 r10; ut64 r9; ut64 r8; ut64 rax; ut64 rcx; ut64 rdx; ut64 rsi;
  ut64 rdi; ut64 orig_rax; ut64 rip; ut64 cs; ut64 eflags; ut64 rsp;
  ut64 ss; ut64 fs_base; ut64 gs_base; ut64 ds; ut64 es; ut64 fs; ut64 gs;
};

struct user_regs_struct_x86_32 {
  ut32 ebx; ut32 ecx; ut32 edx; ut32 esi; ut32 edi; ut32 ebp; ut32 eax;
  ut32 xds; ut32 xes; ut32 xfs; ut32 xgs; ut32 orig_eax; ut32 eip;
  ut32 xcs; ut32 eflags; ut32 esp; ut32 xss;
};

#if __ANDROID__

#if __arm64__ || __aarch64__
#define R_DEBUG_REG_T struct user_pt_regs

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

#else
#define R_DEBUG_REG_T struct pt_regs
#endif

#else

#include <sys/user.h>
#if __i386__ || __x86_64__
#define R_DEBUG_REG_T struct user_regs_struct
#elif __arm64__ || __aarch64__
#define R_DEBUG_REG_T struct user_pt_regs
#elif __arm__
#define R_DEBUG_REG_T struct user_regs
#elif __mips__

#include <sys/ucontext.h>
typedef ut64 mips64_regs_t [274];
#define R_DEBUG_REG_T mips64_regs_t
#endif
#endif

/* For the maps */
typedef struct linux_map_entry {
        unsigned long int start_addr;
        unsigned long int end_addr;
        unsigned int perms;
        unsigned long int offset;
        unsigned long int inode;
        char *name;
        struct linux_map_entry *n;
}linux_map_entry_t;

#define ADD_MAP(p)      do {                                                    \
                                if(me_head == NULL) {                        	\
                                        me_head = p;                  		\
                                        me_tail = p;                         	\
                                } else {                                        \
                                        p->n = NULL;                            \
                                        me_tail->n = p;                      	\
                                        me_tail = p;                         	\
                                }                                               \
                        } while(0);                                             \
/**/


//API
int linux_step (RDebug *dbg);
int linux_attach (RDebug *dbg, int pid);
RDebugInfo *linux_info (RDebug *dbg, const char *arg);
RList *linux_thread_list (int pid, RList *list);
int linux_reg_read (RDebug *dbg, int type, ut8 *buf, int size);
int linux_reg_write (RDebug *dbg, int type, const ut8 *buf, int size);
RList *linux_desc_list (int pid);
int linux_handle_signals (RDebug *dbg);
const char *linux_reg_profile (RDebug *dbg);
