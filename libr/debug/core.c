/* radare - LGPL - Copyright 2009-2015 - kur0 */

#include <r_debug.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>

#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/machine.h>
#include <mach/thread_status.h>
#include <mach/vm_region.h>

#include <mach-o/loader.h>

// TODO: Put this code in an if that checks if the target is a mach kernel.

typedef struct {
  st32 flavor;
  mach_msg_type_number_t count;
} coredump_thread_state_flavor_t;

#if defined (__ppc__)

static coredump_thread_state_flavor_t
thread_flavor_array[] = {
    { PPC_THREAD_STATE,    PPC_THREAD_STATE_COUNT    },
    { PPC_FLOAT_STATE,     PPC_FLOAT_STATE_COUNT     },
    { PPC_EXCEPTION_STATE, PPC_EXCEPTION_STATE_COUNT },
    { PPC_VECTOR_STATE,    PPC_VECTOR_STATE_COUNT    },
};

static int coredump_nflavors = 4;

#elif defined (__ppc64__)

coredump_thread_state_flavor_t
thread_flavor_array[] = {
    { PPC_THREAD_STATE64,    PPC_THREAD_STATE64_COUNT    },
    { PPC_FLOAT_STATE,       PPC_FLOAT_STATE_COUNT       },
    { PPC_EXCEPTION_STATE64, PPC_EXCEPTION_STATE64_COUNT },
    { PPC_VECTOR_STATE,      PPC_VECTOR_STATE_COUNT      },
};

static int coredump_nflavors = 4;

#elif defined (__i386__)

static coredump_thread_state_flavor_t
thread_flavor_array[] = {
    { x86_THREAD_STATE32,    x86_THREAD_STATE32_COUNT    },
    { x86_FLOAT_STATE32,     x86_FLOAT_STATE32_COUNT     },
    { x86_EXCEPTION_STATE32, x86_EXCEPTION_STATE32_COUNT },
};

static int coredump_nflavors = 3;

#elif defined (__x86_64__)

static coredump_thread_state_flavor_t
thread_flavor_array[] = {
    { x86_THREAD_STATE64,    x86_THREAD_STATE64_COUNT    },
    { x86_FLOAT_STATE64,     x86_FLOAT_STATE64_COUNT     },
    { x86_EXCEPTION_STATE64, x86_EXCEPTION_STATE64_COUNT },
};

static int coredump_nflavors = 3;

#endif

#define MAX_TSTATE_FLAVORS 10

typedef struct {
    vm_offset_t header;
    st32 hoffset;
    st32 tstate_size;
    coredump_thread_state_flavor_t *flavors;
} tir_t;

/* Mach0 coredump based on gcore.c from osxbook.org.
   Original source by Amit Singh.
*/
static int mach0_generate_coredump (pid_t pid, const char *newcorefile) {
  ut32 i;
  st32 is_64 = 0;
  st32 error = 0, error1 = 0;

  kern_return_t kr = KERN_SUCCESS;
  st32 segment_count;
  st32 command_size;
  st32 header_size;
  st32 tstate_size;
  st32 hoffset;
  off_t foffset;
  vm_map_offset_t vmoffset;
  vm_offset_t header;
  vm_map_size_t vmsize;
  vm_prot_t prot;
  vm_prot_t maxprot;
  vm_inherit_t inherit;
  struct mach_header *mh;
  struct mach_header_64 *mh64;
  size_t mach_header_sz;
  size_t segment_command_sz;
  ssize_t wc;
  cpu_type_t cpu_type = CPU_TYPE_ANY;
  cpu_subtype_t cpu_subtype = CPU_SUBTYPE_MULTIPLE;

  thread_array_t thread_list;
  mach_msg_type_number_t thread_count;
  coredump_thread_state_flavor_t flavors[MAX_TSTATE_FLAVORS];

  ut32 nesting_depth = 0;
  struct vm_region_submap_info_64 vbr;
  mach_msg_type_number_t vbrcount = 0;
  tir_t tir1;

  printf("It works!\n");

}

R_API bool r_debug_gcore (RDebug* dbg, const char *newcorefile) {
  mach0_generate_coredump(0,"");
}
