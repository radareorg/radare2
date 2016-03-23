/* radare - LGPL - Copyright 2009-2015 - KuroAku */

#include <r_debug.h>
#include <r_util.h>

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
/*
static int create_corefile (const char *corefile) {
  int corefile_fd;

  corefile_fd = open (corefile, O_RDWR | O_CREAT | O_EXCL, 0600);
  if (corefile_fd < 0) {
    perror ("open");
    return corefile_fd;
  }

  // Change ownership
  if (fchown (corefile_fd, kp.kp_eproc.e_ucred.cr_uid,
                   kp.kp_eproc.e_ucred.cr_gid) != 0) {
      eprintf ("Failed to set core file ownership\n");
      return -1;
  }

  return corefile_fd;
}*/

// TODO: Put this code in an if that checks if the target is a mach kernel.
/*
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

static st32 coredump_nflavors = 4;

#elif defined (__ppc64__)

coredump_thread_state_flavor_t
thread_flavor_array[] = {
    { PPC_THREAD_STATE64,    PPC_THREAD_STATE64_COUNT    },
    { PPC_FLOAT_STATE,       PPC_FLOAT_STATE_COUNT       },
    { PPC_EXCEPTION_STATE64, PPC_EXCEPTION_STATE64_COUNT },
    { PPC_VECTOR_STATE,      PPC_VECTOR_STATE_COUNT      },
};

static st32 coredump_nflavors = 4;

#elif defined (__i386__)

static coredump_thread_state_flavor_t
thread_flavor_array[] = {
    { x86_THREAD_STATE32,    x86_THREAD_STATE32_COUNT    },
    { x86_FLOAT_STATE32,     x86_FLOAT_STATE32_COUNT     },
    { x86_EXCEPTION_STATE32, x86_EXCEPTION_STATE32_COUNT },
};

static st32 coredump_nflavors = 3;

#elif defined (__x86_64__)

static coredump_thread_state_flavor_t
thread_flavor_array[] = {
    { x86_THREAD_STATE64,    x86_THREAD_STATE64_COUNT    },
    { x86_FLOAT_STATE64,     x86_FLOAT_STATE64_COUNT     },
    { x86_EXCEPTION_STATE64, x86_EXCEPTION_STATE64_COUNT },
};

static st32 coredump_nflavors = 3;

#endif

#define MAX_TSTATE_FLAVORS 10

// OSX specific default coredump location
#define MACH_COREDUMP_DEST "/cores/core.%u"

typedef struct {
    vm_offset_t header;
    st32 hoffset;
    st32 tstate_size;
    coredump_thread_state_flavor_t *flavors;
} tir_t;

static mach_port_t target_task = MACH_PORT_NULL;

static st32 mach0_get_processor_type (cpu_type_t *cpu_type, cpu_subtype_t *cpu_subtype) {
  kern_return_t kr = KERN_FAILURE;
  host_name_port_t host = MACH_PORT_NULL;
  host_priv_t host_priv = MACH_PORT_NULL;
  processor_port_array_t processor_list = (processor_port_array_t) 0;
  natural_t processor_count;
  natural_t info_count;
  processor_basic_info_data_t basic_info;

  if (!cpu_type || !cpu_subtype) return EINVAL;

  *cpu_type = CPU_TYPE_ANY;
  *cpu_subtype = CPU_SUBTYPE_MULTIPLE;

  host = mach_host_self ();
  if (host == MACH_PORT_NULL) {
    mach_error ("mach_host_self:", host);
    goto out;
  }

  kr = host_get_host_priv_port (host, &host_priv);
  if (kr != KERN_SUCCESS) {
    mach_error ("host_get_host_priv_port:", kr);
    goto out;
  }

  processor_list = (processor_port_array_t) 0;
  kr = host_processors (host_priv, &processor_list, &processor_count);
  if (kr != KERN_SUCCESS) {
    mach_error ("host_processors", kr);
    goto out;
  }

  info_count = PROCESSOR_BASIC_INFO_COUNT;
  kr = processor_info (processor_list[0], PROCESSOR_BASIC_INFO, &host,
                        (processor_info_t) &basic_info, &info_count);
  if (kr != KERN_SUCCESS) {
    *cpu_type = basic_info.cpu_type;
    *cpu_subtype = basic_info.cpu_subtype;
  }

out:
  if (host != MACH_PORT_NULL) mach_port_deallocate (mach_task_self (), host);
  if (host_priv != MACH_PORT_NULL) mach_port_deallocate (mach_task_self (), host);
  if (processor_list) 
    (void) vm_deallocate (mach_task_self (), (vm_address_t) processor_list,
                          processor_count * sizeof (processor_t *));

  return kr;
}


static ut8 get_kproc_bits (struct kinfo_proc kp) {
  return (kp.kp_proc.p_flag & P_LP64) ? 64 : 32;
}

// This looks like an ugly hack. Check for an existing function in the framework
static st32 mach0_get_process_info (pid_t pid, struct kinfo_proc *kp) {
  size_t bufsize = 0;
  size_t orig_bufsize = 0;
  st32 retry_count = 0;
  st32 local_error = 0;
  st32 mib[4];// = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
  size_t len = 4;

  sysctlnametomib ("kern.proc.pid", mib, &len);

  mib[3] = pid;
  orig_bufsize = bufsize = sizeof (struct kinfo_proc);

  /*if (sysctl (mib, len, kp, &bufsize, NULL, 0) == -1) {
    perror ("sysctl");
    return -1;
  } else {
    eprintf ("[DEBUG]: sysctl OK\n");
    //printkproc (kp);
    return 0;
  }*/
/*
  for (retry_count = 0;;retry_count++) {
    eprintf ("[DEBUG] Try #%d\n", retry_count);
    local_error = 0;
    bufsize = orig_bufsize;
    if ((local_error = sysctl (mib, 4, kp, &bufsize, NULL, 0)) < 0) {
      eprintf ("[DEBUG] sysctl returned: %d\n", local_error);
      if (retry_count < 1000) {
        sleep (1);
        continue;
      }
          eprintf ("[DEBUG] Exiting at try #%d\n", retry_count);
      return local_error;
    } else if (local_error == 0) {
      eprintf ("Exiting with code 0\n");
      return local_error;
    }
  }
}

static st32 mach0_target_done (st32 error, st32 corefile_fd)
{
    st32 ret = 0;

    if (target_task != MACH_PORT_NULL) {
        task_resume (target_task);
        mach_port_deallocate (mach_task_self(), target_task);
        target_task = MACH_PORT_NULL;
    }

    if (corefile_fd != -1) {
        ret = close (corefile_fd);
        corefile_fd = -1;
    }

    return ret;
}

static st32 mach0_get_vmmap_entries (task_t task) {
  kern_return_t kr = KERN_SUCCESS;
  vm_address_t address = 0;
  vm_size_t size = 0;
  st32 n = 1;

  while (1) {
    mach_msg_type_number_t count;
    struct vm_region_submap_info_64 info;
    ut32 nesting_depth;

    count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kr = vm_region_recurse_64 (task, &address, &size, &nesting_depth,
      (vm_region_info_64_t) &info, &count);
    if (kr == KERN_INVALID_ADDRESS) {
      break;
    } else if (kr) {
      mach_error ("vm_region:", kr);
      break;
    }

    if (info.is_submap) nesting_depth++;
    else address += size; n++;
  }

  return n;
}

/* Mach0 coredump based on gcore.c from osxbook.org.
   Original source by Amit Singh.
*/
/*static st32 mach0_generate_coredump (RDebug* dbg, const char *newcorefile) {
  ut32 i;
  st32 is_64 = 0;
  st32 error = 0, error1 = 0;
  st32 corefile_fd = -1;

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

  struct kinfo_proc kp, kp_self;

  // Get processor type
  kr = mach0_get_processor_type (&cpu_type, &cpu_subtype);
  if (kr != KERN_SUCCESS) {
    eprintf ("Failed to get processor type (%d)\n", kr);
    return kr;
  }

  // Get task from pid
  // TODO: Change to pid_to_task from mach.c
  kr = task_for_pid (mach_task_self (), pid, &target_task);
  if (kr != KERN_SUCCESS) {
    eprintf ("Failed to find task for process %d with message: %s\n", pid, mach_error_string (kr));
    return kr;
  }

  // Get process info
  kr = mach0_get_process_info (pid, &kp);
  eprintf ("[DEBUG] kr = %d\n", kr);
  if (kr) {
    eprintf ("Failed to retrieve process information for %d\n", pid);
    mach_port_deallocate (mach_task_self (), target_task);
    return kr;
  } else {
    eprintf ("Got proc info for pid %d (%d)\n", pid, kp.kp_proc.p_pid);
  }

  kr = mach0_get_process_info (getpid (), &kp_self);
  if (kr) {
    eprintf ("Failed to retrieve process information for myself (%d)\n", pid);
    mach_port_deallocate (mach_task_self (), target_task);
    return kr;
  } else {
    eprintf ("Got proc info for pid %d (%d)\n", getpid(), kp_self.kp_proc.p_pid);
  }

  // Bitness match check
  if ((kp.kp_proc.p_flag & P_LP64) ^ (kp_self.kp_proc.p_flag & P_LP64)) {
    eprintf ("r2 is %d-bit whereas the target is %d-bit\n",
                get_kproc_bits (kp_self),
                get_kproc_bits (kp));
    mach_port_deallocate (mach_task_self (), target_task);
    return EINVAL; /* bitness must match */
  /*}

  // Mach header
#if defined(__ppc64__) || defined(__x86_64__)
  is_64 = 1;
  mach_header_sz = sizeof(struct mach_header_64);
  segment_command_sz = sizeof(struct segment_command_64);
#else /* 32-bit *//*
  mach_header_sz = sizeof(struct mach_header);
  segment_command_sz = sizeof(struct segment_command);
#endif

  (void)task_suspend (target_task);

  corefile_fd = create_corefile (newcorefile);
  if (corefile_fd < 1) {
    perror ("create_corefile");
    goto out;
  }

  // Get task threads
  kr = task_threads (target_task, &thread_list, &thread_count);
  if (kr != KERN_SUCCESS) {
    error = kr;
    eprintf ("Failed to retrieve threads from target task");
    goto out;
  } else {
    for (i = 0; i < thread_count; i++) {
      mach_port_deallocate (mach_task_self (), thread_list[i]);
    }
    vm_deallocate (mach_task_self (), (vm_address_t) thread_list,
        thread_count * sizeof (thread_act_t));
  }

  // Segments count
  segment_count = mach0_get_vmmap_entries (target_task);
  bcopy (thread_flavor_array, flavors, sizeof (thread_flavor_array));
  tstate_size = 0;

  for (i = 0; i < coredump_nflavors; i++) {
    tstate_size += sizeof (coredump_thread_state_flavor_t) +
                              (flavors[i].count * sizeof (st32));
  }

  command_size = segment_count * segment_command_sz +
                   thread_count  * sizeof (struct thread_command) +
                   tstate_size   * thread_count;

  header_size = command_size + mach_header_sz;

  header = (vm_offset_t)malloc (header_size);
  memset ((void *)header, 0, header_size);

  // Headers
  if (is_64) {
    mh64             = (struct mach_header_64 *)header;
    mh64->magic      = MH_MAGIC_64;
    mh64->cputype    = cpu_type;
    mh64->cpusubtype = cpu_subtype;
    mh64->filetype   = MH_CORE;
    mh64->ncmds      = segment_count + thread_count;
    mh64->sizeofcmds = command_size;
    mh64->reserved   = 0; /* 8-byte alignment *//*
  } else {
    mh               = (struct mach_header *)header;
    mh->magic        = MH_MAGIC;
    mh->cputype      = cpu_type;
    mh->cpusubtype   = cpu_subtype;
    mh->filetype     = MH_CORE;
    mh->ncmds        = segment_count + thread_count;
    mh->sizeofcmds   = command_size;
  }

  hoffset = mach_header_sz;          /* offset into header *//*
  foffset = round_page(header_size); /* offset into file   *//*
  vmoffset = MACH_VM_MIN_ADDRESS;    /* offset into VM     *//*

  // More Segments

  // Write to file

  // Clean
out:
  error1 = mach0_target_done (error, corefile_fd);
  if (error == 0) error = error1;
  return error;

}*/

#define DEFAULT_CORE_DEST MACH_COREDUMP_DEST

R_API bool old_r_debug_gcore (RDebug* dbg, const char *newcorefile) {
/*
  printf ("Declarando la cadena para el nombre del fichero\n");
  char *corefile = malloc (MAXPATHLEN);

  printf ("Before string conversion\n");
  if (strlen (corefile) == 0) snprintf (corefile, MAXPATHLEN, DEFAULT_CORE_DEST, dbg->pid);
  else strncpy (corefile, r_str_chop_ro (strdup (newcorefile)), MAXPATHLEN - 1);

  printf ("Before the if\n");
  if (dbg->pid < 0) {
    printf ("No process to dump.\n");
    return false;
  } else {
    printf ("[DEBUG] PID = %d\n", dbg->pid);
  }
  printf ("[DEBUG] corefile = \"%s\"\n", corefile);
  mach0_generate_coredump (dbg,corefile);
  free (corefile);

  return true;*/
}
