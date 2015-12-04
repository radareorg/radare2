#ifndef _INCLUDE_XNU_THREADS_H_
#define _INCLUDE_XNU_THREADS_H_

#if __POWERPC__
//TODO add better support for PPC
#	define R_REG_T ppc_thread_state_t
#	define R_REG_STATE_T PPC_THREAD_STATE
#	define R_REG_STATE_SZ PPC_THREAD_STATE_SZ

#elif __arm || __arm64 || __aarch64
#	include <mach/arm/thread_status.h>
#	ifndef ARM_THREAD_STATE
#		define ARM_THREAD_STATE 1
#	endif
#	ifndef ARM_THREAD_STATE64
#		define ARM_THREAD_STATE64 6
#	endif
#	define R_REG_T arm_unified_thread_state_t
#	define R_REG_STATE_T MACHINE_THREAD_STATE
#	define R_REG_STATE_SZ MACHINE_THREAD_STATE_COUNT
//TODO maybe these defines break the build header Xcode
#	define R_DEBUG_REG_T arm_debug_state_t
#	define R_DEBUG_STATE_T ARM_DEBUG_STATE
#	define R_DEBUG_STATE_SZ ARM_DEBUG_STATE_COUNT

#elif __x86_64__ || __i386__
#	define R_REG_T x86_thread_state_t
#	define R_REG_STATE_T MACHINE_THREAD_STATE
#	define R_REG_STATE_SZ MACHINE_THREAD_STATE_COUNT
#	define R_DEBUG_REG_T x86_debug_state_t
#	define R_DEBUG_STATE_T x86_DEBUG_STATE
#	define R_DEBUG_STATE_SZ x86_DEBUG_STATE_COUNT
#endif

#define RETURN_ON_MACH_ERROR(msg, retval)\
        if (kr != KERN_SUCCESS) {mach_error (msg, kr); return ((retval));}

//FIXME include this in RDebug How?? sdb??
typedef struct _exception_info {
	exception_mask_t masks[EXC_TYPES_COUNT];
	mach_port_t ports[EXC_TYPES_COUNT];
	exception_behavior_t behaviors[EXC_TYPES_COUNT];
	thread_state_flavor_t flavors[EXC_TYPES_COUNT];
	mach_msg_type_number_t count;
	pthread_t thread;
} xnu_exception_info;

typedef struct _xnu_thread {
	thread_t tid; //mach_port // XXX bad naming here
	char *name; //name of thread
	thread_basic_info_data_t basic_info; //need this?
	int stepping; // thread is stepping or not //TODO implement stepping
	R_REG_T gpr; // type R_REG_T using unified API XXX bad naming
	R_DEBUG_REG_T drx; // type R_DEBUG_REG_T using unified API
	//task_t thtask;
	void *state;
	int state_size;
#if __arm || __arm64 || __aarch64
	void *oldstate;
#endif
	int flavor;
	unsigned int count;
} xnu_thread_t;

#endif
