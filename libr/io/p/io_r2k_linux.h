#ifndef __IO_R2K_LINUX_H__
#define __IO_R2K_LINUX_H__

#include <r_io.h>
#include <r_lib.h>
#include <r_types.h>
#include <r_print.h>
#include <r_util.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>

#define MAX_PHYS_ADDR   128

/*
 * Backend Id (be_id):
 * 	0: Linear Address
 * 	1: Process Address
 * 	2: Physical Address
 */
struct io_r2k_linux {
	int beid;
	int pid;
	ut8 wp;
};

struct r2k_data {
	int pid;
	size_t addr;
	size_t len;
	ut8 *buff;
	ut8 wp;
};

struct r2k_kernel_map_info {
	size_t start_addr;
	size_t end_addr;
	size_t phys_addr[MAX_PHYS_ADDR];
	int n_pages;
	int n_phys_addr;
};

struct r2k_kernel_maps {
	int n_entries;
	int size;
};

struct r2k_control_reg {
#if __x86_64__ || __i386__
	size_t cr0;
	size_t cr1;
	size_t cr2;
	size_t cr3;
	size_t cr4;
#if __x86_64__
	size_t cr8;
#endif
#elif __arm__
	size_t ttbr0;
	size_t ttbr1;
	size_t ttbcr;
	size_t c1;
	size_t c3;
#elif __arm64__ || __aarch64__
	size_t sctlr_el1;
	size_t ttbr0_el1;
	size_t ttbr1_el1;
	size_t tcr_el1;
#endif
};

struct r2k_proc_info {
	int pid;
	char comm[16];
	size_t vmareastruct[4096];
	size_t stack;
	size_t task;
};

#define R2_TYPE 0x69

#define READ_KERNEL_MEMORY  0x1
#define WRITE_KERNEL_MEMORY 0x2
#define READ_PROCESS_ADDR   0x3
#define WRITE_PROCESS_ADDR  0X4
#define READ_PHYSICAL_ADDR  0x5
#define WRITE_PHYSICAL_ADDR 0x6
#define GET_KERNEL_MAP      0x7
#define READ_CONTROL_REG    0x8
#define PRINT_PROC_INFO     0x9

#ifdef _IOC_TYPECHECK
#define r2k_data_size struct r2k_data
#define r2k_kernel_maps_size struct r2k_kernel_maps
#define r2k_control_reg_size struct r2k_control_reg
#define r2k_proc_info_size struct r2k_proc_info
#else
#define r2k_data_size sizeof (struct r2k_data)
#define r2k_kernel_maps_size sizeof (struct r2k_kernel_maps)
#define r2k_control_reg_size sizeof (struct r2k_control_reg)
#define r2k_proc_info_size sizeof (struct r2k_proc_info)
#endif

#define IOCTL_READ_KERNEL_MEMORY  _IOR (R2_TYPE, READ_KERNEL_MEMORY, r2k_data_size)
#define IOCTL_WRITE_KERNEL_MEMORY _IOR (R2_TYPE, WRITE_KERNEL_MEMORY, r2k_data_size)
#define IOCTL_READ_PROCESS_ADDR   _IOR (R2_TYPE, READ_PROCESS_ADDR, r2k_data_size)
#define IOCTL_WRITE_PROCESS_ADDR  _IOR (R2_TYPE, WRITE_PROCESS_ADDR, r2k_data_size)
#define IOCTL_READ_PHYSICAL_ADDR  _IOR (R2_TYPE, READ_PHYSICAL_ADDR, r2k_data_size)
#define IOCTL_WRITE_PHYSICAL_ADDR _IOR (R2_TYPE, WRITE_PHYSICAL_ADDR, r2k_data_size)
#define IOCTL_GET_KERNEL_MAP      _IOR (R2_TYPE, GET_KERNEL_MAP, r2k_kernel_maps_size)
#define IOCTL_READ_CONTROL_REG    _IOR (R2_TYPE, READ_CONTROL_REG, r2k_control_reg_size)
#define IOCTL_PRINT_PROC_INFO     _IOR (R2_TYPE, PRINT_PROC_INFO, r2k_data_size) // Bad hack. Incorrect size, but since module does not use _IOC_SIZE, it won't matter if size parameter is wrong

#define VM_READ 0x1
#define VM_WRITE 0x2
#define VM_EXEC 0x4
#define VM_MAYSHARE 0x80

extern struct io_r2k_linux r2k_struct;

int ReadMemory (RIO *io, RIODesc *iodesc, int ioctl_n, size_t pid, size_t address, ut8 *buf, int len);
int WriteMemory (RIO *io, RIODesc *iodesc, int ioctl_n, size_t pid, ut64 address, const ut8 *buf, int len);
int run_ioctl_command(RIO *io, RIODesc *iodesc, const char *buf);

#endif
