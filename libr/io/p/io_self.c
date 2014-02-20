/* radare - LGPL - Copyright 2014 - pancake */

#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>

#if __APPLE__
#include <mach/vm_map.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_interface.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/mach_error.h>
#include <mach/task.h>
#include <mach/task_info.h>
void macosx_debug_regions (task_t task, mach_vm_address_t address, int max);
#endif

#define PERM_READ 4
#define PERM_WRITE 2 
#define PERM_EXEC 1

typedef struct {
	ut64 from;
	ut64 to;
	int perm;
} RIOSelfSection;

static RIOSelfSection self_sections[1024];
static int self_sections_count;

static int self_in_section(ut64 addr, int *left, int *perm) {
	int i;
	for (i=0; i<self_sections_count; i++) {

		if (addr >= self_sections[i].from && \
			addr < self_sections[i].to) {
				if (left)
					*left = self_sections[i].to-addr;
				if (perm)
					*perm = self_sections[i].perm;
				return R_TRUE;
			}
	}
	return R_FALSE;
}

static int __plugin_open(RIO *io, const char *file, ut8 many) {
	return (!strncmp (file, "self://", 7));
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	int pid = getpid ();
	self_sections_count = 0;
#if __APPLE__
	mach_port_t	task;
	kern_return_t	rc;
	rc = task_for_pid (mach_task_self(),pid, &task);	
	if (rc) {
		eprintf ("task_for_pid failed\n");
		return NULL;
	}
	macosx_debug_regions (task, (void*)(size_t)1, 1000);
	io->va = R_TRUE; // nop
	return r_io_desc_new (&r_io_plugin_self,
		pid, file, rw, mode, NULL);
#elif __linux__
	char *pos_c;
	char null[64];
	char path[1024], line[1024];
	char region[100], region2[100], perms[5];
	snprintf (path, sizeof (path)-1, "/proc/%d/maps", pid);
	FILE *fd = fopen (file, "r");
	if (!fd) 
		return NULL;

	while (!feof (fd)) {
		line[0]='\0';
		fgets (line, sizeof (line)-1, fd);
		if (line[0]=='\0')
			break;
		path[0]='\0';
		sscanf (line, "%s %s %s %s %s %s",
			&region[2], perms, null, null, null, path);
		pos_c = strchr (&region[2], '-');
		if (pos_c) strncpy (path, pos_c, sizeof (path)-1);
		else path[0] = 0;
		int i, perm = 0;
		for (i = 0; perms[i] && i < 4; i++)
			switch (perms[i]) {
			case 'r': perm |= R_IO_READ; break;
			case 'w': perm |= R_IO_WRITE; break;
			case 'x': perm |= R_IO_EXEC; break;
			}
		self_sections[self_sections_count].from = r_num_get (NULL, region);
		self_sections[self_sections_count].to = r_num_get (NULL, region2);
		self_sections[self_sections_count].perm = perm;
		self_sections_count++;
		r_num_get (NULL, region2);
		if (!pos_c)
			continue;
	}
	return r_io_desc_new (&r_io_plugin_self,
		pid, file, rw, mode, NULL);
#else
	#warning not yet implemented for this platform
#endif
	return NULL;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	int left;
	int perm;
	if (self_in_section (io->off, &left, &perm)) {
		if (perm & R_IO_READ) {
			int newlen = R_MIN (len, left);
			ut8 *ptr = (ut8*)(size_t)io->off;
			memcpy (buf, ptr, newlen);
			return newlen;
		}
	}
	return 0;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	if (fd->flags & R_IO_WRITE) {
		int left, perm;
		if (self_in_section (io->off, &left, &perm)) {
			int newlen = R_MIN (len, left);
			ut8 *ptr = (ut8*)(size_t)io->off;
			if (newlen>0)
				memcpy (ptr, buf, newlen);
			return newlen;
		}
	}
	return -1;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET: return offset;
	case SEEK_CUR: return io->off + offset;
	case SEEK_END: return UT64_MAX;
	}
	return offset;
}

static int __close(RIODesc *fd) {
	return 0;
}

struct r_io_plugin_t r_io_plugin_self = {
	.name = "self",
	.desc = "read memory from myself using 'self://'",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.plugin_open = __plugin_open,
	.lseek = __lseek,
	.write = __write,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_mach
};
#endif

#if __APPLE__
// taken from vmmap.c ios clone
void macosx_debug_regions (task_t task, mach_vm_address_t address, int max) {
	kern_return_t kret;

	mach_vm_address_t prev_address;
	/* @TODO: warning - potential overflow here - gotta fix this.. */
	vm_region_basic_info_data_t prev_info, info;
	mach_vm_size_t size, prev_size;

	mach_port_t object_name;
	mach_msg_type_number_t count;

	int nsubregions = 0;
	int num_printed = 0;

	count = VM_REGION_BASIC_INFO_COUNT_64;
	kret = mach_vm_region (task, &address, &size, VM_REGION_BASIC_INFO,
		(vm_region_info_t) &info, &count, &object_name);

	if (kret) {
		printf ("mach_vm_region: Error %d - %s", kret, mach_error_string(kret));
		return;
	}
	memcpy (&prev_info, &info, sizeof (vm_region_basic_info_data_t));
	prev_address = address;
	prev_size = size;
	nsubregions = 1;
	self_sections_count = 0;

	for (;;) {
		int print = 0;
		int done = 0;

		address = prev_address + prev_size;

		/* Check to see if address space has wrapped around. */
		if (address == 0)
			print = done = 1;

		if (!done) {
			// Even on iOS, we use VM_REGION_BASIC_INFO_COUNT_64. This works.

			count = VM_REGION_BASIC_INFO_COUNT_64;


			kret =
			mach_vm_region (task, &address, &size, VM_REGION_BASIC_INFO,
				(vm_region_info_t) &info, &count, &object_name);

			if (kret != KERN_SUCCESS)
			 {
				/* iOS 6 workaround - attempt to reget the task port to avoiD */
				/* "(ipc/send) invalid destination port" (1000003 or something) */
				task_for_pid(mach_task_self(),getpid (), &task);

				kret =
				mach_vm_region (task, &address, &size, VM_REGION_BASIC_INFO,
					(vm_region_info_t) &info, &count, &object_name);


			}
			if (kret != KERN_SUCCESS) {
				fprintf (stderr,"mach_vm_region failed for address %p - Error: %x\n", address,(kret));
				size = 0;
				if (address >= 0x4000000) return;
				print = done = 1;
			}
		}

		if (address != prev_address + prev_size)
			print = 1;

		if ((info.protection != prev_info.protection)
			|| (info.max_protection != prev_info.max_protection)
			|| (info.inheritance != prev_info.inheritance)
			|| (info.shared != prev_info.reserved)
			|| (info.reserved != prev_info.reserved))
			print = 1;

		if (print) {
			int	print_size;
			char *print_size_unit;
			if (num_printed == 0)

				printf ("Region ");
			else
				printf ("   ... ");

			//findListOfBinaries(task, prev_address, prev_size);
			/* Quick hack to show size of segment, which GDB does not */
			print_size = prev_size;
			if (print_size > 1024) { print_size /= 1024; print_size_unit = "K"; }
			if (print_size > 1024) { print_size /= 1024; print_size_unit = "M"; }
			if (print_size > 1024) { print_size /= 1024; print_size_unit = "G"; }
			/* End Quick hack */
			printf (" %p - %p [%d%s](%x/%x; %d, %s, %s)",
				(prev_address),
			       (prev_address + prev_size),
			       print_size,
			       print_size_unit,
			       prev_info.protection,
			       prev_info.max_protection,
			       prev_info.inheritance,
			       prev_info.shared ? "shared" : "private",
			       prev_info.reserved ? "reserved" : "not-reserved");

			self_sections[self_sections_count].from = prev_address;
			self_sections[self_sections_count].to = prev_address+prev_size;
			self_sections[self_sections_count].perm = PERM_READ; //prev_info.protection;
			self_sections_count++;

			if (nsubregions > 1)
				printf (" (%d sub-regions)", nsubregions);

			printf ("\n");

			prev_address = address;
			prev_size = size;
			memcpy (&prev_info, &info, sizeof (vm_region_basic_info_data_t));
			nsubregions = 1;

			num_printed++;
		} else {
			prev_size += size;
			nsubregions++;
		}

		if ((max > 0) && (num_printed >= max)) {
			printf ("Max %d num_printed %d\n", max, num_printed);
			done = 1;
		}
		if (done)
			break;
	 }
}
#endif
