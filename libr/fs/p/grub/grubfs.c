/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <r_io.h>
#include <r_fs.h>
#include "grubfs.h"
#include <stdio.h>
#include <string.h>


static RIOBind *bio = NULL;
static ut64 delta = 0;

static void* empty (int sz) {
	void *p = malloc (sz);
	if (p) memset (p, '\0', sz);
	return p;
}

static grub_err_t read_foo (struct grub_disk *disk, grub_disk_addr_t sector, grub_size_t size, unsigned char *buf) {
	if (disk != NULL) {
		int ret;
		RIOBind *iob = disk->data;
		if (bio)
			iob = bio;
		//printf ("io %p\n", file->root->iob.io);
		ret = iob->read_at (iob->io, delta+(512*sector), buf, 512); // XXX: 512 is hardcoded?
		if (ret == -1)
			return 1;
		//printf ("DISK PTR = %p\n", disk->data);
		//printf ("\nBUF: %x %x %x %x\n", buf[0], buf[1], buf[2], buf[3]);
	} else {
		FILE *fd = fopen ("/tmp/test.fs.img", "rb"); // XXX for debug only
		if (fd) {
			size = 512;
			fseek (fd, (512*sector), SEEK_SET);
			fread (buf, 1, size, fd);
			fclose (fd);
		} else return 1;
	}
	return 0; // 0 is ok
}

GrubFS *grubfs_new (struct grub_fs *myfs, void *data) {
	struct grub_file *file;
	GrubFS *gfs = empty (sizeof (GrubFS));
	// hacky mallocs :D
	gfs->file = file = empty (sizeof (struct grub_file));
	file->device = empty (sizeof (struct grub_device)+1024);
	file->device->disk = empty (sizeof (struct grub_disk));
	file->device->disk->dev = file->device;
	file->device->disk->dev->read = read_foo; // grub_disk_dev
	file->device->disk->data = data;
	//file->device->disk->read_hook = read_foo; //read_hook;
	file->fs = myfs;
	return gfs;
}

grub_disk_t *grubfs_disk (void *data) {
	struct grub_disk *disk = empty (sizeof (struct grub_disk));
	disk = empty (sizeof (struct grub_disk));
	disk->dev = empty (sizeof (struct grub_disk_dev));
	disk->dev->read = read_foo; // grub_disk_dev
	disk->data = data;
	return disk;
}

void grubfs_free (GrubFS *gf) {
	if (gf) {
		if (gf->file && gf->file->device)
			free (gf->file->device->disk);
		//free (gf->file->device);
		free (gf->file);
		free (gf);
	}
}

void grubfs_bind_io (RIOBind *iob, ut64 _delta) {
	bio = iob;
	delta = _delta;
}
