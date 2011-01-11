#include <grub/file.h>
#include <grub/disk.h>
#include <string.h>
#include <stdio.h>

extern struct grub_fs grub_ext2_fs;

void grub_exit () {
	printf ("GTFO!\n");
	exit (0);
}

void read_foo (struct grub_disk *disk, grub_disk_addr_t sector, grub_size_t size, unsigned char *buf) {
	//printf ("==> DISK %x\n", disk);
	//printf ("==> OFFSET %x\n", offset);
	//printf ("[foo]==> Reading hook %x %x\n", sector, size);
	//printf ("==> land: %p\n", buf);
	size=512;
	{
		FILE *fd = fopen ("test.fs.img", "rb");
		fseek (fd, (512*sector), SEEK_SET);
		fread (buf, 1, size, fd);
		//printf ("\nBUF: %x %x %x %x\n", buf[0], buf[1], buf[2], buf[3]);
		fclose (fd);
	}
}

void read_hook (grub_disk_addr_t sector, unsigned long offset, unsigned long length, unsigned char *buf) {
	//printf ("[hook]==> Reading hook sector=%x offset=%x %x\n", sector, offset, length);
	//printf ("[hook]==> last %p\n", buf);
	{
		int size=length;
		FILE *fd = fopen("test.fs.img", "rb");
		fseek (fd, (512*sector)+offset, SEEK_SET);
		fread (buf, 1, size, fd);
		//write (1, buf, size);
		//printf ("BUF: %x %x %x %x\n", buf[0], buf[1], buf[2], buf[3]);
		fclose (fd);
	}
}

grub_file_t openimage(grub_fs_t fs, const char *str) {
	grub_file_t file = malloc (1024);
	file->device = malloc(1024);
	memset (file->device, 0, 1024);
	file->device->disk = malloc(1024);
	file->device->disk->name = strdup ("disk0");
	file->device->disk->dev = file->device;
	//file->device->disk->dev->read = read_hook; //file->device;
	file->device->disk->dev->read = read_foo; //file->device;
	file->device->disk->read_hook = read_hook; //read_hook;
	//file->device->read = read_hook;
	//file->device->read = read_hook;
	//&device; // HACK to avoid segfault
	file->fs = fs;
#if 0
	file->offset = 0;
	file->size = 12190208;
	file->data = malloc (file->size);
#endif
	{
		FILE *fd = fopen("test.fs.img", "rb");
		if (fd == NULL) {
			printf ("Cannot open fs image\n");
			return NULL;
		}
		fread (file->data, file->size, 1, fd);
		fclose (fd);
	}
	file->read_hook = read_hook;
	return file;
}

int dirhook (const char *filename, const struct grub_dirhook_info *info) {
	//info->mtimeset
	//info->case_insensitive
	printf ("DIRFILE: %c (%d) %s\n", info->dir?'d':'f', 
		info->mtime, filename);
	return 0;
}

int do_main() {
	struct grub_file *file;
	struct grub_fs *e2;
	grub_err_t err;
	struct grub_disk disk;

	e2 = &grub_ext2_fs;
	file = openimage (e2, "test.fs.img");
	if (file == NULL) {
		printf ("oops\n");
		return 0;
	}

	err = e2->open (file, "/test");
	if (err == 0) {
		char buf[1024];
		err = e2->read (file, buf, file->size);
//file->read_hook (2, 0, 0);
		write (1, buf, file->size);
		e2->close (file);

		// Root directory list
		err = e2->dir (file->device, "/", dirhook);
		if (err != 0)
			grub_print_error ();
	} else {
		grub_print_error ();
		printf ("error is : %d\n", err);
		return 0;
	}
	return 1;
}

main() {
	printf ("Hello grubfs!\n");
	if (do_main()) {
		printf ("\n** worked!\n");
	} else {
		printf ("\n** failed!\n");
	}
	return 0;
}
