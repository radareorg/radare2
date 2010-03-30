/* mach-ex :: mach-O extractor
 * Copyleft 2010 nibble <at develsec dot org> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <r_userconf.h>

#define ut32 unsigned int
#define ut8  unsigned char

#define FAT_MAGIC 0xcafebabe
#define FAT_CIGAM 0xbebafeca

struct fat_header {
	ut32 magic;
	ut32 nfat_arch;
};

struct fat_arch {
	int cputype;
	int cpusubtype;
	ut32 offset;
	ut32 size;
	ut32 align;
};

char *file = NULL;
int fd;
int file_size;
int endian = LIL_ENDIAN;
struct fat_header hdr;
struct fat_arch *archs = NULL;

static void swapendian (ut8 *orig, int size)
{
	if (endian) {
		ut8 buffer[8];
		switch(size) {
		case 2:
			buffer[0] = orig[0];
			orig[0]   = orig[1];
			orig[1]   = buffer[0];
			break;
		case 4:
			memcpy(buffer, orig, 4);
			orig[0] = buffer[3];
			orig[1] = buffer[2];
			orig[2] = buffer[1];
			orig[3] = buffer[0];
			break;
		case 8:
			memcpy(buffer, orig, 8);
			orig[0] = buffer[7];
			orig[1] = buffer[6];
			orig[2] = buffer[5];
			orig[3] = buffer[4];
			orig[4] = buffer[3];
			orig[5] = buffer[2];
			orig[6] = buffer[1];
			orig[7] = buffer[0];
			break;
		default:
			printf("Invalid size: %d\n", size);
		}
	}
}

static int init() {
	int i;

	lseek (fd, 0, SEEK_SET);
	if (read(fd, &hdr, sizeof (struct fat_header))
			!= sizeof (struct fat_header)) {
		perror ("read (fat_header)");
		return 0;
	}
	if (hdr.magic != FAT_MAGIC && hdr.magic != FAT_CIGAM)
		return 0;
	swapendian ((ut8*)&hdr.magic, sizeof (ut32));
	swapendian ((ut8*)&hdr.nfat_arch, sizeof (ut32));
	if (hdr.nfat_arch == 0)
		return 0;
	if (!(archs = malloc (hdr.nfat_arch * sizeof (struct fat_arch)))) {
		perror ("malloc (fat_arch)");
		return 0;
	}
	if (read (fd, archs, hdr.nfat_arch * sizeof (struct fat_arch))
			!= hdr.nfat_arch * sizeof (struct fat_arch)) {
		perror ("read (fat_arch)");
		return 0;
	}
	for (i = 0; i < hdr.nfat_arch; i++) {
		swapendian ((ut8*)&archs[i].cputype, sizeof (int));
		swapendian ((ut8*)&archs[i].cpusubtype, sizeof (int));
		swapendian ((ut8*)&archs[i].offset, sizeof (ut32));
		swapendian ((ut8*)&archs[i].size, sizeof (ut32));
		swapendian ((ut8*)&archs[i].align, sizeof (ut32));
	}
	return 1;
}

static int extract() {
	ut8 *buf = NULL;
	char output[256];
	int i, fdo;

	fprintf (stderr, "Extracting files...\n");
	for (i = 0; i < hdr.nfat_arch; i++) {
		snprintf (output, 255, "%s.%i", file, i);
		fprintf (stderr, " %s... ", output);
		if (archs[i].size == 0 ||
			archs[i].size > file_size) {
			fprintf (stderr, "Corrupted file\n");
			return 0;
		}
		fprintf (stderr, "%u\n", archs[i].size);
		if (!(buf = malloc (archs[i].size))) {
			perror ("malloc (buf)");
			return 0;
		}
		lseek (fd, archs[i].offset, SEEK_SET);
		if (read (fd, buf, archs[i].size) != archs[i].size) {
			perror ("read (file)");
			return 0;
		}
		if ((fdo = open (output, O_RDWR|O_CREAT, S_IRWXU)) == -1) {
			fprintf (stderr, "Cannot open output file\n");
			return 0;
		}
		if (write (fdo, buf, archs[i].size) != archs[i].size) {
			perror ("write (file)");
			return 0;
		}
		close (fdo);
		free (buf);
	}
	return 1;
}

int main(int argc, char **argv) {
	if (argc != 2) {
		fprintf (stderr, "Usage: %s <fat mach-o file>\n", argv[0]);
		return 1;
	}
	file = argv[1];
	if ((fd = open (file , O_RDONLY)) == -1) {
		fprintf (stderr, "Cannot open file\n");
		return 1;
	}
	file_size = lseek (fd, 0, SEEK_END);
	if (!init ()) {
		fprintf (stderr, "Invalid file type\n");
		return 1;
	}
	if (!extract ()) {
		fprintf (stderr, "Cannot extract mach-o files\n");
		return 1;
	}
	free (archs);
	close (fd);
	return 0;
}
