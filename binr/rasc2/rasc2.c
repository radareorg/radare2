/* radare - LGPL - Copyright 2007-2010 pancake <@nopcode.org> */

#include "rasc.h"
#include "r_types.h"
#include "r_userconf.h"
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#if __UNIX__
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#if __WINDOWS__
#include <windows.h>
#endif

#define BLOCK 4096
int execute = 0;
int scidx = -1;
int hexa_print = 0;
unsigned long off = 0, addr = 0;
unsigned char shellcode[BLOCK];
unsigned char output[BLOCK];

/* sizes */
int A=0, N=0;
int C=0, E=0;
int scsize = 0;
#define SCSIZE N+A+C+E+scsize

static int show_helpline() {
	printf( "Usage: rasc2 [-cCexXtLV] [-l port] [-a addr@off] [-[A|N|C|E] N]\n"
		"             [-s hexpair] [-i name] [-S file] [-h]\n");
	return 0;
}

static int show_help() {
	show_helpline();
	printf(
	"  -l [port]    starts a syscall proxy server\n"
	"  -A [n]       prefix shellcode with N A's (0x41)\n"
	"  -N [n]       prefix shellcode with N nops (0x90)\n"
	"  -C [n]       suffix shellcode with N traps\n"
	"  -E [n]       prefix with enumeration 01 02 03..\n"
	"  -a addr@off  set the return address at a specified offset\n"
	"  -s 'sc'      set shellcode in hexpairs (cc cd 80)\n"
	"  -S 'file'    load shellcode from file\n"
	"  -i 'scdb'    hardcoded shellcode (-L to list)\n"
	"  -L           list hardcoded shellcodes\n"
	"  -c           output in C format\n"
	"  -e           output in escapped string\n"
	"  -x           output in hexpairs format\n"
	"  -X           execute shellcode\n"
	"  -t           test current platform\n"
	"  -V           show version information\n"
	" Environment variables to compile shellcodes:\n"
	"  CMD          Command to execute on execves\n"
	"  HOST         Host to connect\n"
	"  PORT         Port to listen or connect\n");
//#warning TODO: prefix shellcode with setuid() fun
	//printf("  -p          attach \n");
	//printf("  -P          push file and remote execute\n");
	//printf("  -u          use UDP\n");
	return 0;

}

char *filetostr(char *file) {
        FILE *fd = fopen(file,"r");
        char *buf;
        int i, size = BLOCK;

        if (fd == NULL)
                return NULL;

        buf = (char *)malloc(size);
        buf[0]='\0';
        for(i=0;!feof(fd);i++) {
                if (i==size) {
                        size = size + BLOCK;
                        buf = realloc(buf, size);
                }
                fread(buf+i, 1, 1, fd);
        }
        fclose(fd);
        if (buf[0]=='\0') {
                free(buf);
                return NULL;
        }
        return buf;
}

int otf_patch() {
	char *ptr;
	/* on the fly patching */
	if (scidx != -1) {
		if (shellcodes[scidx].cmd) {
			ptr = getenv("CMD");
			if (ptr) {
				strcpy((char*) (shellcode+shellcodes[scidx].cmd), ptr);
				shellcode[shellcodes[scidx].cmd+strlen(ptr)]='\0';
				if (strlen(ptr)>7)
					scsize+=strlen(ptr)-7;
			}
		}
		if (shellcodes[scidx].host) {
			ptr = getenv("HOST");
			if (ptr) {
				int x,y,z,w;
				sscanf(ptr,"%d.%d.%d.%d", &x,&y,&z,&w);
				shellcode[shellcodes[scidx].host+3]=x;
				shellcode[shellcodes[scidx].host+2]=y;
				shellcode[shellcodes[scidx].host+1]=z;
				shellcode[shellcodes[scidx].host+0]=w;
			}
		}
		if (shellcodes[scidx].port) {
			ptr = getenv("PORT");
			if (ptr) {
				unsigned short port = atoi(ptr);
				memcpy(shellcode+shellcodes[scidx].port,&port,2);
			}
		}
	}
	/* patch return address */
	if (addr != 0) {
		/* TODO: swapping endian for addr (-e) */
		unsigned char *foo = (unsigned char *)&addr;
		if (off<0) off = 0;
		if (off>SCSIZE) off = SCSIZE-4;
		output[off+0] = foo[0];
		output[off+1] = foo[1];
		output[off+2] = foo[2];
		output[off+3] = foo[3];
	}
	
	return 0;
}

int print_shellcode() {
	int j=0,i=0;

	if (!(SCSIZE)) {
		printf("No shellcode defined\n");
		return 1;
	}

	if (SCSIZE>=BLOCK) {
		printf("Dont overflow me\n");
		return 1;
	}

	/* prepare output buffer */
	for(i=0;i<A;i++)
		output[i] = 'A';
	if (N%2) {
		for(i=0;i<N;i++)
			output[i+A] = '\x90';
	} else {
		for(i=0;i<N;i+=2) {
			output[i+A]   = '\x40'; // inc eax
			output[i+A+1] = '\x48'; // dec eax
		}
	}
	for(i=0,j='A';i<E;i++,j++) {
		if (j=='\n'||j=='\r')
			j++;
		output[i*4+A+N] = (unsigned char)(j%256);
		output[i*4+A+N+1] = (unsigned char)(j%256);
		output[i*4+A+N+2] = (unsigned char)(j%256);
		output[i*4+A+N+3] = (unsigned char)(j%256);
	}
	memcpy(output+A+N+E, shellcode, scsize);
	for(i=0;i<C;i++)
		output[i+A+E+N+scsize] = '\xCC';

	/* patch addr and env */
	otf_patch();

	switch(hexa_print) {
	case 0: // raw
		write(1, output, SCSIZE);
		break;
	case 1: // hexpairs
		for(i=0;i<SCSIZE;i++)
			printf("%02x", output[i]);
		printf("\n");
		break;
	case 2: // C
		printf("unsigned char shellcode[] = {  ");
		j = 0;
		for(i=0;i<SCSIZE;i++) {
			if (!(i%12)) printf("\n  ");
			printf("0x%02x", output[i]);
			if (i+1!=SCSIZE+scsize)
				printf(", ");
		}
		printf("\n};\n");
		fflush(stdout);
		break;
	case 3:
		if (scsize == 0) {
			printf("No shellcode defined\n");
			return 1;
		} else {
			void (*cb)() = (void *)&shellcode; cb(); 
		}
		break;
	case 4:
		printf("\"");
		j = 0;
		for(i=0;i<SCSIZE;i++) {
			printf("\\x%02x", output[i]);
		}
		printf("\"\n");
		fflush(stdout);
		break;
	}
	return 0;
}

int hex2int (unsigned char *val, unsigned char c) {       
        if ('0' <= c && c <= '9')      *val = (unsigned char)(*val) * 16 + ( c - '0');
        else if (c >= 'A' && c <= 'F') *val = (unsigned char)(*val) * 16 + ( c - 'A' + 10);
        else if (c >= 'a' && c <= 'f') *val = (unsigned char)(*val) * 16 + ( c - 'a' + 10);
        else return 0;
        return 1;
}

int hexpair2bin(const char *arg) // (0A) => 10 || -1 (on error)
{
	unsigned char *ptr;
	unsigned char c = '\0';
	unsigned char d = '\0';
	unsigned int  j = 0;

	for (ptr = (unsigned char *)arg; ;ptr = ptr + 1) {
		if (ptr[0]==' '||ptr[0]=='\t'||ptr[0]=='\n'||ptr[0]=='\r')
			continue;
		if (!IS_PRINTABLE(ptr[0]))
			continue;
		if (ptr[0]=='\0'||ptr[0]==' ' || j==2)
			break;
		d = c;
		if (hex2int(&c, ptr[0]) == 0) {
			fprintf(stderr, "Invalid hexa string at char '%c'.\n", ptr[0]);
			return -1;
		}
		c |= d;
		if (j++ == 0) c <<= 4;
	}

	return (int)c;
}

int load_shellcode_from_me(char *str) {
	int i;
	for(i=0;shellcodes[i].name;i++) {
		if (!strcmp(shellcodes[i].name, str)) {
			memcpy(shellcode, shellcodes[i].data, shellcodes[i].len);
			scsize = shellcodes[i].len;
			scidx = i;
//printf("Using %d bytes shellcode (%s) %02x %02x\n", shellcodes[i].len, shellcodes[i].desc,
//shellcodes[i].data[0], shellcodes[i].data[1], shellcodes[i].data[2]);
			return 1;
		}
	}
	return 0;
}

int load_shellcode_from_string(char *str) {
	int i,j=1,ch,len;
	char input2[1024];

	// hexpairs to bin
	strcpy(input2, str);
	len = strlen(input2);
	input2[0] = '\0';
	for(i=0;i<len;i+=j) {
		if (str[i]==' '||str[i]=='\t'||str[i]=='\n'||str[i]=='\r')
			continue;
		ch = hexpair2bin(str+i);
		if (str[i+2]==' ')
			j = 3;
		else j = 2;

		if (ch == -1)
			break;

		shellcode[scsize++]=ch;
	}
	shellcode[scsize] = '\0';
	
	return 0;
}

int file_type(char *str)
{
	if (!strcmp(str,"-"))
		return 0; // stdin
	if (!strcmp(str+strlen(str)-2,".s"))
		return 1; // stdin
	return 2;
}

int load_shellcode_from_file(char *str)
{
	char buf[1024];
	char *ptr = NULL;

	str[1024]='\0';
	switch(file_type(str)) {
	case 0: // stdin
		printf("TODO\n");
		break;
	case 1: // .s file (assembly
		sprintf(buf, "gcc -nostdlib -o .x %s", str);
		system(buf);
		system("rsc syms-dump .x | grep _start | cut -d : -f 2 | tee .y");
		unlink(".x");
		ptr = filetostr(".y");
		unlink(".y");
		if (ptr) {
			load_shellcode_from_string(ptr);
			free(ptr);
		}
		break;
	default:
		printf("File format not supported\n");
		exit(1);
	}
	
	return 0;
}

int main(int argc, char **argv) {
	int c, listen = 0;

	if (argc<2)
		return show_helpline();

	while ((c = getopt(argc, argv, "a:VcC:ts:S:i:Ll:uhN:A:XxE:e")) != -1) {
		switch( c ) {
		case 't':
			return test();
		case 'x':
			// dump shellcode in hexa
			hexa_print = 1;
			break;
		case 'X':
			// execute
			hexa_print = 3;
			break;
		case 'C':
			C = atoi(optarg);
			break;
		case 'E':
			E = atoi(optarg);
			break;
			// dump shellcode in C
		case 'e':
			hexa_print = 4;
			break;
		case 'c':
			hexa_print = 2;
			break;
		case 'a':
			sscanf(optarg, "%x@%x", (int*) &addr, (int*) &off);
			if (!addr||!off)
				sscanf(optarg, "0%x@%x", (int*) &addr, (int*) &off);

			if (!addr||!off) {
				printf("Invalid argument for -a\n");
				return 1;
			}
			break;
		case 'A':
			A = atoi(optarg);
			break;
		case 's':
			load_shellcode_from_string(optarg);
			break;
		case 'S':
			load_shellcode_from_file(optarg);
			break;
		case 'i':
			if (!load_shellcode_from_me(optarg)) {
				printf("Cannot find shellcode '%s'\n", optarg);
				return 1;
			}
			break;
		case 'N':
			N = atoi(optarg);
			break;
		case 'V':
			printf("rasc2 "R2_VERSION"\n");
			return 0;
		case 'p':
			// prefix the contents of this file
			break;
		case 'h':
			return show_help();
		case 'l':
			listen = atoi(optarg);
			break;
		case 'u':
			printf("TODO: UDP support\n");
			break;
		case 'L':
			for(c=0;shellcodes[c].name;c++) {
				printf("%-20s  %3d   %s\n",
					shellcodes[c].name,
					shellcodes[c].len,
					shellcodes[c].desc);
			}
			return 0;
		}
	}

	print_shellcode();

	return 0;
}
