// 
// Copyright (c) 2016 - LGPL, SkUaTeR, All rights reserved.

#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>
#include <libbochs.h>
#define eprintf(x,y...) \ 
{ FILE * myfile;  myfile=fopen("logio.txt","a"); fprintf(myfile,x,##y);fflush(myfile);fclose(myfile); }

typedef struct {
	libbochs_t desc;    
} RIOBochs;

static libbochs_t *desc = NULL; 
static RIODesc *riobochs = NULL;

static int __plugin_open(RIO *io, const char *file, ut8 many) {
	return !strncmp (file, "bochs://", strlen ("bochs://"));
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	RIOBochs  *riob;
	eprintf("io_open\n");
	char * archivoBochs;
	char * archivoCfg;
	int i,l;
	if (!__plugin_open (io, file, 0))
		return NULL;
	if (riobochs) {
		return riobochs;
	}
	archivoBochs=malloc(1024);
	archivoCfg= malloc (1024);

       	i=strstr(&file[8],"#");
	if (i)
	{
		l=i - (DWORD)&file[8];
		strncpy(archivoBochs,&file[8],l<1024?l:1024);
		archivoBochs[l]=0;

		l=strlen(i+1);
		strncpy(archivoCfg,i+1,l<1024?l:1024);
		archivoCfg[l]=0;
	}
	else
	{
		free(archivoBochs);
		free(archivoCfg);
		eprintf("Error cant find : \n");
		return NULL;
	}
	riob = R_NEW0 (RIOBochs);

	// Inicializamos
	if (bochs_open_(&riob->desc,archivoBochs,archivoCfg) == TRUE)
	{
		desc = &riob->desc;
		riobochs = r_io_desc_new (&r_io_plugin_bochs, -1, file, rw, mode, riob);
		//riogdb = r_io_desc_new (&r_io_plugin_gdb, riog->desc.sock->fd, file, rw, mode, riog);
		//free(archivoBochs);
		//free(archivoCfg);
		return riobochs;
	}
	eprintf ("bochsio.open: Cannot connect to bochs.\n");
	free (riob);
	return NULL;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	eprintf("io_write\n");
	return -1;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	eprintf("io_seek %016"PFMT64x" \n",offset);
	return offset;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	memset (buf, 0xff, count);
	ut64 addr = io->off;
	if (!desc || !desc->data) return -1;
        eprintf("io_read ofs= %016"PFMT64x" count= %x\n",io->off,count);
	bochs_read_(desc,addr,count,buf);
	return count;
}

static int __close(RIODesc *fd) {
	eprintf("io_close\n");
	bochs_close_(desc);
	return true;
}
	
static int __system(RIO *io, RIODesc *fd, const char *cmd) {
        eprintf("system command (%s)\n", cmd);
        if (!strcmp (cmd, "help")) {
                eprintf ("Usage: =!cmd args\n"
                        " =!:<bochscmd>      - Send a bochs command.\n"
                        " =!dobreak          - pause bochs.\n");
			
	} else if (!strncmp (cmd, ":", 1)) {
		eprintf("io_system: Enviando comando bochs\n");
		EnviaComando_(desc,&cmd[1],TRUE);
		io->cb_printf ("%s\n", desc->data);
		return 1;
	} else if (!strncmp (cmd, "dobreak", 7)) {
		CommandStop_(desc);
		io->cb_printf ("%s\n", desc->data);
		return 1;
	}         
        return true;
}

RIOPlugin r_io_plugin_bochs  = {
	.name = "bochs",
	.desc = "Attach to a BOCHS debugger",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.write = __write,
	.plugin_open = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.isdbg = true
};
