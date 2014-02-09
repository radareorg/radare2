/* radare - LGPL - Copyright 2014 condret@runas-racer.com */

#include <r_types.h>
#include <r_lib.h>
#include <r_cmd.h>
#include <r_core.h>
#include <r_io.h>
#include <r_cons.h>
#include <string.h>

static void print_2bpp_row(ut8 * buf)
{
	int i, c = 0;
	for(i=0; i<8; i++) {
		if(buf[1]&( (1<<7) >>i))
			c = 2;
		if(buf[0]&( (1<<7) >>i))
			c++;
		switch(c) {
			case 0:
				r_cons_printf(Color_BGWHITE"  ");
				break;
			case 1:
				r_cons_printf(Color_BGRED"  ");
				break;
			case 2:
				r_cons_printf(Color_BGBLUE"  ");
				break;
			case 3:
				r_cons_printf(Color_BGBLACK"  ");
		}
		c = 0;
	}
}

static int call(void *user, const char *cmd) {
	if (!(cmd[0] == 'p' && cmd[1] == '2' && cmd[2] == 'b' && cmd[3] == 'p' && cmd[4] == 'p'))
		return R_FALSE;
	RCore *core = (RCore *) user;
	int i, t = 1, ct;
	if(strlen(cmd)>6)
		t = atoi(strchr(cmd,' ')+1);
	ut8 buf[16*t];
	r_io_read_at(core->io, core->offset, buf, 16*t);
	for(i=0; i<8; i++) {
		for(ct=0; ct<t; ct++)
			print_2bpp_row(buf+(2*i)+(ct*16));
		r_cons_printf(Color_RESET"\n");
	}
	return R_TRUE;
}

struct r_cmd_plugin_t r_cmd_plugin_2bpp = {
	.name = "2bpp",
	.desc = "Look at data as if they were gb-2bpp. usage: p2bpp [number_of_tiles]",
	.call = call,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_CMD,
	.data = &r_cmd_plugin_2bpp
};
#endif
