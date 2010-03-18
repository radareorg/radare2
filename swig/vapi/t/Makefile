all: bin lang core regs hash sc socket asm search db io array list
	@true

#bin:
#	valac --vapidir=.. bin.vala --pkg r_bin --pkg r_util 

bintest:
	valac --vapidir=.. bintest.vala --pkg r_bin --pkg r_util 

regs:
	valac --vapidir=.. --pkg r_reg regs.vala --pkg r_util

lang:
	valac lang.vala --pkg r_lang --pkg r_util

array:
	valac --vapidir=.. --pkg r_util array.vala

arrayc:
	valac -C --vapidir=.. --pkg r_util array.vala

list:
	valac -o list list.vala --pkg r_util --vapidir=..

listc:
	valac -C -o list list.vala --pkg r_util --vapidir=..

genie:
	valac --vapidir=.. --pkg r_asm --pkg libr asm.gs
	valac --vapidir=.. --pkg r_search --pkg libr search.gs

io:
	valac --vapidir=${PWD}/.. --pkg r_io io.vala

db:
	valac --vapidir=${PWD}/.. --pkg r_db db.vala

sc:
	valac -C --vapidir=${PWD}/.. sc.vala --pkg r_syscall
	gcc sc.c `pkg-config gobject-2.0 --libs --cflags` -I../../include/ -lr_syscall -Wl,-R../../syscall -L../../syscall -o sc

core:
	valac -C --vapidir=${PWD}/.. core.vala --pkg r_core --pkg r_cons
	#gcc `PKG_CONFIG_PATH=../.. pkg-config --libs --cflags gobject-2.0 libr` core.c -o core
	gcc core.c `pkg-config gobject-2.0 --libs --cflags` -I../../include/ \
		-lr_core -Wl,-R../../core -L../../core \
		-lr_util -Wl,-R../../util -L../../util \
		-lr_asm -Wl,-R../../asm -L../../asm \
		-lr_bin -Wl,-R../../bin -L../../bin \
		-lr_io -Wl,-R../../io -L../../io \
		-lr_anal -Wl,-R../../anal -L../../anal \
		-lr_cons -Wl,-R../../cons -L../../cons \
		-lr_debug -Wl,-R../../debug -L../../debug \
		-lr_lang -Wl,-R../../lang -L../../lang \
		-lr_line -Wl,-R../../line -L../../line \
		-lr_lib -Wl,-R../../lib -L../../lib \
		-lr_parse -Wl,-R../../parse -L../../parse \
		-lr_flags -Wl,-R../../flags -L../../flags \
		-lr_meta -Wl,-R../../meta -L../../meta \
		-lr_macro -Wl,-R../../macro -L../../macro \
		-lr_print -Wl,-R../../print -L../../print \
		-lr_config -Wl,-R../../config -L../../config \
		-lr_search -Wl,-R../../search -L../../search \
		-lr_cmd -Wl,-R../../cmd -L../../cmd \
		-lr_hash -Wl,-R../../hash -L../../hash \
		-lr_reg -Wl,-R../../reg -L../../reg \
		-lr_bp -Wl,-R../../bp -L../../bp \
		-g -o core

search:
	valac -C --vapidir=${PWD}/.. search.vala --pkg r_search
	gcc search.c `pkg-config gobject-2.0 --libs --cflags` -I../../include/ \
		-lr_search -Wl,-R../../search -L../../search \
		-lr_util -Wl,-R../../util -L../../util \
		-g -o search
	
asm:
	valac --vapidir=.. --pkg r_asm asm.vala

bin:
	valac -C --vapidir=${PWD}/.. bin.vala --pkg r_bin --pkg r_util
	gcc bin.c `pkg-config gobject-2.0 --libs --cflags` -I../../../libr/include/ \
		-lr_bin -Wl,-R../../../libr/bin -L../../../libr/bin \
		-lr_util -Wl,-R../../../libr/util -L../../../libr/util \
		-g -o bin

hash:
	valac -C --vapidir=${PWD}/.. hash.vala --pkg r_hash
	gcc hash.c `pkg-config gobject-2.0 --libs --cflags` -I../../include/ -lr_hash -Wl,-R../../hash -L../../hash -o hash

socket:
	#valac -C --profile=posix --vapidir=${PWD}/.. socket.vala --pkg r_socket
	valac -C --vapidir=${PWD}/.. socket.vala --pkg r_socket --pkg posix
	gcc socket.c `pkg-config gobject-2.0 --libs --cflags` -I../../include/ -lr_socket -Wl,-R../../socket -L../../socket -o socket

clean:
	-rm -f *.c hash sc *.o *.h core socket asm search bin io
