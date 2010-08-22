NAME=r_vm
DEPS=r_util

OBJ=p/plugins.h vm.o mmu.o reg.o extra.o setup.o stack.o op.o

include ../rules.mk

p/plugins.h:
	cd p && ${MAKE} plugins.h
