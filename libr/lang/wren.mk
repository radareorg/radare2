WREN_LIB=wren/libwren.a
# OBJS+=$(WREN_LIB)
#OBJS+=p/wren.o

wren:
	git clone --depth=1 https://github.com/wren-lang/wren
	$(MAKE) $(WREN_LIB)

p/wren.o: p/wren-vm.c

$(WREN_LIB):
	cd wren/src/vm/ && $(CC) $(CFLAGS) -O3 -c *.c -DWREN_OPT_RANDOM=0 -DWREN_OPT_META=0 -I ../include -I ..
	$(AR) rvs $(WREN_LIB) wren/src/vm/*.o
	$(RANLIB) $(WREN_LIB)

PYTHON?=python

p/wren-vm.c: wren
	cd wren && $(PYTHON) util/generate_amalgamation.py > ../p/wren-vm.c
	cp -f wren/src/include/wren.h p/wren-vm.h
