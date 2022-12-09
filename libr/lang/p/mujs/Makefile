include ../../../../config-user.mk
MUJS_GIT=1
MUJS_SYS=$(USE_SYSMUJS)
MUJS_VER=1.3.2
MUJS_FILE=mujs-$(MUJS_VER).tar.xz
MUJS_URL=https://mujs.com/downloads/$(MUJS_FILE)
DV=mujs-${MUJS_VER}

ifeq ($(shell type wget 2> /dev/null && echo 1),1)
WGET?=wget -c --no-check-certificate -O
else
WGET?=curl -o
endif

MUJSDIR=../../../shlr/mujs

EXT_SO=$(shell r2 -H R2_LIBEXT)

all: $(MUJSDIR)

#$(MAKE) lang_mujs.$(EXT_SO)

lang_mujs.$(EXT_SO): plugin.o $(MUJSDIR)
	-$(CC) -std=c99 -flto -Oz $(DUK_CFLAGS) $(CFLAGS) -fPIC $(LDFLAGS_LIB) \
		-o lang_mujs.$(EXT_SO) plugin.c


$(MUJSDIR) mujs-sync:
ifeq ($(MUJS_SYS),1)
	# do nothing
else
ifeq ($(MUJS_GIT),1)
	[ ! -d $(MUJSDIR) ] && git clone https://github.com/ccxvii/mujs $(MUJSDIR)
	[ -d $(MUJSDIR) ] && cd $(MUJSDIR) && git pull
else
	rm -rf $(MUJS_FILE)
	$(WGET) -O $(MUJS_FILE) $(MUJS_URL)
	tar xJvf $(MUJS_FILE)
	ln -fs mujs-$(MUJS_VER) $(MUJSDIR)
endif
endif
