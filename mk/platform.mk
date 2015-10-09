ifeq ($(OSTYPE),auto)
OSTYPE=$(shell uname | tr 'A-Z' 'a-z')
endif
ifneq (,$(findstring cygwin,${OSTYPE}))
PIC_CFLAGS=
else
ifneq (,$(findstring mingw32,${OSTYPE}))
PIC_CFLAGS=
else
ifneq (,$(findstring mingw64,${OSTYPE}))
PIC_CFLAGS=
else
ifneq (,$(findstring msys,${OSTYPE}))
PIC_CFLAGS=
else
PIC_CFLAGS=-fPIC
endif
endif
endif
endif

