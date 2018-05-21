ifeq ($(OSTYPE),auto)
OSTYPE=$(shell uname | tr 'A-Z' 'a-z')
endif
ifneq (,$(findstring cygwin,${OSTYPE}))
PIC_CFLAGS=
CFLAGS+=-DUNICODE -D_UNICODE
else
ifneq (,$(findstring mingw32,${OSTYPE}))
PIC_CFLAGS=
CFLAGS+=-DUNICODE -D_UNICODE
else
ifneq (,$(findstring mingw64,${OSTYPE}))
PIC_CFLAGS=
CFLAGS+=-DUNICODE -D_UNICODE
else
ifneq (,$(findstring msys,${OSTYPE}))
PIC_CFLAGS=
CFLAGS+=-DUNICODE -D_UNICODE
else
ifneq (,$(findstring windows,${OSTYPE}))
PIC_CFLAGS=
CFLAGS+=-DUNICODE -D_UNICODE
else
ifeq ($(CC),cccl)
PIC_CFLAGS=
CFLAGS+=-DUNICODE -D_UNICODE
else
PIC_CFLAGS=-fPIC
endif
endif
endif
endif
endif
endif
