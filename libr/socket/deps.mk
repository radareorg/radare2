ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LDFLAGS+=${SSL_LDFLAGS}
endif

# OSX 10.7 (lion)
ifeq (${OSTYPE},darwin)
#LDFLAGS+=-lcrypto
# IOS doesnt allows to link against libcrypto
endif
# on solaris only
ifeq (${OSTYPE},solaris)
LDFLAGS+=-lsocket
endif
ifeq (${OSTYPE},qnx)
LDFLAGS+=-lsocket
endif
# windows
ifeq (${OSTYPE},windows)
LDFLAGS+=-lwsock32
#LDFLAGS+=-lws2_32
endif
