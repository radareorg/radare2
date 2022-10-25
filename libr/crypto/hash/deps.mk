
OBJS+=hash/state.o hash/hash.o hash/hamdist.o hash/crca.o hash/fletcher.o hash/sip.o
OBJS+=hash/entropy.o hash/hcalc.o hash/adler32.o hash/luhn.o hash/ssdeep.o
ifeq ($(HAVE_LIB_SSL),1)
CFLAGS+=${SSL_CFLAGS}
LDFLAGS+=${SSL_LDFLAGS}
LINK+=${SSL_LDFLAGS}
else
OBJS+=hash/md4.o hash/md5.o hash/sha1.o hash/sha2.o
endif

ifeq ($(USE_LIB_XXHASH),1)
LDFLAGS+=${LIB_XXHASH}
LINK+=${LIBXXHASH}
else
OBJS+=hash/xxhash.o
endif
