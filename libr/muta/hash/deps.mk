
OBJS+=hash/state.o hash/hash.o hash/hamdist.o hash/crca.o hash/fletcher.o
OBJS+=hash/entropy.o hash/hcalc.o hash/adler32.o hash/luhn.o hash/ssdeep.o

ifeq ($(WANT_SSL_CRYPTO),1)
CFLAGS+=${SSL_CFLAGS}
LDFLAGS+=${SSL_LDFLAGS}
LDFLAGS+=-lcrypto
LINK+=${SSL_LDFLAGS}
OBJS+=hash/sip_ssl.o
else
OBJS+=hash/sip.o
endif

OBJS+=hash/md4.o hash/md5.o hash/sha1.o hash/sha2.o

ifeq ($(USE_LIB_XXHASH),1)
LDFLAGS+=${LIB_XXHASH}
LINK+=${LIBXXHASH}
else
OBJS+=hash/xxhash.o
endif
