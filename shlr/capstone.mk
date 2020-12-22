ifeq ($(USE_CAPSTONE),1)
LINK+=${CAPSTONE_LDFLAGS}
else
LINK+=$(SHLR)/capstone/libcapstone.a
endif
