ifeq ($(WANT_CAPSTONE),1)
ifeq ($(USE_CAPSTONE),1)
LINK+=${CAPSTONE_LDFLAGS}
else
LINK+=$(CS_ROOT)/libcapstone.a
endif
else
# nothing
endif
