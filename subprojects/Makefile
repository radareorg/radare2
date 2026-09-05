.PHONY: default distdeps all clean

-include ../config-user.mk

# automatically set to 1 on dist tarball creation
PREDOWNLOADED=0
WANT_ZYDIS?=1
USE_ZYDIS?=0

DEPS=sdb

ifeq ($(WANT_QJS),1)
  DEPS += qjs
endif

ifeq ($(WANT_ZIP),1)
  ifeq ($(USE_LIB_ZIP),0)
    DEPS += otezip
  endif
endif

ifeq ($(WANT_V35),1)
  DEPS += binaryninja
endif

ifeq ($(WANT_CAPSTONE),0)
  WANT_BUNDLED_CAPSTONE=0
else ifeq ($(USE_CAPSTONE),1)
  WANT_BUNDLED_CAPSTONE=0
else
  WANT_BUNDLED_CAPSTONE=1
endif

ifeq ($(WANT_ZYDIS),1)
  ifneq ($(USE_ZYDIS),1)
    DEPS += zydis
  endif
endif

ifeq ($(WANT_BUNDLED_CAPSTONE),1)
  ifeq ($(USE_CS4),1)
    DEPS += capstone-v4
  else ifeq ($(USE_CSNEXT),1)
    DEPS += capstone-next
  else
    DEPS += capstone-v5
  endif
endif

DISTDEPS=binaryninja capstone-v5 otezip qjs sdb
EXTRADEPS=capstone-next capstone-v4
# vendored in the repo: nothing to download and the directory must survive clean
VENDOREDDEPS=zydis
ALLDEPS=$(DISTDEPS) $(EXTRADEPS) $(VENDOREDDEPS)

ifeq ($(PREDOWNLOADED),1)
	FINALDEPS=$(filter-out $(DISTDEPS), $(DEPS))
else
	FINALDEPS=$(DEPS)
endif

default: $(FINALDEPS)

distdeps: $(DISTDEPS)

all: $(ALLDEPS)

clean:
	rm -rf $(DISTDEPS) $(EXTRADEPS)
	$(MAKE) $(addsuffix _clean, $(VENDOREDDEPS))

include $(addsuffix .mk, $(ALLDEPS))
