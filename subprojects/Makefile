.PHONY: default all clean

DEPS=sdb qjs zydis

ifeq ($(WANT_V35),1)
  DEPS += binaryninja
endif

ifeq ($(USE_CS4),1)
  DEPS += capstone-v4
else ifeq ($(USE_CSNEXT),1)
  DEPS += capstone-next
else
  DEPS += capstone-v5
endif

ALL=$(basename $(wildcard *.mk))

default: $(DEPS)

all: $(ALL)

clean:
	rm -rf $(ALL)

ifeq(1,1)
include *.mk
else
include sdb.mk
ifeq ($(WANT_V35),1)
  include binaryninja.mk
endif
ifeq ($(USE_CS4),1)
  include capstone-v4.mk
else ifeq ($(USE_CSNEXT),1)
  include capstone-next.mk
else
  include capstone-v5.mk
endif
include qjs.mk
include zydis.mk
endif
