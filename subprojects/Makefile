.PHONY: default all clean

-include ../config-user.mk

DEPS=sdb qjs otezip

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

ifeq ($(WANT_BUNDLED_CAPSTONE),1)
  ifeq ($(USE_CS4),1)
    DEPS += capstone-v4
  else ifeq ($(USE_CSNEXT),1)
    DEPS += capstone-next
  else
    DEPS += capstone-v5
  endif
endif

ALL=$(basename $(wildcard *.mk))

default: $(DEPS)

all: $(ALL)

clean:
	rm -rf $(ALL)

include $(addsuffix .mk,$(DEPS))
