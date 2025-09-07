.PHONY: default all clean

DEPS=sdb qjs

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

include *.mk
