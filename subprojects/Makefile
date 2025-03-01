DEPS=sdb qjs

$(info ---- checking var - $(WANT_V35))

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

all: $(DEPS)

clean:
	rm -rf $(DEPS)

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
