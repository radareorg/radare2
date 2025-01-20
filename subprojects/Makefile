DEPS=sdb v35armv7 v35arm64 qjs
ifeq ($(USE_CS4),1)
	DEPS += capstone-v4
else ifeq ($(USE_CS5),1)
	DEPS += capstone-v5
else ifeq ($(USE_CSNEXT),1)
	DEPS += capstone-next
endif

all: $(DEPS)

clean:
	rm -rf $(DEPS)

include sdb.mk
include v35armv7.mk
include v35arm64.mk
ifeq ($(USE_CS4),1)
	include capstone-v4.mk
else ifeq ($(USE_CS5),1)
	include capstone-v5.mk
else ifeq ($(USE_CSNEXT),1)
	include capstone-next.mk
endif
include qjs.mk
