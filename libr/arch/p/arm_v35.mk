# include ../config.mk
include ../../config-user.mk
include ../../global.mk

N=arch_arm_v35
# V35ARM64_HOME=$(TOP)/subprojects/v35arm64/disassembler
V35ARM64_HOME=$(TOP)/subprojects/binaryninja/arch/arm64/disassembler

include p/arm/v35/deps-arm64.mk

OBJ_ARM_V35=p/arm/plugin_v35.o
OBJ_ARM_V35+=$(V35ARM64_LINK)
# V35ARM64_LDFLAGS+=p/arm/v35/v35arm64.a
# LDFLAGS+=p/arm/v35/v35arm64.a
# LDFLAGS+=$(V35ARM64_LINK)

STATIC_OBJ+=${OBJ_ARM_V35}

CFLAGS+=$(V35ARM64_CFLAGS)
TARGET_ARM_V35=$(N).${LIBEXT}

ALL_TARGETS+=$(TARGET_ARM_V35)

$(TARGET_ARM_V35):
	${CC} $(V35ARM64_CFLAGS) ${CFLAGS} $(call libname,$(N)) \
		-lr_util -lr_search -o $(TARGET_ARM_V35) \
		${OBJ_ARM_V35} $(V35ARM64_LDFLAGS)
