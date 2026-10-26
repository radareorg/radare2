#ifndef R2_ARM_CODE_ENDIAN_H
#define R2_ARM_CODE_ENDIAN_H

#include <r_arch.h>

static inline bool arm_code_is_be(RArchConfig *config) {
	return !(R_STR_ISNOTEMPTY (config->abi) && strstr (config->abi, "be8"))
		&& R_ARCH_CONFIG_IS_BIG_ENDIAN (config);
}

#endif
