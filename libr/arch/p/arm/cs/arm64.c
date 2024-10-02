// 64-bit ARM
#include <r_arch.h>
#define CAPSTONE_AARCH64_COMPAT_HEADER
#include <capstone/capstone.h>
#include <capstone/arm.h>

static inline int cs_mode_for_session(RArchSession *as) {
	int mode = CS_MODE_ARM;
	if (as->config->bits == 64) {
		mode = 0;
	}
	mode |= R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config)? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	if (R_STR_ISNOTEMPTY (as->config->cpu)) {
		if (strstr (as->config->cpu, "cortex")) {
			mode |= CS_MODE_MCLASS;
		}
	}
// 	mode |= CS_MODE_V8;
	return mode;
}

#define CSINC ARM64
#define CSINC_MODE cs_mode_for_session (as)
#include "../../capstone.inc.c"

bool r_arm64_arch_cs_init(RArchSession *as, csh *cs_handle) {
	return r_arch_cs_init (as, cs_handle);
}

char *r_arm64_cs_mnemonics(RArchSession *as, csh *cs_handle, int id, bool json) {
	return r_arch_cs_mnemonics(as, *cs_handle, id, json);
}
