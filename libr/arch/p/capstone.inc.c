#ifndef R_ARCH_CAPSTONE_HELPER_INC_C
#define R_ARCH_CAPSTONE_HELPER_INC_C

typedef struct {
	cs_detail detail;
	cs_insn insn;
} RArchCSInsn;

static inline bool r2cs_disasm(csh handle, const uint8_t **code, size_t *size, uint64_t *addr, RArchCSInsn *ci) {
	ci->insn.detail = &ci->detail;
	// capstone post printers inspect the mnemonic before fill_insn writes it
	ci->insn.mnemonic[0] = 0;
	return cs_disasm_iter (handle, code, size, addr, &ci->insn);
}

static inline bool r2cs_disasm_iter(csh handle, const ut8 *buf, int len, ut64 addr, RArchCSInsn *ci) {
	if (len < 1) {
		return false;
	}
	const uint8_t *code = (const uint8_t *)buf;
	size_t size = len;
	uint64_t iter_addr = addr;
	return r2cs_disasm (handle, &code, &size, &iter_addr, ci);
}

#endif

#ifdef CSINC

#ifndef CSINC_MODE
#define CSINC_MODE 0
#endif

#define TOKEN_PASTE(x, y) x ## y

#define CSINC_INS_ENDING CSINC_INS_ENDING_(CSINC)
#define CSINC_INS_ENDING_(y) TOKEN_PASTE(y, _INS_ENDING)

#define CSINC_ARCH CSINC_ARCH_(CSINC)
#define CSINC_ARCH_(y) TOKEN_PASTE(CS_ARCH_, y)

typedef struct {
	csh cs_handle;
	int cs_mode;
	int cs_bits;
	int cs_syntax;
	bool bigendian;
	char *cpu;
} CapstonePluginData;

static void initcs(csh *ud) {
	cs_opt_mem mem = {
		.malloc = malloc,
		.calloc = calloc,
		.realloc = realloc,
		.free = free,
		.vsnprintf = vsnprintf,
	};
	cs_option (*ud, CS_OPT_MEM, (size_t)&mem);
}

static bool r2cs_open(RArchSession *as, int mode, csh *cs_handle) {
	initcs (cs_handle);
	int ret = cs_open (CSINC_ARCH, mode, cs_handle);
	if (ret != CS_ERR_OK) {
		R_LOG_ERROR ("Capstone failed: cs_open(%#x, %#x): %s", CSINC_ARCH, mode, cs_strerror (ret));
		*cs_handle = 0;
		return false;
	}
	cs_option (*cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
	// R2R db/anal/emu db/cmd/cmd_ahi
	if (CSINC_ARCH == CS_ARCH_X86) {
		cs_option (*cs_handle, CS_OPT_UNSIGNED, CS_OPT_ON);
	}
	if (CSINC_ARCH == CS_ARCH_MIPS) {
		cs_option (*cs_handle, CS_OPT_SYNTAX, as->config->syntax == R_ARCH_SYNTAX_REGNUM
			? CS_OPT_SYNTAX_NOREGNAME: CS_OPT_SYNTAX_DEFAULT);
	} else {
		switch (as->config->syntax) {
		case R_ARCH_SYNTAX_ATT:
			cs_option (*cs_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
#if CS_API_MAJOR >= 6
			if (CSINC_ARCH == CS_ARCH_X86) {
				cs_option (*cs_handle, CS_OPT_DETAIL, CS_OPT_DETAIL_INTEL_ORDER);
			}
#endif
			break;
		case R_ARCH_SYNTAX_MASM:
			cs_option (*cs_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_MASM);
			break;
		default:
			cs_option (*cs_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
			break;
		}
	}
	return true;
}

static inline csh r2cs_update_handle(RArchSession *as, CapstonePluginData *cpd, bool *config_changed) {
	R_RETURN_VAL_IF_FAIL (as && cpd, 0);
	const char *cpu = as->config->cpu;
	const bool bigendian = R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config);
	const int bits = as->config->bits;
	const int syntax = as->config->syntax;
	const bool same_cpu = cpu? cpd->cpu && !strcmp (cpu, cpd->cpu): !cpd->cpu;
	const bool same_config = cpd->cs_handle && same_cpu && cpd->cs_bits == bits && cpd->bigendian == bigendian;
	if (config_changed) {
		*config_changed = !same_config;
	}
	if (same_config && cpd->cs_syntax == syntax) {
		return cpd->cs_handle;
	}
	char *new_cpu = !same_cpu && cpu? strdup (cpu): NULL;
	if (!same_cpu && cpu && !new_cpu) {
		return 0;
	}
	const int mode = same_config? cpd->cs_mode: (CSINC_MODE);
	if (!cpd->cs_handle || cpd->cs_mode != mode || cpd->cs_syntax != syntax) {
		csh handle = 0;
		if (!r2cs_open (as, mode, &handle)) {
			free (new_cpu);
			return 0;
		}
		cs_close (&cpd->cs_handle);
		cpd->cs_handle = handle;
		cpd->cs_mode = mode;
	}
	if (!same_cpu) {
		free (cpd->cpu);
		cpd->cpu = new_cpu;
	}
	cpd->bigendian = bigendian;
	cpd->cs_bits = bits;
	cpd->cs_syntax = syntax;
	return cpd->cs_handle;
}

static inline csh r2cs_handle(RArchSession *as, CapstonePluginData *cpd) {
	return r2cs_update_handle (as, cpd, NULL);
}

static inline void r2cs_fini(CapstonePluginData *cpd) {
	if (cpd) {
		cs_close (&cpd->cs_handle);
		free (cpd->cpu);
		memset (cpd, 0, sizeof (*cpd));
	}
}

static char *r2cs_mnemonics(RArchSession *s, csh cs_handle, int id, bool json) {
	if (!cs_handle) {
		return NULL;
	}

	PJ *pj = NULL;
	if (id != -1) {
		const char *name = cs_insn_name (cs_handle, id);
		if (name) {
			if (json) {
				pj = pj_new ();
				pj_a (pj);
				pj_s (pj, name);
				pj_end (pj);
				return pj_drain (pj);
			}
			return strdup (name);
		}
		return NULL;
	}

	RStrBuf *buf = NULL;
	if (json) {
		pj = pj_new ();
		pj_a (pj);
	} else {
		buf = r_strbuf_new ("");
	}
	int i;
	for (i = 1; i < CSINC_INS_ENDING; i++) {
		const char *op = cs_insn_name (cs_handle, i);
		if (!op) {
			continue;
		}
		if (pj) {
			pj_s (pj, op);
		} else {
			r_strbuf_append (buf, op);
			r_strbuf_append (buf, "\n");
		}
	}
	if (pj) {
		pj_end (pj);
	}
	return pj? pj_drain (pj): r_strbuf_drain (buf);
}

#endif
