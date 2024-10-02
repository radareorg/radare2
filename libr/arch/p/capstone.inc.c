#ifndef CSINC
#error Undefined CSINC
#endif

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
	// store cpu and endian too ?
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

static bool r_arch_cs_init(RArchSession *as, csh *cs_handle) {
	int mode = CSINC_MODE;
	initcs (cs_handle);
#if 0
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config);
	if (be) {
		mode = CS_MODE_BIG_ENDIAN;
	}
#endif
#if 0
	if (mode != a->cs_omode || a->config->bits != a->cs_obits) {
		if (a->cs_handle != 0) {
			cs_close (&a->cs_handle);
			a->cs_handle = 0; // unnecessary
		}
		a->cs_omode = mode;
		a->cs_obits = a->config->bits;
	}
#endif
	int ret = cs_open (CSINC_ARCH, mode, cs_handle);
	if (ret != CS_ERR_OK) {
		R_LOG_ERROR ("Capstone failed: cs_open(%#x, %#x): %s", CSINC_ARCH, mode, cs_strerror (ret));
		*cs_handle = 0;
	} else {
		cs_option (*cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
#if CS_API_MAJOR >= 4
		// R2R db/anal/emu db/cmd/cmd_ahi
		if (CSINC_ARCH == CS_ARCH_X86) {
			cs_option (*cs_handle, CS_OPT_UNSIGNED, CS_OPT_ON);
		}
#endif
	}
#if 0
	if (*cs_handle) {
		if (a->config->syntax == R_ARCH_SYNTAX_ATT) {
			cs_option (a->cs_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
#if CS_API_MAJOR >= 4
		} else if (a->config->syntax == R_ARCH_SYNTAX_MASM) {
			cs_option (a->cs_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_MASM);
#endif
		} else {
			cs_option (a->cs_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
		}
	}
#else
	if (*cs_handle) {
		switch (as->config->syntax) {
		case R_ARCH_SYNTAX_ATT:
			cs_option (*cs_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
			break;
#if CS_API_MAJOR >= 4
		case R_ARCH_SYNTAX_MASM:
			cs_option (*cs_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_MASM);
			break;
#endif
		default:
			cs_option (*cs_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
			break;
		}
	}
#endif
	return true;
}

static char *r_arch_cs_mnemonics(RArchSession *s, csh cs_handle, int id, bool json) {
	int i;
#if 0
	csh cs_handle = xnit_capstone (s->arch);
	if (cs_handle == 0) {
		a->cs_handle = cs_handle;
		return NULL;
	}
#endif

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
