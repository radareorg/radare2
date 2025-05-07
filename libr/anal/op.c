/* radare - LGPL - Copyright 2010-2024 - pancake, nibble */

#include <r_anal.h>

static int defaultCycles(RAnalOp *op) {
	switch (op->type) {
	case R_ANAL_OP_TYPE_PUSH:
	case R_ANAL_OP_TYPE_POP:
	case R_ANAL_OP_TYPE_STORE:
	case R_ANAL_OP_TYPE_LOAD:
		return 2;
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_NOP:
		return 1;
	case R_ANAL_OP_TYPE_TRAP:
	case R_ANAL_OP_TYPE_SWI:
		return 4;
	case R_ANAL_OP_TYPE_SYNC:
		return 4;
	case R_ANAL_OP_TYPE_RET:
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_CALL:
		return 4;
	default:
		return 1;
	}
}

// R2R db/asm/arm.v35_64 db/asm/arm.gnu_32 db/anal/arm db/asm/arm.gnu_wd_32
// XXX deprecate!! or at least call r_arch_bath tradition
R_API int r_anal_opasm(RAnal *anal, ut64 addr, const char *s, ut8 *outbuf, int outlen) {
//	RArchConfig *ac = anal->arch->config;
	// XXX this is a hack because RArch needs to hold two pointers one for the encoder and one for the decoder plugins (optionally)
	bool arch_set = false;
	char *tmparch = NULL;
	int ret = 0;
	char *oldname = NULL;
	if (outlen > 0 && anal->arch->session) {
		// no else branch
		RArchSession *as = R_UNWRAP3 (anal, arch, session);
		RArchPluginEncodeCallback encode = R_UNWRAP3 (as, plugin, encode);
		RAnalOp *op = r_anal_op_new ();
		if (!op) {
			return -1;
		}
		if (!encode && as->encoder) {
			encode = as->encoder->plugin->encode;
			as = as->encoder;
		}
		// ok we dont have an encoder
		if (!encode) {
			oldname = strdup (as->plugin->meta.name);
			const char *arch_name = as->plugin->meta.name;
			const char *dot = strchr (arch_name, '.');
			if (dot) {
				char *an = r_str_ndup (arch_name, dot - arch_name);
				if (r_arch_use (anal->arch, anal->arch->cfg, an)) {
					if (anal->arch->session->plugin->encode) {
						tmparch = strdup (an);
					} else {
						char *an2 = r_str_newf ("%s.nz", an);
						if (r_arch_use (anal->arch, anal->arch->cfg, an2)) {
							encode = anal->arch->session->plugin->encode;
							// r_arch_use (anal->arch, anal->arch->cfg, oldname);
							// R_FREE (oldname);
							as = R_UNWRAP3 (anal, arch, session);
							tmparch = an2;
						} else {
							free (an2);
						}
					}
				}
				free (an);
			} else {
				char *an2 = r_str_newf ("%s.nz", arch_name);
				if (r_arch_use (anal->arch, anal->arch->cfg, an2)) {
					tmparch = an2;
				} else {
					free (an2);
				}
			}
			if (!tmparch) {
				r_anal_op_free (op);
				goto beach;
			}
		}
		r_anal_op_set_mnemonic (op, addr, s);
		if (!r_arch_encode (anal->arch, op, 0)) {
			int ret = r_arch_info (anal->arch, R_ARCH_INFO_INVOP_SIZE);
			if (ret < 1) {
				ret = r_arch_info (anal->arch, R_ARCH_INFO_CODE_ALIGN);
				if (ret < 1) {
					ret = 1;
				}
			}
			op->size = ret;
		}
		int finlen = R_MIN (outlen, op->size);
		ret = op->size;
		if (op->bytes && finlen > 0) {
			memcpy (outbuf, op->bytes, finlen);
		} else {
			r_anal_op_free (op);
			ret = -1;
			goto beach;
		}
		r_anal_op_free (op);
		if (oldname) {
			arch_set = true;
			r_arch_use (anal->arch, anal->arch->cfg, oldname);
			R_FREE (oldname);
		}
	} else {
		// try to find a matchiing plugin in r_arch
		r_arch_use (anal->arch, anal->config, anal->config->arch);
		if (anal->arch->session) {
			RAnalOp *op = r_anal_op_new ();
			r_anal_op_set_mnemonic (op, addr, s);
			bool res = r_arch_session_encode (anal->arch->session, op, 0);
			int finlen = R_MIN (outlen, op->size);
			if (res && op->bytes && finlen > 0) {
				memcpy (outbuf, op->bytes, finlen);
				ret = op->size; // finlen
			} else {
				r_anal_op_free (op);
				ret = -1;
				goto beach;
			}
			r_anal_op_free (op);
		}
	}
beach:
	if (tmparch) {
		if (oldname) {
			r_arch_use (anal->arch, anal->arch->cfg, oldname);
		} else if (!arch_set) {
			r_arch_use (anal->arch, anal->arch->cfg, tmparch);
		}
		free (tmparch);
	} else {
		if (oldname) {
			r_arch_use (anal->arch, anal->arch->cfg, oldname);
		}
	}
	return ret;
}

// R2_590 data and len are contained inside RAnalOp. those args must disapear same for addr.. and then we get r_arch_op xD
R_API int r_anal_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	R_RETURN_VAL_IF_FAIL (anal && op && len > 0, -1);
	r_anal_op_init (op);
#if 0
	if (len > 512) {
		eprintf ("%d\n", len);
	}
#endif
	// use core binding to set asm.bits correctly based on the addr
	// this is because of the hassle of arm/thumb
	// this causes the reg profile to be invalidated
	if (anal && anal->coreb.archBits) {
		anal->coreb.archBits (anal->coreb.core, addr);
	}
	const int codealign = anal->config->codealign;
	if (codealign > 1 && (addr % codealign)) {
		op->type = R_ANAL_OP_TYPE_ILL;
		op->addr = addr;
		op->size = codealign - (addr % codealign);
		r_anal_op_set_mnemonic (op, addr, "unaligned");
		if (op->size > len) {
			// truncated
#if 0
			ut8 *fakedata = r_mem_dup (data, op->size);
			if (fakedata) {
				r_anal_op_set_bytes (op, addr, fakedata, op->size);
				free (fakedata);
			}
#endif
		} else {
			r_anal_op_set_bytes (op, addr, data, op->size);
		}
		return -1;
	}
	int ret = R_MIN (2, len);
	if (len > 0 && anal->arch->session) {
		r_anal_op_set_bytes (op, addr, data, len);
		if (!r_arch_decode (anal->arch, op, mask) || op->size <= 0) {
			op->type = R_ANAL_OP_TYPE_ILL;
			op->size = r_anal_archinfo (anal, R_ARCH_INFO_INVOP_SIZE);
			if (op->size < 0) {
				op->size = 1;
			}
			ret = -1;
		} else {
			ret = op->size;
		}
		op->addr = addr;
		/* consider at least 1 byte to be part of the opcode */
		if (op->nopcode < 1) {
			op->nopcode = 1;
		}
	} else if (len > 0 && anal->cur && anal->cur->op) {
		ret = anal->cur->op (anal, op, addr, data, len, mask);
		if (ret < 1) {
			op->type = R_ANAL_OP_TYPE_ILL;
			op->size = r_anal_archinfo (anal, R_ARCH_INFO_INVOP_SIZE);
			if (op->size < 0) {
				op->size = 1;
				ret = -1;
			}
		}
		op->addr = addr;
		/* consider at least 1 byte to be part of the opcode */
		if (op->nopcode < 1) {
			op->nopcode = 1;
		}
	} else if (!memcmp (data, "\xff\xff\xff\xff", R_MIN (4, len))) {
		ret = -1;
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 1;
		op->type = R_ANAL_OP_TYPE_MOV; // XXX ?
		if (op->cycles == 0) {
			op->cycles = defaultCycles (op);
		}
	}
	if (!op->mnemonic && (mask & R_ARCH_OP_MASK_DISASM)) {
		if (anal->verbose) {
			R_LOG_WARN ("unhandled R_ARCH_OP_MASK_DISASM in r_anal_op");
		}
	}
	if (mask & R_ARCH_OP_MASK_HINT) {
		RAnalHint *hint = r_anal_hint_get (anal, addr);
		if (hint) {
			r_anal_op_hint (op, hint);
			r_anal_hint_free (hint);
		}
	}
	if (ret == -1) {
		free (op->mnemonic);
		op->mnemonic = strdup ("invalid");
		int minop = r_arch_info (anal->arch, R_ARCH_INFO_MINOP_SIZE);
		op->size = minop;
		ut64 nextpc = op->addr + op->size;
		if (codealign > 1) {
			op->size += (nextpc % codealign);
		}
	}
	return ret;
}

R_API bool r_anal_op_nonlinear(int t) {
	t &= R_ANAL_OP_TYPE_MASK;
	switch (t) {
	//call
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_RCALL:
	case R_ANAL_OP_TYPE_ICALL:
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_IRCALL:
	case R_ANAL_OP_TYPE_UCCALL:
	// jmp
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_MJMP:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_CJMP:
	case R_ANAL_OP_TYPE_UCJMP:
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_IJMP:
	case R_ANAL_OP_TYPE_IRJMP:
	// trap| ill| unk
	case R_ANAL_OP_TYPE_TRAP:
	case R_ANAL_OP_TYPE_ILL:
	case R_ANAL_OP_TYPE_UNK:
	case R_ANAL_OP_TYPE_SWI:
	case R_ANAL_OP_TYPE_RET:
		return true;
	default:
		return false;
	}
}

R_API bool r_anal_op_ismemref(int t) {
	t &= R_ANAL_OP_TYPE_MASK;
	switch (t) {
	case R_ANAL_OP_TYPE_LOAD:
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_STORE:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_CMP:
		return true;
	default:
		return false;
	}
}

static struct optype {
	const int type;
	const char *name;
} optypes[] = {
	{ R_ANAL_OP_TYPE_IO, "io" },
	{ R_ANAL_OP_TYPE_ACMP, "acmp" },
	{ R_ANAL_OP_TYPE_ADD, "add" },
	{ R_ANAL_OP_TYPE_SYNC, "sync" },
	{ R_ANAL_OP_TYPE_AND, "and" },
	{ R_ANAL_OP_TYPE_CALL, "call" },
	{ R_ANAL_OP_TYPE_CCALL, "ccall" },
	{ R_ANAL_OP_TYPE_CJMP, "cjmp" },
	{ R_ANAL_OP_TYPE_MJMP, "mjmp" },
	{ R_ANAL_OP_TYPE_CMP, "cmp" },
	{ R_ANAL_OP_TYPE_ILL, "ill" },
	{ R_ANAL_OP_TYPE_JMP, "jmp" },
	{ R_ANAL_OP_TYPE_LEA, "lea" },
	{ R_ANAL_OP_TYPE_LEAVE, "leave" },
	{ R_ANAL_OP_TYPE_LOAD, "load" },
	{ R_ANAL_OP_TYPE_NEW, "new" },
	{ R_ANAL_OP_TYPE_MOD, "mod" },
	{ R_ANAL_OP_TYPE_CMOV, "cmov" },
	{ R_ANAL_OP_TYPE_MOV, "mov" },
	{ R_ANAL_OP_TYPE_NOR, "nor" },
	{ R_ANAL_OP_TYPE_CAST, "cast" },
	{ R_ANAL_OP_TYPE_MUL, "mul" },
	{ R_ANAL_OP_TYPE_DIV, "div" },
	{ R_ANAL_OP_TYPE_NOP, "nop" },
	{ R_ANAL_OP_TYPE_NOT, "not" },
	{ R_ANAL_OP_TYPE_NULL, "null" },
	{ R_ANAL_OP_TYPE_OR, "or" },
	{ R_ANAL_OP_TYPE_POP, "pop" },
	{ R_ANAL_OP_TYPE_PUSH, "push" },
	{ R_ANAL_OP_TYPE_RPUSH, "rpush" },
	{ R_ANAL_OP_TYPE_REP, "rep" },
	{ R_ANAL_OP_TYPE_RET, "ret" },
	{ R_ANAL_OP_TYPE_CRET, "cret" },
	{ R_ANAL_OP_TYPE_ROL, "rol" },
	{ R_ANAL_OP_TYPE_ROR, "ror" },
	{ R_ANAL_OP_TYPE_SAL, "sal" },
	{ R_ANAL_OP_TYPE_SAR, "sar" },
	{ R_ANAL_OP_TYPE_SHL, "shl" },
	{ R_ANAL_OP_TYPE_SHR, "shr" },
	{ R_ANAL_OP_TYPE_STORE, "store" },
	{ R_ANAL_OP_TYPE_SUB, "sub" },
	{ R_ANAL_OP_TYPE_SWI, "swi" },
	{ R_ANAL_OP_TYPE_CSWI, "cswi" },
	{ R_ANAL_OP_TYPE_SWITCH, "switch" },
	{ R_ANAL_OP_TYPE_TRAP, "trap" },
	{ R_ANAL_OP_TYPE_UCALL, "ucall" },
	{ R_ANAL_OP_TYPE_RCALL, "rcall" },
	{ R_ANAL_OP_TYPE_ICALL, "icall" },
	{ R_ANAL_OP_TYPE_IRCALL, "ircall" },
	{ R_ANAL_OP_TYPE_UCCALL, "uccall" },
	{ R_ANAL_OP_TYPE_UCJMP, "ucjmp" },
	{ R_ANAL_OP_TYPE_MCJMP, "mcjmp" },
	{ R_ANAL_OP_TYPE_RCJMP, "rcjmp" },
	{ R_ANAL_OP_TYPE_UJMP, "ujmp" },
	{ R_ANAL_OP_TYPE_RJMP, "rjmp" },
	{ R_ANAL_OP_TYPE_IJMP, "ijmp" },
	{ R_ANAL_OP_TYPE_IRJMP, "irjmp" },
	{ R_ANAL_OP_TYPE_UNK, "unk" },
	{ R_ANAL_OP_TYPE_UPUSH, "upush" },
	{ R_ANAL_OP_TYPE_RPUSH, "rpush" },
	{ R_ANAL_OP_TYPE_XCHG, "xchg" },
	{ R_ANAL_OP_TYPE_XOR, "xor" },
	{ R_ANAL_OP_TYPE_CASE, "case" },
	{ R_ANAL_OP_TYPE_CPL, "cpl" },
	{ R_ANAL_OP_TYPE_CRYPTO, "crypto" },
	{ R_ANAL_OP_TYPE_LENGTH, "length" },
	{ R_ANAL_OP_TYPE_ABS, "abs" },
};

R_API int r_anal_optype_from_string(const char *type) {
	int i;
	for  (i = 0; i < R_ARRAY_SIZE (optypes); i++) {
		if (!strcmp (optypes[i].name, type)) {
			return optypes[i].type;
		}
	}
	return -1;
}

R_API const char *r_anal_optype_index(int idx) {
	if (idx < 0 || idx >= R_ARRAY_SIZE (optypes)) {
		return NULL;
	}
	return optypes[idx].name;
}

R_API const char *r_anal_optype_tostring(int t) {
	int i;
	for (i = 0; i < R_ARRAY_SIZE (optypes); i++) {
		if (optypes[i].type == t) {
			return optypes[i].name;
		}
	}
	t &= R_ANAL_OP_TYPE_MASK; // ignore the modifier bits... we don't want this!
	for (i = 0; i < R_ARRAY_SIZE (optypes); i++) {
		if (optypes[i].type == t) {
			return optypes[i].name;
		}
	}
	return "undefined";
}

R_API const char *r_anal_op_to_esil_string(RAnal *anal, RAnalOp *op) {
	return r_strbuf_tostring (&op->esil);
}

// TODO: use esil here?
R_API char *r_anal_op_tostring(RAnal *anal, RAnalOp *op) {
	RAnalBlock *bb;
	RAnalFunction *f;
	char *cstr, ret[128];
	char *r0, *a0, *a1;
	if (op->dsts.len || op->srcs.len) {
		RAnalValue *dst = r_vector_at (&op->dsts, 0);
		RAnalValue *src0 = r_vector_at (&op->srcs, 0);
		RAnalValue *src1 = r_vector_at (&op->srcs, 1);
		r0 = r_anal_value_tostring (dst);
		a0 = r_anal_value_tostring (src0);
		a1 = r_anal_value_tostring (src1);
		if (!r0) {
			r0 = strdup ("?");
		}
		if (!a0) {
			a0 = strdup ("?");
		}
		if (!a1) {
			a1 = strdup ("?");
		}
	} else {
		r0 = strdup ("?");
		a0 = strdup ("?");
		a1 = strdup ("?");
	}

	switch (op->type) {
	case R_ANAL_OP_TYPE_MOV:
		snprintf (ret, sizeof (ret), "%s = %s", r0, a0);
		break;
	case R_ANAL_OP_TYPE_CJMP:
		if ((bb = r_anal_bb_from_offset (anal, op->addr))) {
			cstr = bb->cond? r_anal_cond_tostring (bb->cond): strdup ("$z");
			snprintf (ret, sizeof (ret), "if (%s) goto 0x%"PFMT64x, cstr, op->jump);
			free (cstr);
		} else {
			snprintf (ret, sizeof (ret), "if (%s) goto 0x%"PFMT64x, "?", op->jump);
		}
		break;
	case R_ANAL_OP_TYPE_JMP:
		snprintf (ret, sizeof (ret), "goto 0x%"PFMT64x, op->jump);
		break;
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_IJMP:
	case R_ANAL_OP_TYPE_IRJMP:
		snprintf (ret, sizeof (ret), "goto %s", r0);
		break;
	case R_ANAL_OP_TYPE_PUSH:
	case R_ANAL_OP_TYPE_UPUSH:
	case R_ANAL_OP_TYPE_RPUSH:
		snprintf (ret, sizeof (ret), "push %s", a0);
		break;
	case R_ANAL_OP_TYPE_POP:
		snprintf (ret, sizeof (ret), "pop %s", r0);
		break;
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_RCALL:
	case R_ANAL_OP_TYPE_ICALL:
	case R_ANAL_OP_TYPE_IRCALL:
		snprintf (ret, sizeof (ret), "%s()", r0);
		break;
	case R_ANAL_OP_TYPE_CALL:
		f = r_anal_get_fcn_in (anal, op->jump, R_ANAL_FCN_TYPE_NULL);
		if (f) {
			snprintf (ret, sizeof (ret), "%s()", f->name);
		} else {
			snprintf (ret, sizeof (ret), "0x%"PFMT64x"()", op->jump);
		}
		break;
	case R_ANAL_OP_TYPE_CCALL:
		f = r_anal_get_fcn_in (anal, op->jump, R_ANAL_FCN_TYPE_NULL);
		if ((bb = r_anal_bb_from_offset (anal, op->addr))) {
			cstr = bb->cond? r_anal_cond_tostring (bb->cond): strdup ("$z");
			if (f) {
				snprintf (ret, sizeof (ret), "if (%s) %s()", cstr, f->name);
			} else {
				snprintf (ret, sizeof (ret), "if (%s) 0x%" PFMT64x "()", cstr, op->jump);
			}
			free (cstr);
		} else {
			if (f) {
				snprintf (ret, sizeof (ret), "if (unk) %s()", f->name);
			} else {
				snprintf (ret, sizeof (ret), "if (unk) 0x%" PFMT64x "()", op->jump);
			}
		}
		break;
	case R_ANAL_OP_TYPE_ADD:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s += %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s + %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_SUB:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s -= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s - %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_MUL:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s *= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s * %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_DIV:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s /= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s / %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_AND:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s &= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s & %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_OR:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s |= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s | %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_XOR:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s ^= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s ^ %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_LEA:
		snprintf (ret, sizeof (ret), "%s -> %s", r0, a0);
		break;
	case R_ANAL_OP_TYPE_CMP:
		memcpy (ret, ";", 2);
		break;
	case R_ANAL_OP_TYPE_NOR: // NOT + OR
		memcpy (ret, "nor", 4);
		break;
	case R_ANAL_OP_TYPE_NOP:
		memcpy (ret, "nop", 4);
		break;
	case R_ANAL_OP_TYPE_RET:
		memcpy (ret, "ret", 4);
		break;
	case R_ANAL_OP_TYPE_CRET:
		if ((bb = r_anal_bb_from_offset (anal, op->addr))) {
			cstr = bb->cond? r_anal_cond_tostring (bb->cond): strdup ("$z");
			snprintf (ret, sizeof (ret), "if (%s) ret", cstr);
			free (cstr);
		} else {
			strcpy (ret, "if (unk) ret");
		}
		break;
	case R_ANAL_OP_TYPE_LEAVE:
		memcpy (ret, "leave", 6);
		break;
	case R_ANAL_OP_TYPE_MOD:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s %%= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s %% %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_XCHG:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "tmp = %s; %s = %s; %s = tmp", r0, r0, a0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s ^ %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_ROL:
	case R_ANAL_OP_TYPE_ROR:
	case R_ANAL_OP_TYPE_SWITCH:
	case R_ANAL_OP_TYPE_CASE:
		R_LOG_ERROR ("Command not implemented");
		free (r0);
		free (a0);
		free (a1);
		return NULL;
	default:
		free (r0);
		free (a0);
		free (a1);
		return NULL;
	}
	free (r0);
	free (a0);
	free (a1);
	return strdup (ret);
}

R_API const char *r_anal_stackop_tostring(int s) {
	switch (s) {
	case R_ANAL_STACK_NULL:
		return "null";
	case R_ANAL_STACK_NOP:
		return "nop";
	case R_ANAL_STACK_INC:
		return "inc";
	case R_ANAL_STACK_GET:
		return "get";
	case R_ANAL_STACK_SET:
		return "set";
	case R_ANAL_STACK_RESET:
		return "reset";
	}
	return "unk";
}

R_API const char *r_anal_op_family_tostring(int n) {
	switch (n) {
	case R_ANAL_OP_FAMILY_UNKNOWN: return "unk";
	case R_ANAL_OP_FAMILY_CPU: return "cpu";
	case R_ANAL_OP_FAMILY_SECURITY: return "sec";
	case R_ANAL_OP_FAMILY_FPU: return "fpu";
	case R_ANAL_OP_FAMILY_VEC: return "vec";
	case R_ANAL_OP_FAMILY_PRIV: return "priv";
	case R_ANAL_OP_FAMILY_THREAD: return "thrd";
	case R_ANAL_OP_FAMILY_CRYPTO: return "crpt";
	case R_ANAL_OP_FAMILY_IO: return "io";
	case R_ANAL_OP_FAMILY_VIRT: return "virt";
	case R_ANAL_OP_FAMILY_SIMD: return "simd";
	}
	return NULL;
}

struct op_family {
	const char *name;
	int id;
};

static const struct op_family of[] = {
	{ "cpu", R_ANAL_OP_FAMILY_CPU },
	{ "fpu", R_ANAL_OP_FAMILY_FPU },
	{ "vec", R_ANAL_OP_FAMILY_VEC },
	{ "priv", R_ANAL_OP_FAMILY_PRIV },
	{ "virt", R_ANAL_OP_FAMILY_VIRT },
	{ "crypto", R_ANAL_OP_FAMILY_CRYPTO },
	{ "io", R_ANAL_OP_FAMILY_IO },
	{ "sec", R_ANAL_OP_FAMILY_SECURITY },
	{ "thread", R_ANAL_OP_FAMILY_THREAD },
	{ "simd", R_ANAL_OP_FAMILY_SIMD },
};

R_API int r_anal_op_family_from_string(const char *f) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (of); i ++) {
		if (!strcmp (f, of[i].name)) {
			return of[i].id;
		}
	}
	return R_ANAL_OP_FAMILY_UNKNOWN;
}

/* apply hint to op, return the number of hints applied */
R_API int r_anal_op_hint(RAnalOp *op, RAnalHint *hint) {
	int changes = 0;
	if (hint) {
		if (hint->val != UT64_MAX) {
			op->val = hint->val;
			changes++;
		}
		if (hint->type > 0) {
			op->type = hint->type;
			changes++;
		}
		if (hint->jump != UT64_MAX) {
			op->jump = hint->jump;
			changes++;
		}
		if (hint->fail != UT64_MAX) {
			op->fail = hint->fail;
			changes++;
		}
		if (hint->opcode) {
			/* XXX: this is not correct */
			free (op->mnemonic);
			op->mnemonic = strdup (hint->opcode);
			changes++;
		}
		if (hint->esil) {
			r_strbuf_set (&op->esil, hint->esil);
			changes++;
		}
		if (hint->size) {
			op->size = hint->size;
			changes++;
		}
	}
	return changes;
}

// returns the '33' in 'rax + 33'
// returns value for the given register name in specific address / range
// imho this should not iterate, should be just a helper to get that value
R_API int r_anal_op_reg_delta(RAnal *anal, ut64 addr, const char *name) {
	ut8 buf[32];
	anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf));
	RAnalOp op = {0};
	RAnalValue *dst = NULL;
	if (r_anal_op (anal, &op, addr, buf, sizeof (buf), R_ARCH_OP_MASK_ALL) > 0) {
		dst = r_vector_at (&op.dsts, 0);
		if (dst && dst->reg && (!name || !strcmp (dst->reg, name))) {
			if (r_vector_length (&op.srcs) > 0) {
				r_anal_op_fini (&op);
				return ((RAnalValue*)r_vector_at (&op.srcs, 0))->delta;
			}
		}
	}
	r_anal_op_fini (&op);
	return 0;
}

R_API const char *r_anal_op_direction_tostring(RAnalOp *op) {
	if (!op) {
		return "none";
	}
	switch (op->direction) {
	case R_ANAL_OP_DIR_READ:
		return "read";
	case R_ANAL_OP_DIR_WRITE:
		return "write";
	case R_ANAL_OP_DIR_EXEC:
		return "exec";
	case R_ANAL_OP_DIR_REF:
		return "ref";
	default:
		break;
	}
	return "none";
}
