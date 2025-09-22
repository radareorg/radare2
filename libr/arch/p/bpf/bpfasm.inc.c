static bool parse_instruction(RBpfSockFilter *f, BPFAsmParser *p, ut64 pc) {
	const char *mnemonic_tok = token_next (p);
	PARSE_NEED_TOKEN (mnemonic_tok);
	int mlen = r_str_nlen (mnemonic_tok, 5);
	if (mlen < 2 || mlen > 4) {
		R_LOG_ERROR ("invalid mnemonic");
	}

	char mnemonic[5] = {0};
	strncpy (mnemonic, mnemonic_tok, 4);

	int opc;
	bpf_token op[11] = {0};
	for (opc = 0; opc < (sizeof (op) / sizeof (op[0]));) {
		const char *t = token_next (p);
		if (t == NULL) {
			break;
		}
		strncpy (op[opc++], t, TOKEN_MAX_LEN);
	}

	if (TOKEN_EQ (mnemonic, "txa")) {
		f->code = BPF_MISC_TXA;
		return true;
	}
	if (TOKEN_EQ (mnemonic, "tax")) {
		f->code = BPF_MISC_TAX;
		return true;
	}

	if (TOKEN_EQ (mnemonic, "ret")) {
		f->code = BPF_RET;
		PARSE_NEED (opc == 1);
		if (is_k_tok (op[0])) {
			f->code |= BPF_K;
			return parse_k (f, op[0]);
		} else if (TOKEN_EQ (op[0], "x")) {
			f->code |= BPF_X;
			return true;
		} else if (TOKEN_EQ (op[0], "a")) {
			f->code |= BPF_A;
			return true;
		} else {
			return false;
		}
	}

	if (strncmp (mnemonic, "ld", 2) == 0) {
		return parse_ld (f, mnemonic, opc, op);
	}

	if (strncmp (mnemonic, "st", 2) == 0) {
		switch (mnemonic[2]) {
		case '\0': f->code = BPF_ST; break;
		case 'x': f->code = BPF_STX; break;
		default: return false;
		}
		// Expect: M[<k>]
		PARSE_NEED (opc == 4);
		PARSE_NEED (TOKEN_EQ (op[0], "M") || TOKEN_EQ (op[0], "m"));
		PARSE_STR (op[1], "[");
		PARSE_NEED (parse_k (f, op[2]));
		PARSE_STR (op[3], "]");
		return true;
	}

	if (mnemonic[0] == 'j') {
		return parse_j (f, mnemonic, opc, op, pc);
	}

	return parse_alu (f, mnemonic, opc, op);
}
