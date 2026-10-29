/* radare2 - GPL - Copyright 2026 - pancake */

// Port IO occupies a separate synthetic ESIL address space above CPU memory.
static void z80_szp(RStrBuf *e) {
	r_strbuf_append (e, "0xff,t2,&,t2,=,t2,!,Z,=,7,t2,>>,S,=,4,t2,>>,t2,^,t3,=,2,t3,>>,t3,^,t3,=,1,t3,>>,t3,^,1,&,!,P,=,0x28,t2,&,f,|=,");
}

static void z80_alu(RStrBuf *e, int kind, const char *src, bool wide) {
	int bits = wide? 16: 8;
	const char *dst = wide? "hl": "a";
	bool sub = kind == 2 || kind == 3 || kind == 7;
	bool carry = kind == 1 || kind == 3;
	r_strbuf_appendf (e, "%s,t0,=,%s,t1,=,", dst, src);
	if (kind >= 4 && kind <= 6) {
		r_strbuf_appendf (e, "t1,t0,%s,t2,=,0,f,=,", kind == 4? "&": kind == 5? "^": "|");
		z80_szp (e);
		if (kind == 4) {
			r_strbuf_append (e, "1,H,=,");
		}
	} else {
		r_strbuf_appendf (e, "%s,t1,%st0,%s,t2,=,", carry? "C,t3,=,": "0,t3,=,", carry? "t3,+,": "", sub? "-": "+");
		r_strbuf_appendf (e, "0x%04x,t2,&,t4,=,0,f,=,%d,N,=,t4,!,Z,=,%d,t4,>>,S,=,0x28,%st4,>>,&,f,|=,",
			wide? 0xffff: 0xff, sub, bits - 1, wide? "8,": "0,");
		// Half carry and signed overflow use the original operands and full result.
		r_strbuf_appendf (e, "%d,t0,t1,^,t2,^,>>,1,&,H,=,", wide? 12: 4);
		r_strbuf_appendf (e, "%d,t0,t2,^,t0,t1,^,%s&,>>,1,&,P,=,", bits - 1, sub? "": "0xffff,^,");
		r_strbuf_appendf (e, "%d,t2,>>,1,&,C,=,", bits);
	}
	if (kind != 7) {
		r_strbuf_appendf (e, "t2,%s,=,", dst);
	}
}

static void z80_push(RStrBuf *e, const char *src) {
	r_strbuf_appendf (e, "2,sp,-=,%s,sp,=[2],", src);
}

static void z80_pop(RStrBuf *e, const char *dst) {
	r_strbuf_appendf (e, "sp,[2],%s,=,2,sp,+=,", dst);
}

static void z80_exchange(RStrBuf *e, const char *a, const char *b) {
	r_strbuf_appendf (e, "%s,t0,=,%s,%s,=,t0,%s,=,", a, b, a, b);
}

static void z80_cb(RAnalOp *op, ut8 code, const char *src, const char *dst, const char *copy) {
	RStrBuf *e = &op->esil;
	int x = code >> 6, y = (code >> 3) & 7;
	op->type = x == 1? R_ANAL_OP_TYPE_AND: R_ANAL_OP_TYPE_MOV;
	r_strbuf_appendf (e, "%s,t0,=,", src);
	if (x == 1) {
		r_strbuf_appendf (e, "1,C,&,f,=,1,H,=,%u,t0,&,!,Z,=,Z,P,=,%sS,=,0x28,t0,&,f,|=,", 1 << y, y == 7? "7,t0,>>,": "0,");
		return;
	}
	if (x >= 2) {
		r_strbuf_appendf (e, "%u,t0,%s,t2,=,", x == 2? 255 ^ (1 << y): 1 << y, x == 2? "&": "|");
	} else {
		const char *expr[] = {
			"7,t0,>>,1,t0,<<,|", "7,1,t0,&,<<,1,t0,>>,|",
			"C,1,t0,<<,|", "7,C,<<,1,t0,>>,|",
			"1,t0,<<", "0x80,t0,&,1,t0,>>,|", "1,1,t0,<<,|", "1,t0,>>"
		};
		r_strbuf_appendf (e, "%s,t2,=,0,f,=,%s,1,&,C,=,", expr[y], (y & 1)? "t0": "7,t0,>>");
		z80_szp (e);
	}
	r_strbuf_appendf (e, "t2,%s,", dst);
	if (copy) {
		r_strbuf_appendf (e, "t2,%s,=,", copy);
	}
}

static bool z80_esil(RAnalOp *op, const ut8 *data, int len) {
	static const char *r[] = { "b", "c", "d", "e", "h", "l", "hl,[1]", "a" };
	static const char *w[] = { "b,=", "c,=", "d,=", "e,=", "h,=", "l,=", "hl,=[1]", "a,=" };
	static const char *cc[] = { "Z,!", "Z", "C,!", "C", "P,!", "P", "S,!", "S" };
	const char *rp[] = { "bc", "de", "hl", "sp" };
	const char *rp2[] = { "bc", "de", "hl", "af" };
	const char *rr[8], *ww[8];
	memcpy (rr, r, sizeof (rr));
	memcpy (ww, w, sizeof (ww));
	RStrBuf *e = &op->esil;
	int prefix = 0, at = 0;
	const char *index = NULL;
	if (data[0] == 0xdd || data[0] == 0xfd) {
		prefix = 4;
		index = data[0] == 0xdd? "ix": "iy";
		rp[2] = rp2[2] = index;
		at++;
	}
	ut8 code = data[at++];
	int x = code >> 6, y = (code >> 3) & 7, z = code & 7, p = y >> 1, q = y & 1;
	char mem[64], store[64], hi[16], lo[16];
	bool displacement = index && (code == 0xcb || (x == 1 && code != 0x76 && (y == 6 || z == 6)) || (x == 2 && z == 6) || (x == 0 && y == 6 && z >= 4 && z <= 6));
	if (index) {
		snprintf (hi, sizeof (hi), "%sh", index);
		snprintf (lo, sizeof (lo), "%sl", index);
		rr[4] = hi;
		rr[5] = lo;
		// LD H/L,(IX+d) and LD (IX+d),H/L use the ordinary H/L registers.
		if (x == 1 && (y == 6 || z == 6)) {
			rr[4] = "h";
			rr[5] = "l";
		}
		if (displacement) {
			snprintf (mem, sizeof (mem), "0xffff,%d,%s,+,&", (st8)data[at++], index);
		} else {
			snprintf (mem, sizeof (mem), "%s", index);
		}
		snprintf (store, sizeof (store), "%s,=[1]", mem);
		ww[6] = store;
		r_strbuf_appendf (e, "%s,t5,=,", mem);
		rr[6] = "t5,[1]";
		ww[4] = !strcmp (rr[4], "h")? "h,=": data[0] == 0xdd? "ixh,=": "iyh,=";
		ww[5] = !strcmp (rr[5], "l")? "l,=": data[0] == 0xdd? "ixl,=": "iyl,=";
	}
	if (at > len) {
		return false;
	}
	ut16 nn = at + 1 < len? r_read_le16 (data + at): 0;
	char immediate[32];
	snprintf (immediate, sizeof (immediate), "%u", at < len? data[at]: 0);
	op->cycles = 4 + prefix;
	if (op->type == R_ANAL_OP_TYPE_UNK) {
		op->type = R_ANAL_OP_TYPE_MOV;
	}
	if (code == 0xcb) {
		ut8 cb = data[at];
		z80_cb (op, cb, index? rr[6]: rr[cb & 7], index? ww[6]: ww[cb & 7], index && (cb & 7) != 6 && (cb >> 6) != 1? r[cb & 7]: NULL);
		op->size = at + 1;
		op->cycles = index? ((cb >> 6) == 1? 20: 23): (cb & 7) == 6? ((cb >> 6) == 1? 12: 15): 8;
		return op->size <= len;
	}
	if (code == 0xed) {
		code = data[at++];
		x = code >> 6; y = (code >> 3) & 7; z = code & 7; p = y >> 1; q = y & 1;
		nn = at + 1 < len? r_read_le16 (data + at): 0;
		op->size = at;
		op->cycles = 8;
		if (x == 1) {
			switch (z) {
			case 0:
				r_strbuf_append (e, "0x1000000,bc,+,[1],t2,=,1,f,&,f,=,");
				z80_szp (e);
				if (y != 6) {
					r_strbuf_appendf (e, "t2,%s,", w[y]);
				}
				op->cycles = 12;
				break;
			case 1:
				r_strbuf_appendf (e, "%s,0x1000000,bc,+,=[1],", y == 6? "0": r[y]);
				op->cycles = 12;
				break;
			case 2:
				z80_alu (e, q? 1: 3, rp[p], true);
				op->cycles = 15;
				break;
			case 3:
				r_strbuf_set (e, "");
				if (q) {
					r_strbuf_appendf (e, "%u,[2],%s,=,", nn, rp[p]);
				} else {
					r_strbuf_appendf (e, "%s,%u,=[2],", rp[p], nn);
				}
				op->size += 2;
				op->cycles = 20;
				break;
			case 4:
				r_strbuf_append (e, "a,t6,=,0,a,=,");
				z80_alu (e, 2, "t6", false);
				break;
			case 5:
				z80_pop (e, "pc");
				r_strbuf_append (e, "iff2,iff1,=,");
				op->cycles = 14;
				break;
			case 6: {
				static const int modes[] = { 0, 0, 1, 2, 0, 0, 1, 2 };
				r_strbuf_appendf (e, "%d,im,=,", modes[y]);
				break;
			}
			case 7:
				if (y < 2) {
					r_strbuf_appendf (e, "a,%s,=,", y? "r": "i");
				} else if (y < 4) {
					r_strbuf_appendf (e, "%s,t2,=,1,f,&,f,=,", y == 2? "i": "r");
					z80_szp (e);
					r_strbuf_append (e, "iff2,P,=,t2,a,=,");
				} else if (y < 6) {
					r_strbuf_append (e, "hl,[1],t0,=,a,t1,=,");
					r_strbuf_append (e, y == 4? "4,t0,>>,4,t1,<<,0xf0,&,|,hl,=[1],0xf0,t1,&,0xf,t0,&,|,a,=,": "4,t0,<<,0xf0,&,0xf,t1,&,|,hl,=[1],0xf0,t1,&,4,t0,>>,|,a,=,");
					r_strbuf_append (e, "a,t2,=,1,f,&,f,=,");
					z80_szp (e);
				}
				op->cycles = y >= 4? 18: 9;
				break;
			}
		} else if (x == 2 && y >= 4 && z <= 3) {
			bool dec = y & 1, repeat = y & 2;
			if (z == 0) {
				r_strbuf_append (e, "hl,[1],de,=[1],1,bc,-=,0xc1,f,&,f,=,bc,!,!,P,=,");
			} else if (z == 1) {
				r_strbuf_append (e, "C,t6,=,");
				z80_alu (e, 7, "hl,[1]", false);
				r_strbuf_append (e, "t6,C,=,1,bc,-=,bc,!,!,P,=,");
			} else {
				r_strbuf_append (e, z == 2? "0x1000000,bc,+,[1],hl,=[1],": "hl,[1],0x1000000,bc,+,=[1],");
				r_strbuf_append (e, "1,b,-=,b,!,Z,=,1,N,=,");
			}
			r_strbuf_appendf (e, "1,hl,%s=,", dec? "-": "+");
			if (!z) {
				r_strbuf_appendf (e, "1,de,%s=,", dec? "-": "+");
			}
			if (repeat) {
				r_strbuf_appendf (e, "%s,%s?{,2,pc,-=,},", z < 2? "bc": "b", z == 1? "Z,!,&,": "");
				op->failcycles = 16;
			}
			op->cycles = repeat? 21: 16;
		}
		return op->size <= len;
	}
	op->size = at;
	if (x == 1) {
		if (code == 0x76) {
			r_strbuf_append (e, "1,halted,=,");
		} else {
			r_strbuf_appendf (e, "%s,%s,", rr[z], ww[y]);
			op->cycles = prefix + (y == 6 || z == 6? (index? 15: 7): 4);
		}
	} else if (x == 2) {
		z80_alu (e, y, rr[z], false);
		op->cycles = prefix + (z == 6? (index? 15: 7): 4);
	} else if (x == 0) {
		switch (z) {
		case 0:
			if (y == 1) {
				z80_exchange (e, "af", "af2");
			} else if (y >= 2) {
				op->size++;
				ut16 target = op->addr + op->size + (st8)data[at];
				if (y == 2) {
					r_strbuf_append (e, "1,b,-=,b,?{,");
				} else if (y >= 4) {
					r_strbuf_appendf (e, "%s,?{,", cc[y - 4]);
				}
				r_strbuf_appendf (e, "%u,pc,=,", target);
				if (y != 3) {
					r_strbuf_append (e, "},");
				}
				op->cycles = y == 2? 13: 12;
				op->failcycles = y == 2? 8: y >= 4? 7: 0;
			}
			break;
		case 1:
			if (!q) {
				r_strbuf_appendf (e, "%u,%s,=,", nn, rp[p]);
				op->size += 2;
				op->cycles = 10 + prefix;
			} else {
				r_strbuf_appendf (e, "%s,t0,=,%s,t1,=,t1,t0,+,t2,=,0xc4,f,&,f,=,12,t0,t1,^,t2,^,>>,1,&,H,=,16,t2,>>,1,&,C,=,8,t2,>>,0x28,&,f,|=,t2,%s,=,", rp[2], rp[p], rp[2]);
				op->cycles = 11 + prefix;
			}
			break;
		case 2:
			if (p < 2) {
				r_strbuf_appendf (e, q? "%s,[1],a,=,": "a,%s,=[1],", rp[p]);
			} else if (p == 2) {
				if (q) {
					r_strbuf_appendf (e, "%u,[2],%s,=,", nn, rp[2]);
				} else {
					r_strbuf_appendf (e, "%s,%u,=[2],", rp[2], nn);
				}
			} else {
				r_strbuf_appendf (e, q? "%u,[1],a,=,": "a,%u,=[1],", nn);
			}
			if (p >= 2) {
				op->size += 2;
			}
			op->cycles = prefix + (p < 2? 7: p == 2? 16: 13);
			break;
		case 3:
			r_strbuf_appendf (e, "1,%s,%s=,", rp[p], q? "-": "+");
			op->cycles = 6 + prefix;
			break;
		case 4:
		case 5:
			r_strbuf_appendf (e, "%s,t0,=,1,t0,%s,t2,=,1,f,&,f,=,%d,N,=,4,t0,t2,^,>>,1,&,H,=,t0,%u,==,$z,P,=,", rr[y], z == 5? "-": "+", z == 5, z == 5? 128: 127);
			z80_szp (e);
			// INC/DEC use overflow rather than parity.
			r_strbuf_appendf (e, "t0,%u,==,$z,P,=,t2,%s,", z == 5? 128: 127, ww[y]);
			op->cycles = prefix + (y == 6? (index? 19: 11): 4);
			break;
		case 6:
			r_strbuf_appendf (e, "%s,%s,", immediate, ww[y]);
			op->size++;
			op->cycles = prefix + (y == 6? (index? 15: 10): 7);
			break;
		case 7:
			if (y < 4) {
				r_strbuf_append (e, "f,t6,=,");
				z80_cb (op, y * 8 + 7, "a", "a,=", NULL);
				r_strbuf_append (e, "0xc4,t6,&,0x29,f,&,|,f,=,");
			} else if (y == 4) {
				r_strbuf_append (e, "a,t0,=,C,t1,=,0,t3,=,H,9,0xf,a,&,>,N,!,&,|,?{,6,t3,=,},C,0x99,t0,>,N,!,&,|,?{,0x60,t3,|=,1,t1,=,},N,?{,t3,a,-=,}{,t3,a,+=,},a,t2,=,2,f,&,f,=,t1,C,=,4,t0,a,^,>>,1,&,H,=,");
				z80_szp (e);
			} else if (y == 5) {
				r_strbuf_append (e, "0xff,a,^=,0xc5,f,&,0x12,|,0x28,a,&,|,f,=,");
			} else {
				r_strbuf_append (e, y == 6? "0,C,=,0,H,=,1,C,=,": "C,t0,=,C,!,C,=,t0,H,=,");
				r_strbuf_append (e, "0,N,=,0xd5,f,&,0x28,a,&,|,f,=,");
			}
			break;
		}
	} else {
		switch (z) {
		case 0:
			r_strbuf_appendf (e, "%s,?{,", cc[y]);
			z80_pop (e, "pc");
			r_strbuf_append (e, "},");
			op->cycles = 11;
			op->failcycles = 5;
			break;
		case 1:
			if (!q) {
				z80_pop (e, rp2[p]);
				op->cycles = 10 + prefix;
			} else if (p == 0) {
				z80_pop (e, "pc");
				op->cycles = 10;
			} else if (p == 1) {
				z80_exchange (e, "bc", "bc2");
				z80_exchange (e, "de", "de2");
				z80_exchange (e, "hl", "hl2");
			} else if (p == 2) {
				r_strbuf_appendf (e, "%s,pc,=,", rp[2]);
			} else {
				r_strbuf_appendf (e, "%s,sp,=,", rp[2]);
				op->cycles = 6 + prefix;
			}
			break;
		case 2:
			r_strbuf_appendf (e, "%s,?{,%u,pc,=,},", cc[y], nn);
			op->size += 2;
			op->cycles = 10;
			break;
		case 3:
			if (y == 0) {
				r_strbuf_appendf (e, "%u,pc,=,", nn);
				op->size += 2;
				op->cycles = 10;
			} else if (y == 2 || y == 3) {
				r_strbuf_appendf (e, y == 2? "a,0x1000000,8,a,<<,%u,|,+,=[1],": "0x1000000,8,a,<<,%u,|,+,[1],a,=,", data[at]);
				op->size++;
				op->cycles = 11;
			} else if (y == 4) {
				r_strbuf_appendf (e, "sp,[2],t0,=,%s,sp,=[2],t0,%s,=,", rp[2], rp[2]);
				op->cycles = 19 + prefix;
			} else if (y == 5) {
				z80_exchange (e, "de", "hl");
			} else if (y == 6) {
				r_strbuf_append (e, "0,iff1,=,0,iff2,=,0,ei,=,");
			} else if (y == 7) {
				r_strbuf_append (e, "1,iff1,=,1,iff2,=,2,ei,=,");
			}
			break;
		case 4:
			r_strbuf_appendf (e, "%s,?{,", cc[y]);
			z80_push (e, "pc");
			r_strbuf_appendf (e, "%u,pc,=,},", nn);
			op->size += 2;
			op->cycles = 17;
			op->failcycles = 10;
			break;
		case 5:
			if (!q) {
				z80_push (e, rp2[p]);
				op->cycles = 11 + prefix;
			} else if (!p) {
				z80_push (e, "pc");
				r_strbuf_appendf (e, "%u,pc,=,", nn);
				op->size += 2;
				op->cycles = 17;
			}
			break;
		case 6:
			z80_alu (e, y, immediate, false);
			op->size++;
			op->cycles = 7;
			break;
		case 7:
			z80_push (e, "pc");
			r_strbuf_appendf (e, "%u,pc,=,", y * 8);
			op->cycles = 11;
			break;
		}
	}
	return op->size <= len;
}
