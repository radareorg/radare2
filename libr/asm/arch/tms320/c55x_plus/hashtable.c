/* c55plus - LGPL - Copyright 2013 - th0rpe */

#include "ins.h"
#include "hashvector.h"
#include <r_types.h>

static const st32 hash_const_01 = 0x2474f685;
static const st32 hash_const_02 = 0x42fbc0b8;
static const st32 hash_const_03 = 0x086a18eb;
static const st32 hash_const_04 = 0x001d02e8;
static const st32 hash_const_05 = 0;

extern ut8* ins_buff;
extern ut32 ins_buff_len;
extern HASHCODE_ENTRY_T ins_hash[];


st32 get_hashfunc_01(st32 arg1, st32 arg2) {
	return arg1;
}

st32 get_hashfunc_02(st32 arg1, st32 arg2) {
	char v4 = 0;
	st32 v2 = arg2 & 0xFE000000;
	if ( (arg2 & 0xFE000000u) > 0x72000000 ) {
		if ( (ut32)v2 <= 0xD8000000 ) {
			if ( v2 != 0xd8000000) {
				if ( (ut32)v2 > 0xC4000000 ) {
					if ( (ut32)v2 > 0xCE000000 ) {
						if ( (ut32)v2 > 0xD4000000 ) {
							if ( v2 == -704643072 )
								return 95;
							return arg1;
						}
						if ( v2 != -738197504 && v2 != -805306368 ) {
							if ( v2 == -771751936 )
								return 95;
							return arg1;
						}
					} else {
						if ( v2 != -838860800 ) {
							if ( (ut32)v2 > 0xCA000000 ) {
								if ( v2 == -872415232 )
									return 95;
								return arg1;
							}
							if ( v2 != -905969664 && v2 != -973078528 ) {
								if ( v2 == -939524096 )
									return 95;
								return arg1;
							}
						}
					}
				} else {
					if ( v2 != -1006632960 ) {
						if ( (ut32)v2 <= 0x7E000000 ) {
							if ( v2 != 2113929216 ) {
								if ( (ut32)v2 > 0x78000000 ) {
									if ( v2 != 2046820352 && v2 != 2080374784 )
										return arg1;
								} else {
									if ( v2 != 2013265920 && v2 != 1946157056 ) {
										if ( v2 == 1979711488 )
											return 226;
										return arg1;
									}
								}
							}
							return 226;
						}
						if ( (ut32)v2 > 0xC0000000 ) {
							if ( v2 == -1040187392 )
								return 95;
							return arg1;
						}
						if ( v2 != 0xC0000000 ) {
							if ( v2 == -1610612736 )
								return 540;
							if ( v2 == -1577058304 )
								return 541;
							return arg1;
						}
					}
				}
			}
			return 95;
		}
		if ( (ut32)v2 > 0xEC000000 ) {
			if ( (ut32)v2 > 0xF6000000 ) {
				if ( (ut32)v2 > 0xFC000000 ) {
					if ( v2 != -33554432 )
						return arg1;
					return 96;
				}
				if ( v2 == -67108864 || v2 == -134217728 )
					return 96;
				v4 = v2 == -100663296;
			} else {
				if ( v2 == -167772160 )
					return 96;
				if ( (ut32)v2 > 0xF2000000 ) {
					v4 = v2 == -201326592;
				} else {
					if ( v2 == -234881024 || v2 == -301989888 )
						return 96;
					v4 = v2 == -268435456;
				}
			}
		} else {
			if ( v2 == -335544320 )
				return 96;
			if ( (ut32)v2 > 0xE2000000 ) {
				if ( (ut32)v2 > 0xE8000000 ) {
					v4 = v2 == -369098752;
				} else {
					if ( v2 == -402653184 || v2 == -469762048 )
						return 96;
					v4 = v2 == -436207616;
				}
			} else {
				if ( v2 == -503316480 )
					return 96;
				if ( (ut32)v2 <= 0xDE000000 ) {
					if ( v2 != -570425344 && v2 != -637534208 && v2 != -603979776 )
						return arg1;
					return 95;
				}
				v4 = v2 == -536870912;
			}
		}
		if ( !v4 )
			return arg1;
		return 96;
	}
	if ( (arg2 & 0xFE000000) == 1912602624 )
		return 226;
	if ( (ut32)v2 > 0x48000000 ) {
		if ( (ut32)v2 <= 0x5E000000 ) {
			if ( v2 != 1577058304 ) {
				if ( (ut32)v2 > 0x54000000 ) {
					if ( (ut32)v2 > 0x5A000000 ) {
						if ( v2 != 1543503872 )
							return arg1;
					} else {
						if ( v2 != 1509949440 && v2 != 1442840576 ) {
							if ( v2 == 1476395008 )
								return 178;
							return arg1;
						}
					}
				} else {
					if ( v2 != 1409286144 ) {
						if ( (ut32)v2 > 0x4E000000 ) {
							if ( v2 != 1342177280 ) {
								if ( v2 == 1375731712 )
									return 178;
								return arg1;
							}
						} else {
							if ( v2 != 1308622848 && v2 != 1241513984 ) {
								if ( v2 == 1275068416 )
									return 178;
								return arg1;
							}
						}
					}
				}
			}
			return 178;
		}
		if ( (ut32)v2 > 0x68000000 ) {
			if ( (ut32)v2 > 0x6E000000 ) {
				if ( v2 == 1879048192 )
					return 226;
				return arg1;
			}
			if ( v2 != 1845493760 && v2 != 1778384896 ) {
				if ( v2 == 1811939328 )
					return 226;
				return arg1;
			}
		} else {
			if ( v2 != 1744830464 ) {
				if ( (ut32)v2 > 0x64000000 ) {
					if ( v2 == 1711276032 )
						return 226;
					return arg1;
				}
				if ( v2 != 1677721600 && v2 != 1610612736 ) {
					if ( v2 == 1644167168 )
						return 226;
					return arg1;
				}
			}
		}
		return 226;
	}
	if ( v2 == 1207959552 )
		return 178;
	if ( (ut32)v2 <= 0x14000000 ) {
		if ( v2 != 335544320 ) {
			if ( (ut32)v2 > 0xA000000 ) {
				if ( (ut32)v2 > 0x10000000 ) {
					if ( v2 == 301989888 )
						return 142;
					return arg1;
				}
				if ( v2 != 268435456 && v2 != 201326592 ) {
					if ( v2 == 234881024 )
						return 142;
					return arg1;
				}
			} else {
				if ( v2 != 167772160 ) {
					if ( (ut32)v2 > 0x4000000 ) {
						if ( v2 != 100663296 ) {
							if ( v2 == 134217728 )
								return 142;
							return arg1;
						}
					} else {
						if ( v2 != 67108864 && v2 ) {
							if ( v2 == 33554432 )
								return 142;
							return arg1;
						}
					}
				}
			}
		}
		return 142;
	}
	if ( (ut32)v2 > 0x1E000000 ) {
		if ( (ut32)v2 > 0x44000000 ) {
			if ( v2 == 1174405120 )
				return 178;
			return arg1;
		}
		if ( v2 != 1140850688 && v2 != 0x40000000 ) {
			if ( v2 == 1107296256 )
				return 178;
			return arg1;
		}
		return 178;
	}
	if ( v2 == 503316480 )
		return 142;
	if ( (ut32)v2 <= 0x1A000000 ) {
		if ( v2 != 436207616 && v2 != 369098752 ) {
			if ( v2 == 402653184 )
				return 142;
			return arg1;
		}
		return 142;
	}
	if ( v2 == 469762048 )
		return 142;
	return arg1;
}

st32 get_hashfunc_03(st32 arg1, st32 arg2) {
	st32 v2 = arg2 & 0xE0000000;
	if ( (arg2 & 0xE0000000u) <= 0x80000000 ) {
		if ( (arg2 & 0xE0000000) == 0x80000000)
			return 102;
		if ( !v2 )
			return 485;
		if ( v2 == 536870912 )
			return 486;
		return arg1;
	}
	if (v2 != 0xA0000000)
		return arg1;
	return 475;
}

st32 get_hashfunc_04(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x80000000 ) {
		if ( (arg2 & 0x80000000) == 0x80000000)
			result = 99;
		else result = arg1;
	} else result = 100;
	return result;
}

st32 get_hashfunc_05(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x80000000 ) {
		if ( (arg2 & 0x80000000) == 0x80000000)
			result = 97;
		else result = arg1;
	} else result = 98;
	return result;
}

st32 get_hashfunc_06(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x80000000 ) {
		if ( (st32)(arg2 & 0x80000000) == 0x80000000 )
			result = 228;
		else result = arg1;
	} else result = 227;
	return result;
}

st32 get_hashfunc_07(st32 arg1, st32 arg2) {
	st32 result;

	if ( arg2 & 0x80000000 ) {
		if ( (arg2 & 0x80000000) == 0x80000000)
			result = 52;
		else result = arg1;
	} else result = 140;
	return result;
}

st32 get_hashfunc_08(st32 arg1, st32 arg2) {
	st32 tmp; 

	tmp = arg2 & 0xC0000000;
	if ( (arg2 & 0xC0000000u) <= 0x80000000 ) {
		if ( (arg2 & 0xC0000000) == 0x80000000)
			return 87;
		if ( !tmp )
			return 85;
		if ( tmp == 0x40000000 )
			return 86;
		return arg1;
	}
	if ( tmp != 0xC0000000 )
		return arg1;
	return 88;
}

st32 get_hashfunc_09(st32 arg1, st32 arg2) {
	st32 v2; 

	v2 = arg2 & 0xC0000000;
	if ( (arg2 & 0xC0000000u) <= 0x80000000 ) {
		if ( (arg2 & 0xC0000000) == 0x80000000)
			return 91;
		if ( !v2 )
			return 89;
		if ( v2 == 0x40000000 )
			return 90;
		return arg1;
	}
	if ( v2 != 0xC0000000 )
		return arg1;
	return 92;
}

st32 get_hashfunc_10(st32 arg1, st32 arg2) {
	st32 v2; 
	st32 v3; 

	v2 = arg2;
	v3 = v2 & 0x500000;
	if ( (ut32)v3 <= 0x400000 ) {
		if ( v3 == 4194304 )
			return 247;
		if ( !v3 )
			return 245;
		if ( v3 == 1048576 )
			return 249;
		return arg1;
	}
	if ( v3 != 5242880 )
		return arg1;
	return 248;
}

st32 get_hashfunc_11(st32 arg1, st32 arg2) {
	st32 result; 

	/* */

	if ( (ut32)hash_const_05 & arg2 ) {
		if ( ((ut32)hash_const_05 & arg2) == 524288 )
			result = 460;
		else
			result = arg1;
	} else {
		result = 244;
	}
	return result;
}

st32 get_hashfunc_12(st32 arg1, st32 arg2) {
	st32 tmp; 
	st32 v3; 
	st32 result; 

	tmp = arg2;
	v3 = tmp & 0x400000;
	if ( v3 ) {
		if ( v3 == 4194304 )
			result = 521;
		else result = arg1;
	} else result = 374;
	return result;
}

st32 get_hashfunc_13(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 30;
		else result = arg1;
	} else result = 32;
	return result;
}

st32 get_hashfunc_14(st32 arg1, st32 arg2) {
	st32 result; 

	if (arg2 & 0x1000000) {
		if ( (arg2 & 0x1000000) == 0x1000000)
			result = 61;
		else result = arg1;
	} else result = 60;
	return result;
}

st32 get_hashfunc_15(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 63;
		else
			result = arg1;
	} else result = 62;
	return result;
}

st32 get_hashfunc_16(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 69;
		else
			result = arg1;
	} else result = 64;
	return result;
}

st32 get_hashfunc_17(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 68;
		else
			result = arg1;
	} else result = 67;
	return result;
}

st32 get_hashfunc_18(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 66;
		else
			result = arg1;
	} else result = 65;
	return result;
}

st32 get_hashfunc_19(st32 arg1, st32 arg2) {
	st32 v2; 

	v2 = arg2 & 0xC1000000;
	if ( (arg2 & 0xC1000000u) > 0x40000000 ) {
		if ( v2 != 0x80000000 && v2 != 0xC0000000 )
			return arg1;
	} else {
		if ( (arg2 & 0xC1000000) != 0x40000000 && v2 ) {
			if ( v2 == 16777216 )
				return 469;
			return arg1;
		}
	}
	return 59;
}

st32 get_hashfunc_20(st32 arg1, st32 arg2) {
	st32 v2; 

	v2 = arg2 & 0x1400000;
	if ( (arg2 & 0x1400000u) <= 0x1000000 ) {
		if ( (arg2 & 0x1400000) == 16777216 )
			return 75;
		if ( !v2 )
			return 74;
		if ( v2 == 4194304 )
			return 78;
		return arg1;
	}
	if ( v2 != 20971520 )
		return arg1;
	return 77;
}

st32 get_hashfunc_21(st32 arg1, st32 arg2) {
	st32 v2; 

	v2 = arg2 & 0x1400000;
	if ( (arg2 & 0x1400000u) <= 0x1000000 ) {
		if ( (arg2 & 0x1400000) == 16777216 )
			return 73;
		if ( !v2 )
			return 72;
		if ( v2 == 4194304 )
			return 108;
		return arg1;
	}
	if ( v2 != 20971520 )
		return arg1;
	return 109;
}

st32 get_hashfunc_22(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x8200 ) {
		if ( (unsigned short)(arg2 & 0x8200) == 512 )
			result = 364;
		else result = arg1;
	} else result = 357;
	return result;
}

st32 get_hashfunc_23(st32 arg1, st32 arg2) {
	st32 v2; 
	st32 v3; 

	v2 = arg2;
	v3 = v2 & 0x41C000;
	if ( (ut32)v3 <= 0x400000 ) {
		if ( v3 == 4194304 )
			return 323;
		if ( (ut32)v3 <= 0xC000 ) {
			if ( v3 != 49152 ) {
				if ( !v3 )
					return 324;
				if ( v3 == 16384 )
					return 370;
				if ( v3 == 32768 )
					return 325;
				return arg1;
			}
			return 372;
		}
		if ( v3 != 65536 ) {
			if ( v3 != 81920 ) {
				if ( v3 == 114688 )
					return 371;
				return arg1;
			}
			return 373;
		}
		return 314;
	}
	if ( (ut32)v3 <= 0x410000 ) {
		if ( v3 != 4259840 ) {
			if ( v3 == 4210688 )
				return 369;
			//if ( (st32 (*)(char))v3 == (char *)hash_const_01 )
			if (v3 == hash_const_01)
				return 325;
			if ( v3 != 4243456 )
				return arg1;
			return 372;
		}
		return 314;
	}
	if ( v3 != 4276224 ) {
		if ( v3 == 4308992 )
			return 371;
		return arg1;
	}
	return 373;
}

st32 get_hashfunc_24(st32 arg1, st32 arg2) {
	st32 v2; 
	st32 v3; 

	v2 = arg2;
	v3 = v2 & 0x418000;
	if ( (ut32)v3 <= 0x400000 ) {
		if ( v3 == 4194304 )
			return 330;
		if ( (ut32)v3 <= 0x10000 ) {
			if ( v3 != 65536 ) {
				if ( !v3 )
					return 329;
				if ( v3 == 32768 )
					return 307;
				return arg1;
			}
			return 480;
		}
		if ( v3 == 98304 )
			return 467;
		return arg1;
	}
	//if ( (st32 (*)(char))v3 != (char *)hash_const_01 ) {
	if (v3 != hash_const_01) {
		if (v3 == 4259840) return 480;
		if (v3 == 4292608) return 467;
		return arg1;
	}
	return 308;
}

st32 get_hashfunc_25(st32 arg1, st32 arg2) {
	ut32 v2; 

	v2 = (ut32)hash_const_02 & arg2;
	if ( ((ut32)hash_const_02 & arg2) <= 0x8000 ) {
		if ( ((ut32)hash_const_02 & arg2) != 32768 ) {
			if ( v2 <= 0x400 ) {
				if ( v2 != 1024 && v2 ) {
					if ( v2 == 512 )
						return 365;
					return arg1;
				}
				return 365;
			}
			if ( v2 == 1536 )
				return 365;
			return arg1;
		}
		return 382;
	}
	if ( v2 <= 0x8600 ) {
		if ( v2 != 34304 && v2 != 33280 && v2 != 33792 )
			return arg1;
		return 382;
	}
	//if ( (st32 (*)(char))v2 != (char *)hash_const_01 )
	if (v2 != hash_const_01)
		return arg1;
	return 380;
}

st32 get_hashfunc_26(st32 arg1, st32 arg2) {
	st32 v2; 
	st32 v3; 

	v2 = arg2;
	v3 = v2 & 0x41C000;
	if ( (ut32)v3 <= 0x404000 ) {
		if ( v3 == 4210688 || v3 == 16384 )
			return 310;
		if ( v3 != 49152 ) {
			if ( v3 == 4194304 )
				return 312;
			return arg1;
		}
		return 311;
	}
	//if ( (st32 (*)(char))v3 != (st32 (*)(char))hash_const_01 ) {
	if (v3 != hash_const_01) {
		if ( v3 != 4243456 )
			return arg1;
		return 311;
	}
	return 313;
}

st32 get_hashfunc_27(st32 arg1, st32 arg2) {
	st32 v2; 
	st32 v3; 
	st32 result; 

	v2 = arg2;
	v3 = v2 & 0x18000;
	if ( v3 ) {
		if ( v3 == 32768 ) {
			result = 376;
		} else {
			if ( v3 == 65536 )
				result = 377;
			else
				result = arg1;
		}
	} else {
		result = 375;
	}
	return result;
}


st32 get_hashfunc_28(st32 arg1, st32 arg2) {
	st32 v2; 
	st32 v3; 
	char v5; 

	v2 = arg2;
	v3 = v2 & 0x1F800;
	if ( (ut32)v3 <= 0xA000 ) {
		if ( v3 != 40960 ) {
			if ( (ut32)v3 <= 0x3000 ) {
				if ( v3 == 12288 )
					return 384;
				if ( (ut32)v3 <= 0x1800 ) {
					if ( v3 != 6144 && v3 && v3 != 2048 ) {
						if ( v3 == 4096 )
							return 384;
						return arg1;
					}
					return 384;
				}
				if ( v3 == 8192 || v3 == 10240 )
					return 384;
				return arg1;
			}
			if ( (ut32)v3 > 0x8800 ) {
				if ( v3 != 36864 ) {
					if ( v3 == 38912 )
						return 385;
					return arg1;
				}
			} else {
				if ( v3 != 34816 ) {
					if ( v3 != 14336 ) {
						if ( v3 == 24576 )
							return 388;
						if ( v3 == 32768 )
							return 385;
						return arg1;
					}
					return 384;
				}
			}
		}
		return 385;
	}
	if ( (ut32)v3 <= 0x11000 ) {
		if ( v3 == 69632 )
			return 386;
		if ( (ut32)v3 <= 0xE000 ) {
			if ( v3 == 57344 )
				return 387;
			if ( v3 != 43008 && v3 != 45056 && v3 != 47104 )
				return arg1;
			return 385;
		}
		if ( v3 == 65536 )
			return 386;
		v5 = v3 == 67584;
		LABEL_35:
		if ( !v5 )
			return arg1;
		return 386;
	}
	if ( (ut32)v3 <= 0x13000 ) {
		if ( v3 == 77824 || v3 == 71680 || v3 == 73728 )
			return 386;
		v5 = v3 == 75776;
		goto LABEL_35;
	}
	if ( v3 == 79872 )
		return 386;
	if ( v3 != 90112 )
		return arg1;
	return 389;
}

st32 get_hashfunc_29(st32 arg1, st32 arg2) {
	st32 v2; 
	st32 v3; 

	v2 = arg2;
	v3 = v2 & 0x40F800;
	if ( v3 <= (ut32)hash_const_03 ) {
		//if ( (st32 (*)(int, int, int))v3 == (st32 (*)(int, int, int))hash_const_03)
		if (v3 == hash_const_03)
			return 305;
		if ( v3 == 40960 )
			return 306;
		if ( v3 == 57344 )
			return 391;
		return arg1;
	}
	if (v3 != 4218880)
		return arg1;
	return 390;
}

st32 get_hashfunc_30(st32 arg1, st32 arg2) {
	st32 v2; 
	st32 v3; 
	st32 result; 

	v2 = arg2;
	v3 = v2 & 0x18000;
	if ( v3 ) {
		if ( v3 == 32768 ) {
			result = 303;
		} else {
			if ( v3 == 65536 )
				result = 304;
			else
				result = arg1;
		}
	} else result = 302;
	return result;
}

st32 get_hashfunc_31(st32 arg1, st32 arg2) {
	st32 result; 
	st32 v3 = arg2 & 0x380000;

	if ( (ut32)v3 <= 0x200000 ) {
		if ( v3 == 2097152 )
			return 271;
		if ( (ut32)v3 > 0x100000 ) {
			if ( v3 == 1572864 )
				return 534;
		} else {
			if ( v3 == 1048576 )
				return 317;
			if ( !v3 )
				return 319;
			if ( v3 == 524288 )
				return 533;
		}
		return arg1;
	}
	if ( v3 == 2621440 ) {
		result = 535;
	} else {
		if ( v3 == 3145728 ) {
			result = 321;
		} else {
			if ( v3 != 3670016 )
				return arg1;
			result = 536;
		}
	}
	return result;
}

st32 get_hashfunc_32(st32 arg1, st32 arg2) {
	st32 v2; 
	st32 v3; 
	st32 result; 

	v2 = arg2;
	v3 = v2 & 0x18000;
	if ( v3 ) {
		if ( v3 == 32768 ) {
			result = 258;
		} else {
			if ( v3 == 65536 )
				result = 259;
			else
				result = arg1;
		}
	} else {
		result = 261;
	}
	return result;
}


st32 get_hashfunc_33(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x8000 ) {
		if ( (unsigned short)(arg2 & 0x8000) == 32768 )
			result = 327;
		else
			result = arg1;
	} else result = 326;
	return result;
}

st32 get_hashfunc_34(st32 arg1, st32 arg2) {
	st32 result; 
	st32 v2 = arg2;
	st32 v3 = v2 & 0x580000;
	if ( (ut32)v3 <= 0x180000 ) {
		if ( v3 == 1572864 )
			return 471;
		if ( !v3 )
			return 392;
		if ( v3 == 524288 )
			return 470;
		if ( v3 == 1048576 )
			return 393;
		return arg1;
	}
	if ( v3 == 4194304 ) {
		result = 394;
	} else {
		if ( v3 != 5242880 )
			return arg1;
		result = 395;
	}
	return result;
}


st32 get_hashfunc_35(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 189;
		else
			result = arg1;
	} else result = 186;
	return result;
}

st32 get_hashfunc_36(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1C00000 ) {
		if ( (arg2 & 0x1C00000) == 16777216 )
			result = 188;
		else
			result = arg1;
	} else result = 187;
	return result;
}

st32 get_hashfunc_37(st32 arg1, st32 arg2) {
	st32 result; 

	if ( (arg2 & 0x1800000) == 8388608 ) {
		result = 473;
	} else {
		if ( (arg2 & 0x1800000) == 25165824 )
			result = 474;
		else
			result = arg1;
	}
	return result;
}

st32 get_hashfunc_38(st32 arg1, st32 arg2) {
	st32 v2 = arg2 & 0x1010000;
	if ( (arg2 & 0x1010000u) <= 0x1000000 ) {
		if ( (arg2 & 0x1010000) == 16777216 )
			return 472;
		if ( !v2 )
			return 23;
		if ( v2 == 65536 )
			return 24;
		return arg1;
	}
	if ( v2 != 16842752 )
		return arg1;
	return 26;
}

st32 get_hashfunc_39(st32 arg1, st32 arg2) {
	st32 result; 

	if ( (arg2 & 0x1010000) == 65536 ) {
		result = 25;
	} else {
		if ( (arg2 & 0x1010000) == 16842752 )
			result = 27;
		else
			result = arg1;
	}
	return result;
}

st32 get_hashfunc_40(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1010000 ) {
		if ( (arg2 & 0x1010000) == 16777216 )
			result = 135;
		else
			result = arg1;
	} else result = 134;
	return result;
}

st32 get_hashfunc_41(st32 arg1, st32 arg2) {
	st32 result; 
	st32 v2 = arg2 & 0x1010000;
	if ( arg2 & 0x1010000 ) {
		if ( v2 == 16777216 ) {
			result = 138;
		} else {
			if ( v2 == 16842752 )
				result = 139;
			else
				result = arg1;
		}
	} else result = 137;
	return result;
}

st32 get_hashfunc_42(st32 arg1, st32 arg2) {
	st32 v2 = arg2 & 0x1010000;
	if ( (arg2 & 0x1010000u) <= 0x1000000 ) {
		if ( (arg2 & 0x1010000) == 16777216 )
			return 12;
		if ( !v2 )
			return 11;
		if ( v2 == 65536 )
			return 8;
		return arg1;
	}
	if ( v2 != 16842752 )
		return arg1;
	return 9;
}

st32 get_hashfunc_43(st32 arg1, st32 arg2) {
	st32 v2; 

	v2 = arg2 & 0x1010000;
	if ( (arg2 & 0x1010000u) <= 0x1000000 ) {
		if ( (arg2 & 0x1010000) == 16777216 )
			return 13;
		if ( !v2 )
			return 15;
		if ( v2 == 65536 )
			return 10;
		return arg1;
	}
	if ( v2 != 16842752 )
		return arg1;
	return 14;
}

st32 get_hashfunc_44(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 29;
		else
			result = arg1;
	} else result = 28;
	return result;
}

st32 get_hashfunc_45(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 17;
		else
			result = arg1;
	} else result = 16;
	return result;
}

st32 get_hashfunc_46(st32 arg1, st32 arg2) {
	st32 v2; 

	v2 = arg2 & 0xC1000000;
	if ( (arg2 & 0xC1000000u) > 0x40000000 ) {
		if ( v2 != 0x80000000 && v2 != 0xC0000000 )
			return arg1;
	} else {
		if ( (arg2 & 0xC1000000) != 0x40000000 && v2 ) {
			if ( v2 == 16777216 )
				return 136;
			return arg1;
		}
	}
	return 18;
}

st32 get_hashfunc_47(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 130;
		else
			result = arg1;
	} else result = 132;
	return result;
}

st32 get_hashfunc_48(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 133;
		else
			result = arg1;
	} else result = 131;
	return result;
}

st32 get_hashfunc_49(st32 arg1, st32 arg2) {
	st32 result; 

	if (arg2 & 0x80000000) {
		if ((arg2 & 0x80000000) == 0x80000000)
			result = 33;
		else result = arg1;
	} else result = 35;
	return result;
}

st32 get_hashfunc_50(st32 arg1, st32 arg2) {
	st32 v3 = arg2 & 0x780000;
	if ( (ut32)v3 <= 0x400000 ) {
		if ( v3 == 4194304 )
			return 522;
		if ( (ut32)v3 > 0x180000 ) {
			if ( v3 == 2621440 )
				return 402;
			if ( v3 == 3145728 )
				return 411;
		} else {
			if ( v3 == 1572864 )
				return 401;
			if ( !v3 )
				return 403;
			if ( v3 == 524288 )
				return 400;
		}
		return arg1;
	}
	if ((ut32)v3 <= 0x680000) {
		if (v3 == 0x680000)
			return 526;
		if (v3 == hash_const_05)
			return 524;
		if ( v3 == 0x580000)
			return 525;
		return arg1;
	}
	if ( v3 != 7340032 )
		return arg1;
	return 523;
}

st32 get_hashfunc_51(st32 arg1, st32 arg2) {
	st32 v3 = arg2 & 0x180000;
	if ( (ut32)v3 > 0x100000 ) {
		if ( v3 != 1572864 )
			return arg1;
	} else {
		if ( v3 != 1048576 ) {
			if ( !v3 )
				return 396;
			if ( v3 == 524288 )
				return 532;
			return arg1;
		}
	}
	return 398;
}

st32 get_hashfunc_52(st32 arg1, st32 arg2) {
	st32 v3 = arg2 & 0x18000;
	if ( (ut32)v3 <= 0x10000 ) {
		if (v3 == 0x10000) return 296;
		if (v3 == 0x8000) return 300;
		if (!v3) return 298;
		return arg1;
	}
	if (v3 != 0x18000)
		return arg1;
	return 301;
}

st32 get_hashfunc_53(st32 arg1, st32 arg2) {
	st32 v2 = arg2 & 0x8200;
	st32 result; 

	if (arg2 & 0x8200) {
		if (v2 == 512) {
			result = 530;
		} else {
			result = (v2==0x8000)? 297: arg1;
		}
	} else result = 355;
	return result;
}

st32 get_hashfunc_54(st32 arg1, st32 arg2) {
	st32 v2 = arg2 & 0x8200;
	if ( (ut32)v2 <= 0x8000 ) {
		if ( v2 == 32768 )
			return 316;
		if ( !(arg2 & 0x8200) )
			return 410;
		if ( v2 == 512 )
			return 531;
		return arg1;
	}
	if ( v2 != 33280 )
		return arg1;
	return 315;
}

st32 get_hashfunc_55(st32 arg1, st32 arg2) {
	st32 result;
	if ((arg2 & 0x8000)) {
		if ( (unsigned short)(arg2 & 0x8000) == 32768 )
			result = 295;
		else result = arg1;
	} else result = 294;
	return result;
}

st32 get_hashfunc_56(st32 arg1, st32 arg2) {
	st32 result; 
	st32 v3 = arg2 & 0x18180;
	if ( (ut32)v3 <= 0x8080 ) {
		if ( v3 == 32896 )
			return 528;
		if ( !v3 )
			return 406;
		if ( v3 == 128 )
			return 527;
		if ( v3 == 32768 )
			return 407;
		return arg1;
	}
	if ( v3 == 98304 ) {
		result = 408;
	} else {
		if ( v3 != 98432 )
			return arg1;
		result = 529;
	}
	return result;
}

st32 get_hashfunc_57(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x8000 ) {
		if ( (unsigned short)(arg2 & 0x8000) == 32768 )
			result = 405;
		else
			result = arg1;
	} else result = 404;
	return result;
}

st32 get_hashfunc_58(st32 arg1, st32 arg2) {
	st32 v2; 
	st32 v3; 
	st32 result; 

	v2 = arg2;
	v3 = v2 & 0x18000;
	if ( v3 ) {
		if ( v3 == 32768 ) {
			result = 263;
		} else {
			if ( v3 == 65536 )
				result = 264;
			else
				result = arg1;
		}
	} else {
		result = 262;
	}
	return result;
}

st32 get_hashfunc_59(st32 arg1, st32 arg2) {
	st32 result; 
	st32 v2 = arg2 & 0x8180;
	if ( (ut32)v2 <= 0x100 ) {
		if ( v2 == 256 )
			return 505;
		if ( !(arg2 & 0x8180) )
			return 503;
		if ( v2 == 128 )
			return 504;
		return arg1;
	}
	if ( v2 == 384 ) {
		result = 506;
	} else {
		if ( v2 != 32768 )
			return arg1;
		result = 507;
	}
	return result;
}

st32 get_hashfunc_60(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 173;
		else
			result = arg1;
	} else result = 172;
	return result;
}

st32 get_hashfunc_61(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 175;
		else
			result = arg1;
	} else result = 174;
	return result;
}

st32 get_hashfunc_62(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 152;
		else
			result = arg1;
	} else result = 151;
	return result;
}

st32 get_hashfunc_63(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 154;
		else
			result = arg1;
	} else result = 153;
	return result;
}

st32 get_hashfunc_64(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 180;
		else
			result = arg1;
	} else result = 179;
	return result;
}

st32 get_hashfunc_65(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 182;
		else
			result = arg1;
	} else result = 181;
	return result;
}

st32 get_hashfunc_66(st32 arg1, st32 arg2) {
	st32 result; 

	if ( (arg2 & 0x1C00000) == 12582912 ) {
		result = 157;
	} else {
		if ( (arg2 & 0x1C00000) == 29360128 )
			result = 158;
		else
			result = arg1;
	}
	return result;
}


st32 get_hashfunc_67(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 57;
		else
			result = arg1;
	} else result = 56;
	return result;
}

st32 get_hashfunc_68(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 208;
		else
			result = arg1;
	} else result = 207;
	return result;
}

st32 get_hashfunc_69(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 209;
		else
			result = arg1;
	} else result = 210;
	return result;
}

st32 get_hashfunc_70(st32 arg1, st32 arg2) {
	st32 v2; 
	st32 result; 

	v2 = arg2 & 0x1400000;
	if ( arg2 & 0x1400000 ) {
		if ( v2 == 16777216 ) {
			result = 217;
		} else {
			if ( v2 == 20971520 )
				result = 212;
			else
				result = arg1;
		}
	} else {
		result = 216;
	}
	return result;
}

st32 get_hashfunc_71(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1400000 ) {
		if ( (arg2 & 0x1400000) == 4194304 )
			result = 211;
		else
			result = arg1;
	} else {
		result = 218;
	}
	return result;
}

st32 get_hashfunc_72(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 221;
		else
			result = arg1;
	} else result = 220;
	return result;
}

st32 get_hashfunc_73(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1010000 ) {
		if ( (arg2 & 0x1010000) == 16777216 )
			result = 215;
		else
			result = arg1;
	} else result = 214;
	return result;
}

st32 get_hashfunc_74(st32 arg1, st32 arg2) {
	st32 result; 

	if ( (arg2 & 0x1010000) == 65536 ) {
		result = 213;
	} else {
		if ( (arg2 & 0x1010000) == 16842752 )
			result = 426;
		else
			result = arg1;
	}
	return result;
}

st32 get_hashfunc_75(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x80000000 ) {
		if ((arg2 & 0x80000000) == 0x80000000)
			result = 457;
		else result = arg1;
	} else result = 459;
	return result;
}

st32 get_hashfunc_76(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 21;
		else result = arg1;
	} else result = 19;
	return result;
}

st32 get_hashfunc_77(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 22;
		else
			result = arg1;
	} else result = 20;
	return result;
}

st32 get_hashfunc_78(st32 arg1, st32 arg2) {
	st32 v3 = arg2 & 0x18000;
	if ( (ut32)v3 <= 0x10000 ) {
		if ( v3 == 65536 )
			return 429;
		if ( !v3 )
			return 427;
		if ( v3 == 32768 )
			return 428;

		return arg1;
	}
	if ( v3 != 98304 )
		return arg1;
	return 252;
}

st32 get_hashfunc_79(st32 arg1, st32 arg2) {
	st32 v2; 
	st32 v3; 
	st32 result; 

	v2 = arg2;
	v3 = v2 & 0x18180;
	if ( (ut32)v3 <= 0x8100 ) {
		if ( v3 == 33024 )
			return 437;
		if ( (ut32)v3 > 0x180 ) {
			if ( v3 == 32768 )
				return 431;
			if ( v3 == 32896 )
				return 435;
		} else {
			if ( v3 == 384 )
				return 440;
			if ( !v3 )
				return 430;
			if ( v3 == 128 )
				return 432;
			if ( v3 == 256 )
				return 434;
		}
		return arg1;
	}
	if ( (ut32)v3 <= 0x10100 ) {
		if ( v3 == 65792 )
			return 442;
		if ( v3 == 33152 )
			return 441;
		if ( v3 == 65536 )
			return 433;
		if ( v3 == 65664 )
			return 436;
		return arg1;
	}
	if ( v3 == 65920 ) {
		result = 439;
	} else {
		if ( v3 != 98688 )
			return arg1;
		result = 438;
	}
	return result;
}

st32 get_hashfunc_80(st32 arg1, st32 arg2) {
	st32 v2; 
	st32 v3; 
	st32 result; 

	v2 = arg2;
	v3 = v2 & 0x18180;
	if ( (ut32)v3 <= 0x8100 ) {
		if ( v3 == 33024 )
			return 450;
		if ( (ut32)v3 > 0x180 ) {
			if ( v3 == 32768 )
				return 444;
			if ( v3 == 32896 )
				return 448;
		} else {
			if ( v3 == 384 )
				return 453;
			if ( !v3 )
				return 443;
			if ( v3 == 128 )
				return 445;
			if ( v3 == 256 )
				return 447;
		}
		return arg1;
	}
	if ( (ut32)v3 <= 0x10100 ) {
		if ( v3 == 65792 )
			return 455;
		if ( v3 == 33152 )
			return 454;
		if ( v3 == 65536 )
			return 446;
		if ( v3 == 65664 )
			return 449;
		return arg1;
	}
	if ( v3 == 65920 ) {
		result = 452;
	} else {
		if ( v3 != 98688 )
			return arg1;
		result = 451;
	}
	return result;
}

st32 get_hashfunc_81(st32 arg1, st32 arg2) {
	st32 result; 
	st32 v2 = arg2 & 0x1000180;
	if ( (arg2 & 0x1000180u) <= 0x1000000 ) {
		if ( (arg2 & 0x1000180) == 16777216 )
			return 191;
		if ( (ut32)v2 > 0x100 ) {
			if ( v2 == 384 )
				return 200;
		} else {
			if ( v2 == 256 )
				return 538;
			if ( !v2 )
				return 190;
			if ( v2 == 128 )
				return 537;
		}
		return arg1;
	}
	if ( v2 == 16777344 ) {
		result = 194;
	} else {
		if ( v2 == 16777472 ) {
			result = 539;
		} else {
			if ( v2 != 16777600 )
				return arg1;
			result = 201;
		}
	}
	return result;
}

st32 get_hashfunc_82(st32 arg1, st32 arg2) {
	st32 v2; 
	st32 result; 

	v2 = arg2 & 0x1000180;
	if ( (arg2 & 0x1000180u) <= 0x100 ) {
		if ( (arg2 & 0x1000180) == 256 )
			return 203;
		if ( !v2 )
			return 192;
		if ( v2 == 128 )
			return 195;
		return arg1;
	}
	if ( v2 == 384 ) {
		result = 198;
	} else {
		if ( v2 != 16777600 )
			return arg1;
		result = 196;
	}
	return result;
}

st32 get_hashfunc_83(st32 arg1, st32 arg2) {
	st32 v2; 
	st32 result; 
	char v4; 

	v2 = arg2 & 0x1810180;
	if ( (arg2 & 0x1810180u) <= 0x800080 ) {
		if ( (arg2 & 0x1810180) != 8388736 ) {
			if ( (ut32)v2 <= 0x10000 ) {
				if ( v2 == 65536 )
					return 193;
				if ( (ut32)v2 <= 0x100 ) {
					if ( v2 != 256 ) {
						if ( v2 ) {
							if ( v2 == 128 )
								return 197;
							return arg1;
						}
						return 193;
					}
					return 202;
				}
				v4 = v2 == 384;
				LABEL_11:
				if ( v4 )
					return 199;
				return arg1;
			}
			if ( (ut32)v2 > 0x10180 ) {
				if ( v2 == 8388608 )
					return 193;
				return arg1;
			}
			if ( v2 == 65920 )
				return 199;
			if ( v2 != 65664 ) {
				if ( v2 == 65792 )
					return 202;
				return arg1;
			}
		}
		return 197;
	}
	if ( (ut32)v2 <= 0x810100 ) {
		if ( v2 == 8454400 )
			return 202;
		if ( (ut32)v2 <= 0x810000 ) {
			if ( v2 == 8454144 )
				return 193;
			if ( v2 == 8388864 )
				return 202;
			v4 = v2 == 8388992;
			goto LABEL_11;
		}
		if ( v2 != 8454272 )
			return arg1;
		return 197;
	}
	if ( v2 == 8454528 )
		return 199;
	if ( v2 == 16777216 ) {
		result = 205;
	} else {
		if ( v2 != 16777344 )
			return arg1;
		result = 206;
	}
	return result;
}


st32 get_hashfunc_84(st32 arg1, st32 arg2) {
	st32 result; 
	st32 v2 = arg2 & 0x1000180;
	if ( arg2 & 0x1000180 ) {
		if ( v2 == 16777344 ) {
			result = 509;
		} else {
			if ( v2 == 16777472 )
				result = 510;
			else result = arg1;
		}
	} else result = 508;
	return result;
}

st32 get_hashfunc_85(st32 arg1, st32 arg2) {
	st32 result; 

	if ( (arg2 & 0x1000180) == 128 ) {
		result = 511;
	} else {
		if ( (arg2 & 0x1000180) == 256 )
			result = 512;
		else
			result = arg1;
	}
	return result;
}

st32 get_hashfunc_86(st32 arg1, st32 arg2) {
	st32 result; 

	if ( arg2 & 0x1000000 ) {
		if ( (arg2 & 0x1000000) == 16777216 )
			result = 171;
		else
			result = arg1;
	} else result = 170;
	return result;
}

st32 get_hashfunc_87(st32 arg1, st32 v2) {
	st32 result; 
	st32 v3 = v2 & 0x79B981;
	if ( v3 == 33024 || v3 == 4227328 )
		result = 490;
	else result = ( v3 == 4260097 )? 491: arg1;
	return result;
}

st32 get_hashfunc_88(st32 arg1, st32 arg2) {
	st32 v2 = arg2;
	st32 v3 = v2 & 0x79B981;
	if ( (ut32)v3 <= 0x410101 ) {
		if (v3 == 0x410101)
			return 493;
		if (v3 == 0x8100 || v3 == 0x408100)
			return 492;
		return arg1;
	}
	if (v3 != hash_const_04)
		return arg1;
	return 494;
}

st32 get_hashfunc_89(st32 arg1, st32 arg2) {
	st32 result; 

	if ( (arg2 & 0x1B901B9) == 16777600 ) {
		result = 488;
	} else {
		if ( (arg2 & 0x1B901B9) == 25231616 )
			result = 495;
		else
			result = arg1;
	}
	return result;
}

st32 get_hashfunc_90(st32 arg1, st32 arg2) {
	st32 v2; 
	st32 v4; 
	st32 v5; 

	v2 = arg2 & 0x1F901B9;
	if ( (arg2 & 0x1F901B9u) <= 0x1810101 ) {
		if ( (arg2 & 0x1F901B9) == 25231617 )
			return 498;
		if ( (ut32)v2 <= 0x1000180 ) {
			if ( v2 != 16777600 ) {
				if ( v2 == 8454401 )
					return 497;
				if ( v2 == 8454529 )
					return 499;
				return arg1;
			}
			return 489;
		}
		if ( v2 == 20971904 )
			return 489;
		return arg1;
	}
	v4 = v2 - 25231744;
	if ( v4 ) {
		v5 = v4 - 1;
		if ( !v5 )
			return 500;

		/* FIX */
		v5 -= 0x3FFFFF;
		if(v5 != 0) {
			return arg1;
		}
		/*
		   if ( (_UNKNOWN *)v5 != &unk_3FFFFF )
		   return arg1;
		 */
	}
	return 496;
}

st32 get_hashfunc_91(st32 arg1, st32 arg2) {
	st32 result; 

	if ( (arg2 & 0x1F901BF) == 8454145 ) {
		result = 501;
	} else {
		if ( (arg2 & 0x1F901BF) == 25231361 )
			result = 502;
		else result = arg1;
	}
	return result;
}

//get hashcode from instruction bytecode
st32 get_hash_code(ut32 ins_pos) {
	ut32 len, ins_part1;
	ut32 opcode, pos;
	st32 (*get_hashcode_func)(st32 arg, st32 arg2);
	ut32 ins_len;
	st32 arg, ins_part2, hash_code;

	ins_part1 = 0;
	ins_part2 = 0;

	opcode = get_ins_part(ins_pos, 1);
	ins_len = get_ins_len(opcode);

	if (C55PLUS_DEBUG) {
		printf("opcode: 0x%x part: %d\n", opcode, ins_pos);
		printf("ins_len: 0x%x\n", ins_len);
	}

	if (ins_len > 1 ) {
		len = ins_len - 1;
		if (len >= 4 )
			len = 4;

		ins_part1 = get_ins_part(ins_pos + 1, len) << (8 * (4 - len));
		ins_part2 = 0;
		if (ins_len > 5 )
			ins_part2 = get_ins_part(ins_pos + 5, 1);
	}

	pos = (2 * opcode | (ins_part1 >> 31));
	//arg = *(ut32 *)(((ut8 *)ins_hash)+ pos * 8);
	arg = ins_hash[pos].code;

	ins_part2 >>= 7;
	ins_part2 |= (ins_part1 * 2);

	//get_hashcode_func = *(ut32 *)(((ut8 *)ins_hash + sizeof(ut32)) + pos * 8);
	get_hashcode_func = ins_hash[pos].hash_func;

	if (C55PLUS_DEBUG) {
		printf("hashfunc => %p 0x%x\n", get_hashcode_func, pos);
		printf("hashargs => 0x%x 0x%x 0x%x\n", (ut32)arg, ins_part1, ins_part2);
	}

	hash_code = get_hashcode_func(arg, ins_part2);
	if (C55PLUS_DEBUG) {
		printf ("ret hashcode: 0x%x\n", hash_code);
	}

	return hash_code;
}
