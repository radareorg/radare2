/* radare - LGPL - Copyright 2013 - 2014 - condret@runas-racer.com */

#define GB_8BIT		1
#define	GB_16BIT	2
#define ARG_8		4
#define	ARG_16		8
#define GB_IO		16		//	Most io (Joypad, Sound, Screen ...)


typedef struct{
	const char *name;
	const int type;
} gb_opcode;

#ifndef GB_DIS_LEN_ONLY
static const char *cb_ops[]={	"rlc","rrc","rl","rr","sla","sra","swap","srl",
				"bit 0,","bit 1,","bit 2,","bit 3,","bit 4,","bit 5,","bit 6,","bit 7,",
				"res 0,","res 1,","res 2,","res 3,","res 4,","res 5,","res 6,","res 7,",
				"set 0,","set 1,","set 2,","set 3,","set 4,","set 5,","set 6,","set 7,"};

static const char *cb_regs[]={	"b","c","d","e","h","l","[hl]","a"};
#endif

static gb_opcode gb_op[] = {
	{"nop"			,GB_8BIT},			//0x00
	{"ld bc, 0x%04x"	,GB_8BIT+ARG_16},
	{"ld [bc], a"		,GB_8BIT},
	{"inc bc"		,GB_8BIT},
	{"inc b"		,GB_8BIT},
	{"dec b"		,GB_8BIT},
	{"ld b, 0x%02x"		,GB_8BIT+ARG_8},
	{"rlca"			,GB_8BIT},
	{"ld [0x%04x], sp"	,GB_8BIT+ARG_16},		//word or byte?
	{"add hl, bc"		,GB_8BIT},
	{"ld a, [bc]"		,GB_8BIT},
	{"dec bc"		,GB_8BIT},
	{"inc c"		,GB_8BIT},
	{"dec c"		,GB_8BIT},
	{"ld c, 0x%02x"		,GB_8BIT+ARG_8},
	{"rrca"			,GB_8BIT},

	{"stop"			,GB_8BIT},			//0x10
	{"ld de, 0x%04x"	,GB_8BIT+ARG_16},
	{"ld [de], a"		,GB_8BIT},
	{"inc de"		,GB_8BIT},
	{"inc d"		,GB_8BIT},
	{"dec d"		,GB_8BIT},
	{"ld d, 0x%02x"		,GB_8BIT+ARG_8},
	{"rla"			,GB_8BIT},
	{"jr 0x%02x"		,GB_8BIT+ARG_8},		//signed
	{"add hl, de"		,GB_8BIT},
	{"ld a, [de]"		,GB_8BIT},
	{"dec de"		,GB_8BIT},
	{"inc e"		,GB_8BIT},
	{"dec e"		,GB_8BIT},
	{"ld e, 0x%02x"		,GB_8BIT+ARG_8},
	{"rra"			,GB_8BIT},

	{"jr nZ, 0x%02x"	,GB_8BIT+ARG_8},		//0x20 //signed
	{"ld hl, 0x%04x"	,GB_8BIT+ARG_16},
	{"ldi [hl], a"		,GB_8BIT},
	{"inc hl"		,GB_8BIT},
	{"inc h"		,GB_8BIT},
	{"dec h"		,GB_8BIT},
	{"ld h, 0x%02x"		,GB_8BIT+ARG_8},
	{"daa"			,GB_8BIT},
	{"jr Z, 0x%02x"		,GB_8BIT+ARG_8},		//signed
	{"add hl, hl"		,GB_8BIT},
	{"ldi a, [hl]"		,GB_8BIT},
	{"dec hl"		,GB_8BIT},
	{"inc l"		,GB_8BIT},
	{"dec l"		,GB_8BIT},
	{"ld l, 0x%02x"		,GB_8BIT+ARG_8},
	{"cpl"			,GB_8BIT},

	{"jr nC, 0x%02x"	,GB_8BIT+ARG_8},		//0x30 //signed
	{"ld sp, 0x%04x"	,GB_8BIT+ARG_16},
	{"ldd [hl], a"		,GB_8BIT},
	{"inc sp"		,GB_8BIT},
	{"inc [hl]"		,GB_8BIT},
	{"dec [hl]"		,GB_8BIT},
	{"ld [hl], 0x%02x"	,GB_8BIT+ARG_8},
	{"scf"			,GB_8BIT},
	{"jr C, 0x%02x"		,GB_8BIT+ARG_8},		//signed
	{"add hl, sp"		,GB_8BIT},
	{"ldd a, [hl]"		,GB_8BIT},
	{"dec sp"		,GB_8BIT},
	{"inc a"		,GB_8BIT},
	{"dec a"		,GB_8BIT},
	{"ld a, 0x%02x"		,GB_8BIT+ARG_8},
	{"ccf"			,GB_8BIT},

	{"ld b, b"		,GB_8BIT},			//0x40
	{"ld b, c"		,GB_8BIT},
	{"ld b, d"		,GB_8BIT},
	{"ld b, e"		,GB_8BIT},
	{"ld b, h"		,GB_8BIT},
	{"ld b, l"		,GB_8BIT},
	{"ld b, [hl]"		,GB_8BIT},
	{"ld b, a"		,GB_8BIT},
	{"ld c, b"		,GB_8BIT},
	{"ld c, c"		,GB_8BIT},
	{"ld c, d"		,GB_8BIT},
	{"ld c, e"		,GB_8BIT},
	{"ld c, h"		,GB_8BIT},
	{"ld c, l"		,GB_8BIT},
	{"ld c, [hl]"		,GB_8BIT},
	{"ld c, a"		,GB_8BIT},

	{"ld d, b"		,GB_8BIT},			//0x50
	{"ld d, c"		,GB_8BIT},
	{"ld d, d"		,GB_8BIT},
	{"ld d, e"		,GB_8BIT},
	{"ld d, h"		,GB_8BIT},
	{"ld d, l"		,GB_8BIT},
	{"ld d, [hl]"		,GB_8BIT},
	{"ld d, a"		,GB_8BIT},
	{"ld e, b"		,GB_8BIT},
	{"ld e, c"		,GB_8BIT},
	{"ld e, d"		,GB_8BIT},
	{"ld e, e"		,GB_8BIT},
	{"ld e, h"		,GB_8BIT},
	{"ld e, l"		,GB_8BIT},
	{"ld e, [hl]"		,GB_8BIT},
	{"ld e, a"		,GB_8BIT},

	{"ld h, b"		,GB_8BIT},			//0x60
	{"ld h, c"		,GB_8BIT},
	{"ld h, d"		,GB_8BIT},
	{"ld h, e"		,GB_8BIT},
	{"ld h, h"		,GB_8BIT},
	{"ld h, l"		,GB_8BIT},
	{"ld h, [hl]"		,GB_8BIT},
	{"ld h, a"		,GB_8BIT},
	{"ld l, b"		,GB_8BIT},
	{"ld l, c"		,GB_8BIT},
	{"ld l, d"		,GB_8BIT},
	{"ld l, e"		,GB_8BIT},
	{"ld l, h"		,GB_8BIT},
	{"ld l, l"		,GB_8BIT},
	{"ld l, [hl]"		,GB_8BIT},
	{"ld l, a"		,GB_8BIT},

	{"ld [hl], b"		,GB_8BIT},			//0X70
	{"ld [hl], c"		,GB_8BIT},
	{"ld [hl], d"		,GB_8BIT},
	{"ld [hl], e"		,GB_8BIT},
	{"ld [hl], h"		,GB_8BIT},
	{"ld [hl], l"		,GB_8BIT},
	{"halt"			,GB_8BIT},
	{"ld [hl], a"		,GB_8BIT},
	{"ld a, b"		,GB_8BIT},
	{"ld a, c"		,GB_8BIT},
	{"ld a, d"		,GB_8BIT},
	{"ld a, e"		,GB_8BIT},
	{"ld a, h"		,GB_8BIT},
	{"ld a, l"		,GB_8BIT},
	{"ld a, [hl]"		,GB_8BIT},
	{"ld a, a"		,GB_8BIT},

	{"add b"		,GB_8BIT},			//0x80
	{"add c"		,GB_8BIT},
	{"add d"		,GB_8BIT},
	{"add e"		,GB_8BIT},
	{"add h"		,GB_8BIT},
	{"add l"		,GB_8BIT},
	{"add [hl]"		,GB_8BIT},
	{"add a"		,GB_8BIT},
	{"adc b"		,GB_8BIT},
	{"adc c"		,GB_8BIT},
	{"adc d"		,GB_8BIT},
	{"adc e"		,GB_8BIT},
	{"adc h"		,GB_8BIT},
	{"adc l"		,GB_8BIT},
	{"adc [hl]"		,GB_8BIT},
	{"adc a"		,GB_8BIT},

	{"sub b"		,GB_8BIT},			//0x90
	{"sub c"		,GB_8BIT},
	{"sub d"		,GB_8BIT},
	{"sub e"		,GB_8BIT},
	{"sub h"		,GB_8BIT},
	{"sub l"		,GB_8BIT},
	{"sub [hl]"		,GB_8BIT},
	{"sub a"		,GB_8BIT},
	{"sbc b"		,GB_8BIT},
	{"sbc c"		,GB_8BIT},
	{"sbc d"		,GB_8BIT},
	{"sbc e"		,GB_8BIT},
	{"sbc h"		,GB_8BIT},
	{"sbc l"		,GB_8BIT},
	{"sbc [hl]"		,GB_8BIT},
	{"sbc a"		,GB_8BIT},

	{"and b"		,GB_8BIT},			//0xa0
	{"and c"		,GB_8BIT},
	{"and d"		,GB_8BIT},
	{"and e"		,GB_8BIT},
	{"and h"		,GB_8BIT},
	{"and l"		,GB_8BIT},
	{"and [hl]"		,GB_8BIT},
	{"and a"		,GB_8BIT},
	{"xor b"		,GB_8BIT},
	{"xor c"		,GB_8BIT},
	{"xor d"		,GB_8BIT},
	{"xor e"		,GB_8BIT},
	{"xor h"		,GB_8BIT},
	{"xor l"		,GB_8BIT},
	{"xor [hl]"		,GB_8BIT},
	{"xor a"		,GB_8BIT},

	{"or b"			,GB_8BIT},			//0xb0
	{"or c"			,GB_8BIT},
	{"or d"			,GB_8BIT},
	{"or e"			,GB_8BIT},
	{"or h"			,GB_8BIT},
	{"or l"			,GB_8BIT},
	{"or [hl]"		,GB_8BIT},
	{"or a"			,GB_8BIT},
	{"cp b"			,GB_8BIT},
	{"cp c"			,GB_8BIT},
	{"cp d"			,GB_8BIT},
	{"cp e"			,GB_8BIT},
	{"cp h"			,GB_8BIT},
	{"cp l"			,GB_8BIT},
	{"cp [hl]"		,GB_8BIT},
	{"cp a"			,GB_8BIT},

	{"ret nZ"		,GB_8BIT},			//0xc0
	{"pop bc"		,GB_8BIT},
	{"jp nZ, 0x%04x"	,GB_8BIT+ARG_16},
	{"jp 0x%04x"		,GB_8BIT+ARG_16},
	{"call nZ, 0x%04x"	,GB_8BIT+ARG_16},
	{"push bc"		,GB_8BIT},
	{"add 0x%02x"		,GB_8BIT+ARG_8},
	{"rst 0"		,GB_8BIT},
	{"ret Z"		,GB_8BIT},
	{"ret"			,GB_8BIT},
	{"jp Z, 0x%04x"		,GB_8BIT+ARG_16},
	{""			,GB_16BIT},
	{"call Z, 0x%04x"	,GB_8BIT+ARG_16},
	{"call 0x%04x"		,GB_8BIT+ARG_16},
	{"adc 0x%02x"		,GB_8BIT+ARG_8},
	{"rst 8"		,GB_8BIT},

	{"ret nC"		,GB_8BIT},			//0xd0
	{"pop de"		,GB_8BIT},
	{"jp nC, 0x%04x"	,GB_8BIT+ARG_16},
	{"invalid"		,GB_8BIT},
	{"call nC, 0x%04x"	,GB_8BIT+ARG_16},
	{"push de"		,GB_8BIT},
	{"sub 0x%02x"		,GB_8BIT+ARG_8},
	{"rst 16"		,GB_8BIT},
	{"ret C"		,GB_8BIT},
	{"reti"			,GB_8BIT},
	{"jp C, 0x%04x"		,GB_8BIT+ARG_16},
	{"invalid"		,GB_8BIT},
	{"call C, 0x%04x"	,GB_8BIT+ARG_16},
	{"invalid"		,GB_8BIT},
	{"sbc 0x%02x"		,GB_8BIT+ARG_8},
	{"rst 24"		,GB_8BIT},

	{"ld [0x%04x], a"	,GB_8BIT+ARG_8+GB_IO},	//0xe0
	{"pop hl"		,GB_8BIT},
	{"ld [0xff00 + c], a"	,GB_8BIT},
	{"invalid"		,GB_8BIT},
	{"invalid"		,GB_8BIT},
	{"push hl"		,GB_8BIT},
	{"and 0x%02x"		,GB_8BIT+ARG_8},
	{"rst 32"		,GB_8BIT},
	{"add sp, 0x%02x"	,GB_8BIT+ARG_8},		//signed
	{"jp hl"		,GB_8BIT},
	{"ld [0x%04x], a"	,GB_8BIT+ARG_16},		//signed
	{"invalid"		,GB_8BIT},
	{"invalid"		,GB_8BIT},
	{"invalid"		,GB_8BIT},
	{"xor 0x%02x"		,GB_8BIT+ARG_8},
	{"rst 40"		,GB_8BIT},

	{"ld a, [0x%04x]"	,GB_8BIT+ARG_8+GB_IO},	//0xf0
	{"pop af"		,GB_8BIT},
	{"ld a, [0xff00 + c]"	,GB_8BIT},
	{"di"			,GB_8BIT},
	{"invalid"		,GB_8BIT},
	{"push af"		,GB_8BIT},
	{"or 0x%02x"		,GB_8BIT+ARG_8},
	{"rst 48"		,GB_8BIT},
	{"ld hl, sp + 0x%02x"	,GB_8BIT+ARG_8},		//signed
	{"ld sp, hl"		,GB_8BIT},
	{"ld a, [0x%04x]"	,GB_8BIT+ARG_16},
	{"ei"			,GB_8BIT},
	{"invalid"		,GB_8BIT},
	{"invalid"		,GB_8BIT},
	{"cp 0x%02x"		,GB_8BIT+ARG_8},
	{"rst 56"		,GB_8BIT},
};
