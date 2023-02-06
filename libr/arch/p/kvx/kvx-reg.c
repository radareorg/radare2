/* radare - LGPL - Copyright 2022 - jmaselbas */

#include "kvx.h"
#include "kvx-reg.h"

static const char *kv3_reg_srf[] = {
	"$pc",
	"$ps",
	"$pcr",
	"$ra",
	"$cs",
	"$csit",
	"$aespc",
	"$ls",
	"$le",
	"$lc",
	"$ipe",
	"$men",
	"$pmc",
	"$pm0",
	"$pm1",
	"$pm2",
	"$pm3",
	"$pmsa",
	"$tcr",
	"$t0v",
	"$t1v",
	"$t0r",
	"$t1r",
	"$wdv",
	"$wdr",
	"$ile",
	"$ill",
	"$ilr",
	"$mmc",
	"$tel",
	"$teh",
	"$res31",
	"$syo",
	"$hto",
	"$ito",
	"$do",
	"$mo",
	"$pso",
	"$res38",
	"$res39",
	"$dc",
	"$dba0",
	"$dba1",
	"$dwa0",
	"$dwa1",
	"$mes",
	"$ws",
	"$res47",
	"$res48",
	"$res49",
	"$res50",
	"$res51",
	"$res52",
	"$res53",
	"$res54",
	"$res55",
	"$res56",
	"$res57",
	"$res58",
	"$res59",
	"$res60",
	"$res61",
	"$res62",
	"$res63",
	"$spc_pl0",
	"$spc_pl1",
	"$spc_pl2",
	"$spc_pl3",
	"$sps_pl0",
	"$sps_pl1",
	"$sps_pl2",
	"$sps_pl3",
	"$ea_pl0",
	"$ea_pl1",
	"$ea_pl2",
	"$ea_pl3",
	"$ev_pl0",
	"$ev_pl1",
	"$ev_pl2",
	"$ev_pl3",
	"$sr_pl0",
	"$sr_pl1",
	"$sr_pl2",
	"$sr_pl3",
	"$es_pl0",
	"$es_pl1",
	"$es_pl2",
	"$es_pl3",
	"$res88",
	"$res89",
	"$res90",
	"$res91",
	"$res92",
	"$res93",
	"$res94",
	"$res95",
	"$syow",
	"$htow",
	"$itow",
	"$dow",
	"$mow",
	"$psow",
	"$res102",
	"$res103",
	"$res104",
	"$res105",
	"$res106",
	"$res107",
	"$res108",
	"$res109",
	"$res110",
	"$res111",
	"$res112",
	"$res113",
	"$res114",
	"$res115",
	"$res116",
	"$res117",
	"$res118",
	"$res119",
	"$res120",
	"$res121",
	"$res122",
	"$res123",
	"$res124",
	"$res125",
	"$res126",
	"$res127",
	"$spc",
	"$res129",
	"$res130",
	"$res131",
	"$sps",
	"$res133",
	"$res134",
	"$res135",
	"$ea",
	"$res137",
	"$res138",
	"$res139",
	"$ev",
	"$res141",
	"$res142",
	"$res143",
	"$sr",
	"$res145",
	"$res146",
	"$res147",
	"$es",
	"$res149",
	"$res150",
	"$res151",
	"$res152",
	"$res153",
	"$res154",
	"$res155",
	"$res156",
	"$res157",
	"$res158",
	"$res159",
	"$res160",
	"$res161",
	"$res162",
	"$res163",
	"$res164",
	"$res165",
	"$res166",
	"$res167",
	"$res168",
	"$res169",
	"$res170",
	"$res171",
	"$res172",
	"$res173",
	"$res174",
	"$res175",
	"$res176",
	"$res177",
	"$res178",
	"$res179",
	"$res180",
	"$res181",
	"$res182",
	"$res183",
	"$res184",
	"$res185",
	"$res186",
	"$res187",
	"$res188",
	"$res189",
	"$res190",
	"$res191",
	"$res192",
	"$res193",
	"$res194",
	"$res195",
	"$res196",
	"$res197",
	"$res198",
	"$res199",
	"$res200",
	"$res201",
	"$res202",
	"$res203",
	"$res204",
	"$res205",
	"$res206",
	"$res207",
	"$res208",
	"$res209",
	"$res210",
	"$res211",
	"$res212",
	"$res213",
	"$res214",
	"$res215",
	"$res216",
	"$res217",
	"$res218",
	"$res219",
	"$res220",
	"$res221",
	"$res222",
	"$res223",
	"$res224",
	"$res225",
	"$res226",
	"$res227",
	"$res228",
	"$res229",
	"$res230",
	"$res231",
	"$res232",
	"$res233",
	"$res234",
	"$res235",
	"$res236",
	"$res237",
	"$res238",
	"$res239",
	"$res240",
	"$res241",
	"$res242",
	"$res243",
	"$res244",
	"$res245",
	"$res246",
	"$res247",
	"$res248",
	"$res249",
	"$res250",
	"$res251",
	"$res252",
	"$res253",
	"$res254",
	"$res255",
	"$vsfr0",
	"$vsfr1",
	"$vsfr2",
	"$vsfr3",
	"$vsfr4",
	"$vsfr5",
	"$vsfr6",
	"$vsfr7",
	"$vsfr8",
	"$vsfr9",
	"$vsfr10",
	"$vsfr11",
	"$vsfr12",
	"$vsfr13",
	"$vsfr14",
	"$vsfr15",
	"$vsfr16",
	"$vsfr17",
	"$vsfr18",
	"$vsfr19",
	"$vsfr20",
	"$vsfr21",
	"$vsfr22",
	"$vsfr23",
	"$vsfr24",
	"$vsfr25",
	"$vsfr26",
	"$vsfr27",
	"$vsfr28",
	"$vsfr29",
	"$vsfr30",
	"$vsfr31",
	"$vsfr32",
	"$vsfr33",
	"$vsfr34",
	"$vsfr35",
	"$vsfr36",
	"$vsfr37",
	"$vsfr38",
	"$vsfr39",
	"$vsfr40",
	"$vsfr41",
	"$vsfr42",
	"$vsfr43",
	"$vsfr44",
	"$vsfr45",
	"$vsfr46",
	"$vsfr47",
	"$vsfr48",
	"$vsfr49",
	"$vsfr50",
	"$vsfr51",
	"$vsfr52",
	"$vsfr53",
	"$vsfr54",
	"$vsfr55",
	"$vsfr56",
	"$vsfr57",
	"$vsfr58",
	"$vsfr59",
	"$vsfr60",
	"$vsfr61",
	"$vsfr62",
	"$vsfr63",
	"$vsfr64",
	"$vsfr65",
	"$vsfr66",
	"$vsfr67",
	"$vsfr68",
	"$vsfr69",
	"$vsfr70",
	"$vsfr71",
	"$vsfr72",
	"$vsfr73",
	"$vsfr74",
	"$vsfr75",
	"$vsfr76",
	"$vsfr77",
	"$vsfr78",
	"$vsfr79",
	"$vsfr80",
	"$vsfr81",
	"$vsfr82",
	"$vsfr83",
	"$vsfr84",
	"$vsfr85",
	"$vsfr86",
	"$vsfr87",
	"$vsfr88",
	"$vsfr89",
	"$vsfr90",
	"$vsfr91",
	"$vsfr92",
	"$vsfr93",
	"$vsfr94",
	"$vsfr95",
	"$vsfr96",
	"$vsfr97",
	"$vsfr98",
	"$vsfr99",
	"$vsfr100",
	"$vsfr101",
	"$vsfr102",
	"$vsfr103",
	"$vsfr104",
	"$vsfr105",
	"$vsfr106",
	"$vsfr107",
	"$vsfr108",
	"$vsfr109",
	"$vsfr110",
	"$vsfr111",
	"$vsfr112",
	"$vsfr113",
	"$vsfr114",
	"$vsfr115",
	"$vsfr116",
	"$vsfr117",
	"$vsfr118",
	"$vsfr119",
	"$vsfr120",
	"$vsfr121",
	"$vsfr122",
	"$vsfr123",
	"$vsfr124",
	"$vsfr125",
	"$vsfr126",
	"$vsfr127",
	"$vsfr128",
	"$vsfr129",
	"$vsfr130",
	"$vsfr131",
	"$vsfr132",
	"$vsfr133",
	"$vsfr134",
	"$vsfr135",
	"$vsfr136",
	"$vsfr137",
	"$vsfr138",
	"$vsfr139",
	"$vsfr140",
	"$vsfr141",
	"$vsfr142",
	"$vsfr143",
	"$vsfr144",
	"$vsfr145",
	"$vsfr146",
	"$vsfr147",
	"$vsfr148",
	"$vsfr149",
	"$vsfr150",
	"$vsfr151",
	"$vsfr152",
	"$vsfr153",
	"$vsfr154",
	"$vsfr155",
	"$vsfr156",
	"$vsfr157",
	"$vsfr158",
	"$vsfr159",
	"$vsfr160",
	"$vsfr161",
	"$vsfr162",
	"$vsfr163",
	"$vsfr164",
	"$vsfr165",
	"$vsfr166",
	"$vsfr167",
	"$vsfr168",
	"$vsfr169",
	"$vsfr170",
	"$vsfr171",
	"$vsfr172",
	"$vsfr173",
	"$vsfr174",
	"$vsfr175",
	"$vsfr176",
	"$vsfr177",
	"$vsfr178",
	"$vsfr179",
	"$vsfr180",
	"$vsfr181",
	"$vsfr182",
	"$vsfr183",
	"$vsfr184",
	"$vsfr185",
	"$vsfr186",
	"$vsfr187",
	"$vsfr188",
	"$vsfr189",
	"$vsfr190",
	"$vsfr191",
	"$vsfr192",
	"$vsfr193",
	"$vsfr194",
	"$vsfr195",
	"$vsfr196",
	"$vsfr197",
	"$vsfr198",
	"$vsfr199",
	"$vsfr200",
	"$vsfr201",
	"$vsfr202",
	"$vsfr203",
	"$vsfr204",
	"$vsfr205",
	"$vsfr206",
	"$vsfr207",
	"$vsfr208",
	"$vsfr209",
	"$vsfr210",
	"$vsfr211",
	"$vsfr212",
	"$vsfr213",
	"$vsfr214",
	"$vsfr215",
	"$vsfr216",
	"$vsfr217",
	"$vsfr218",
	"$vsfr219",
	"$vsfr220",
	"$vsfr221",
	"$vsfr222",
	"$vsfr223",
	"$vsfr224",
	"$vsfr225",
	"$vsfr226",
	"$vsfr227",
	"$vsfr228",
	"$vsfr229",
	"$vsfr230",
	"$vsfr231",
	"$vsfr232",
	"$vsfr233",
	"$vsfr234",
	"$vsfr235",
	"$vsfr236",
	"$vsfr237",
	"$vsfr238",
	"$vsfr239",
	"$vsfr240",
	"$vsfr241",
	"$vsfr242",
	"$vsfr243",
	"$vsfr244",
	"$vsfr245",
	"$vsfr246",
	"$vsfr247",
	"$vsfr248",
	"$vsfr249",
	"$vsfr250",
	"$vsfr251",
	"$vsfr252",
	"$vsfr253",
	"$vsfr254",
	"$vsfr255",
};

const char *kv3_reg_grf[] = {
	"$r0",
	"$r1",
	"$r2",
	"$r3",
	"$r4",
	"$r5",
	"$r6",
	"$r7",
	"$r8",
	"$r9",
	"$r10",
	"$r11",
	"$r12", /* $sp */
	"$r13", /* $tp */
	"$r14", /* $fp */
	"$r15",
	"$r16",
	"$r17",
	"$r18",
	"$r19",
	"$r20",
	"$r21",
	"$r22",
	"$r23",
	"$r24",
	"$r25",
	"$r26",
	"$r27",
	"$r28",
	"$r29",
	"$r30",
	"$r31",
	"$r32",
	"$r33",
	"$r34",
	"$r35",
	"$r36",
	"$r37",
	"$r38",
	"$r39",
	"$r40",
	"$r41",
	"$r42",
	"$r43",
	"$r44",
	"$r45",
	"$r46",
	"$r47",
	"$r48",
	"$r49",
	"$r50",
	"$r51",
	"$r52",
	"$r53",
	"$r54",
	"$r55",
	"$r56",
	"$r57",
	"$r58",
	"$r59",
	"$r60",
	"$r61",
	"$r62",
	"$r63",
};

const char *kv3_reg_grf_pair[] = {
	"$r0r1",
	"$r2r3",
	"$r4r5",
	"$r6r7",
	"$r8r9",
	"$r10r11",
	"$r12r13",
	"$r14r15",
	"$r16r17",
	"$r18r19",
	"$r20r21",
	"$r22r23",
	"$r24r25",
	"$r26r27",
	"$r28r29",
	"$r30r31",
	"$r32r33",
	"$r34r35",
	"$r36r37",
	"$r38r39",
	"$r40r41",
	"$r42r43",
	"$r44r45",
	"$r46r47",
	"$r48r49",
	"$r50r51",
	"$r52r53",
	"$r54r55",
	"$r56r57",
	"$r58r59",
	"$r60r61",
	"$r62r63",
};

const char *kv3_reg_grf_quad[] = {
	"$r0r1r2r3",
	"$r4r5r6r7",
	"$r8r9r10r11",
	"$r12r13r14r15",
	"$r16r17r18r19",
	"$r20r21r22r23",
	"$r24r25r26r27",
	"$r28r29r30r31",
	"$r32r33r34r35",
	"$r36r37r38r39",
	"$r40r41r42r43",
	"$r44r45r46r47",
	"$r48r49r50r51",
	"$r52r53r54r55",
	"$r56r57r58r59",
	"$r60r61r62r63",
};

const char *kv3_reg_arf[] = {
	"$a0",
	"$a1",
	"$a2",
	"$a3",
	"$a4",
	"$a5",
	"$a6",
	"$a7",
	"$a8",
	"$a9",
	"$a10",
	"$a11",
	"$a12",
	"$a13",
	"$a14",
	"$a15",
	"$a16",
	"$a17",
	"$a18",
	"$a19",
	"$a20",
	"$a21",
	"$a22",
	"$a23",
	"$a24",
	"$a25",
	"$a26",
	"$a27",
	"$a28",
	"$a29",
	"$a30",
	"$a31",
	"$a32",
	"$a33",
	"$a34",
	"$a35",
	"$a36",
	"$a37",
	"$a38",
	"$a39",
	"$a40",
	"$a41",
	"$a42",
	"$a43",
	"$a44",
	"$a45",
	"$a46",
	"$a47",
	"$a48",
	"$a49",
	"$a50",
	"$a51",
	"$a52",
	"$a53",
	"$a54",
	"$a55",
	"$a56",
	"$a57",
	"$a58",
	"$a59",
	"$a60",
	"$a61",
	"$a62",
	"$a63",
};

const char *kv3_reg_arf_pair[] = {
	"$a0a1",
	"$a2a3",
	"$a4a5",
	"$a6a7",
	"$a8a9",
	"$a10a11",
	"$a12a13",
	"$a14a15",
	"$a16a17",
	"$a18a19",
	"$a20a21",
	"$a22a23",
	"$a24a25",
	"$a26a27",
	"$a28a29",
	"$a30a31",
	"$a32a33",
	"$a34a35",
	"$a36a37",
	"$a38a39",
	"$a40a41",
	"$a42a43",
	"$a44a45",
	"$a46a47",
	"$a48a49",
	"$a50a51",
	"$a52a53",
	"$a54a55",
	"$a56a57",
	"$a58a59",
	"$a60a61",
	"$a62a63",
};

const char *kv3_reg_arf_quad[] = {
	"$a0a1a2a3",
	"$a4a5a6a7",
	"$a8a9a10a11",
	"$a12a13a14a15",
	"$a16a17a18a19",
	"$a20a21a22a23",
	"$a24a25a26a27",
	"$a28a29a30a31",
	"$a32a33a34a35",
	"$a36a37a38a39",
	"$a40a41a42a43",
	"$a44a45a46a47",
	"$a48a49a50a51",
	"$a52a53a54a55",
	"$a56a57a58a59",
	"$a60a61a62a63",
};

inline static ut64 extract_field(int w, int o, ut64 v) {
	if (w > 63) {
		return 0;
	}
	ut64 m = (1ULL << w) - 1;
	return (v >> o) & m;
}

inline static ut64 sx(int w, ut64 v) {
	ut64 s = 1ULL << (w - 1);
	ut64 m = s - 1;

	if (v & s)
		v |= ~m;
	else
		v &= m;

	return v;
}

void kvx_decode_none(operand_t *o, const ut32 *b) {
	o->type = KVX_OPER_TYPE_UNK;
}

void kv3_decode_rw(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (6, 18, b[0]);
	o->reg = kv3_reg_grf[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rz(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (6, 0, b[0]);
	o->reg = kv3_reg_grf[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_ry(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (6, 6, b[0]);
	o->reg = kv3_reg_grf[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_ru(operand_t *o, const ut32 *b) {
	int r = extract_field (5, 19, b[0]);
	o->reg = kv3_reg_grf_pair[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rv(operand_t *o, const ut32 *b) {
	int r = extract_field (4, 20, b[0]);
	o->reg = kv3_reg_grf_quad[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rr(operand_t *o, const ut32 *b) {
	int r = extract_field (4, 2, b[0]);
	o->reg = kv3_reg_srf[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rt(operand_t *o, const ut32 *b) {
	kv3_decode_rw (o, b);
}

void kv3_decode_ra(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (6, 18, b[0]);
	o->reg = kv3_reg_arf[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rap(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (5, 19, b[0]);
	o->reg = kv3_reg_arf_pair[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_raq(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (4, 20, b[0]);
	o->reg = kv3_reg_arf_quad[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rb(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (6, 12, b[0]);
	o->reg = kv3_reg_arf[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rb_odd(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (5, 13, b[0]);
	r = 2 * r;
	o->reg = kv3_reg_arf[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rb_even(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (5, 13, b[0]);
	r = (2 * r) + 1;
	o->reg = kv3_reg_arf[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rbp(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (5, 13, b[0]);
	o->reg = kv3_reg_arf_pair[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rbq(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (4, 14, b[0]);
	o->reg = kv3_reg_arf_quad[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rc(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (6, 6, b[0]);
	o->reg = kv3_reg_arf[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rc_odd(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (5, 7, b[0]);
	r = 2 * r;
	o->reg = kv3_reg_arf[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rc_even(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (5, 7, b[0]);
	r = (2 * r) + 1;
	o->reg = kv3_reg_arf[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rd(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (6, 0, b[0]);
	o->reg = kv3_reg_arf[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_re(operand_t *o, const ut32 *b) {
	kv3_decode_ra (o, b);
}

void kv3_decode_rm(operand_t *o, const ut32 *b) {
	kv3_decode_ru (o, b);
}

void kv3_decode_rn(operand_t *o, const ut32 *b) {
	kv3_decode_rv (o, b);
}

void kv3_decode_ro(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (5, 7, b[0]);
	o->reg = kv3_reg_grf_pair[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rp(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (5, 1, b[0]);
	o->reg = kv3_reg_grf_pair[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rq(operand_t *o, const ut32 *b) {
	int r = extract_field (4, 2, b[0]);
	o->reg = kv3_reg_arf_quad[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_rs(operand_t *o, const ut32 *b) {
	int r;
	r = extract_field (9, 6, b[0]);
	o->reg = kv3_reg_srf[r];
	o->type = KVX_OPER_TYPE_REG;
}

void kv3_decode_u6(operand_t *o, const ut32 *b) {
	o->imm = extract_field (6, 6, b[0]);
	o->type = KVX_OPER_TYPE_IMM;
}

void kv3_decode_s10(operand_t *o, const ut32 *b) {
	o->imm = sx (10, extract_field (10, 6, b[0]));
	o->type = KVX_OPER_TYPE_IMM;
}

void kv3_decode_s16(operand_t *o, const ut32 *b) {
	o->imm = sx (16, extract_field (16, 0, b[0]));
	o->type = KVX_OPER_TYPE_IMM;
}

void kv3_decode_imm32(operand_t *o, const ut32 *b) {
	/* TODO: handle splat */
	ut64 imm;
	imm = extract_field (27, 0, b[1]);
	imm <<= 5;
	imm |= extract_field (5, 6, b[0]);
	o->imm = sx (32, imm);
	o->type = KVX_OPER_TYPE_IMM;
}

void kv3_decode_imm37(operand_t *o, const ut32 *b) {
	ut64 imm;
	imm = extract_field (27, 0, b[1]);
	imm <<= 10;
	imm |= extract_field (10, 6, b[0]);
	o->imm = sx (37, imm);
	o->type = KVX_OPER_TYPE_IMM;
}

void kv3_decode_imm43(operand_t *o, const ut32 *b) {
	ut64 imm;
	imm = extract_field (6, 0, b[0]);
	imm <<= 27;
	imm |= extract_field (27, 0, b[1]);
	imm <<= 10;
	imm |= extract_field (10, 6, b[0]);
	o->imm = sx (43, imm);
	o->type = KVX_OPER_TYPE_IMM;
}

void kv3_decode_imm64(operand_t *o, const ut32 *b) {
	ut64 imm;
	imm = extract_field(27, 0, b[2]);
	imm <<= 27;
	imm |= extract_field(27, 0, b[1]);
	imm <<= 10;
	imm |= extract_field(10, 6, b[0]);
	o->imm = imm;
	o->type = KVX_OPER_TYPE_IMM;
}

void kv3_decode_off27(operand_t *o, const ut32 *b) {
	ut64 imm;
	imm = extract_field (27, 0, b[1]);
	o->imm = sx (27, imm);
	o->type = KVX_OPER_TYPE_IMM;
}

void kv3_decode_off54(operand_t *o, const ut32 *b) {
	ut64 imm;
	imm = extract_field (27, 0, b[2]);
	imm <<= 27;
	imm |= extract_field (27, 0, b[1]);
	o->imm = sx (54, imm);
	o->type = KVX_OPER_TYPE_IMM;
}

void kv3_decode_pcrel17(operand_t *o, const ut32 *b) {
	ut64 imm;
	imm = extract_field (17, 6, b[0]);
	imm = sx (17, imm) << 2;
	o->imm = imm;
	o->type = KVX_OPER_TYPE_OFF;
}

void kv3_decode_pcrel27(operand_t *o, const ut32 *b) {
	ut64 imm;
	imm = extract_field (27, 0, b[0]);
	o->imm = sx (27, imm) << 2;
	o->type = KVX_OPER_TYPE_OFF;
}

void kv3_decode_start_bit(operand_t *o, const ut32 *b) {
	o->imm = extract_field (6, 6, b[0]);
	o->type = KVX_OPER_TYPE_IMM;
}

void kv3_decode_stop_bit(operand_t *o, const ut32 *b) {
	ut64 imm;
	imm = extract_field (2, 24, b[0]);
	imm <<= 4;
	imm |= extract_field (4, 12, b[0]);
	o->imm = imm;
	o->type = KVX_OPER_TYPE_IMM;
}

void kv3_decode_shift(operand_t *o, const ut32 *b) {
	o->imm = extract_field (6, 0, b[0]);
	o->type = KVX_OPER_TYPE_IMM;
}

void kv3_decode_sys(operand_t *o, const ut32 *b) {
	o->imm = extract_field (12, 0, b[0]);
	o->type = KVX_OPER_TYPE_IMM;
}
