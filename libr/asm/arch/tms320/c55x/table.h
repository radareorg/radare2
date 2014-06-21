{
	.byte = 0x00,
	.size = 0x03,
	.insn = {
		// kkkkkkkkxCCCCCCC0000000E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,CCCCCCC), INSN_FLAG(16,k8),  LIST_END },
		.syntax = INSN_SYNTAX(RPTCC k8, cond),
	},
},
{
	.byte = 0x02,
	.size = 0x03,
	.insn = {
		// xxxxxxxxxCCCCCCC0000001E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,CCCCCCC),  LIST_END },
		.syntax = INSN_SYNTAX(RETCC cond),
	},
},
{
	.byte = 0x04,
	.size = 0x03,
	.insn = {
		// LLLLLLLLxCCCCCCC0000010E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,CCCCCCC), INSN_FLAG(16,L8),  LIST_END },
		.syntax = INSN_SYNTAX(BCC L8, cond),
	},
},
{
	.byte = 0x06,
	.size = 0x03,
	.insn = {
		// LLLLLLLLLLLLLLLL0000011E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,L16),  LIST_END },
		.syntax = INSN_SYNTAX(B L16),
	},
},
{
	.byte = 0x08,
	.size = 0x03,
	.insn = {
		// LLLLLLLLLLLLLLLL0000100E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,L16),  LIST_END },
		.syntax = INSN_SYNTAX(CALL L16),
	},
},
{
	.byte = 0x0c,
	.size = 0x03,
	.insn = {
		// kkkkkkkkkkkkkkkk0000110E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,k16),  LIST_END },
		.syntax = INSN_SYNTAX(RPT k16),
	},
},
{
	.byte = 0x0e,
	.size = 0x03,
	.insn = {
		// llllllllllllllll0000111E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,l16),  LIST_END },
		.syntax = INSN_SYNTAX(RPTB pmad),
	},
},
{
	.byte = 0x10,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// xxSHIFTWDDSS00000001000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,SS), INSN_FLAG(14,DD), INSN_FLAG(16,SHIFTW),  LIST_END },
				.syntax = INSN_SYNTAX(AND ACx << #SHIFTW[, ACy]),
			},
			{
				// xxSHIFTWDDSS00010001000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,SS), INSN_FLAG(14,DD), INSN_FLAG(16,SHIFTW),  LIST_END },
				.syntax = INSN_SYNTAX(OR ACx << #SHIFTW[, ACy]),
			},
			{
				// xxSHIFTWDDSS00100001000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,SS), INSN_FLAG(14,DD), INSN_FLAG(16,SHIFTW),  LIST_END },
				.syntax = INSN_SYNTAX(XOR ACx << #SHIFTW[, ACy]),
			},
			{
				// xxSHIFTWDDSS00110001000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,SS), INSN_FLAG(14,DD), INSN_FLAG(16,SHIFTW),  LIST_END },
				.syntax = INSN_SYNTAX(ADD ACx << #SHIFTW, ACy),
			},
			{
				// xxSHIFTWDDSS01000001000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,SS), INSN_FLAG(14,DD), INSN_FLAG(16,SHIFTW),  LIST_END },
				.syntax = INSN_SYNTAX(SUB ACx << #SHIFTW, ACy),
			},
			{
				// xxSHIFTWDDSS01010001000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,SS), INSN_FLAG(14,DD), INSN_FLAG(16,SHIFTW),  LIST_END },
				.syntax = INSN_SYNTAX(SFTS ACx, #SHIFTW[, ACy]),
			},
			{
				// xxSHIFTWDDSS01100001000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,6),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,SS), INSN_FLAG(14,DD), INSN_FLAG(16,SHIFTW),  LIST_END },
				.syntax = INSN_SYNTAX(SFTSC ACx, #SHIFTW[, ACy]),
			},
			{
				// xxSHIFTWDDSS01110001000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,7),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,SS), INSN_FLAG(14,DD), INSN_FLAG(16,SHIFTW),  LIST_END },
				.syntax = INSN_SYNTAX(SFTL ACx, #SHIFTW[, ACy]),
			},
			{
				// xxddxxxxxxSS10000001000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,8),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,SS), INSN_FLAG(20,dd),  LIST_END },
				.syntax = INSN_SYNTAX(EXP ACx, Tx),
			},
			{
				// xxddxxxxDDSS10010001000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,9),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,SS), INSN_FLAG(14,DD), INSN_FLAG(20,dd),  LIST_END },
				.syntax = INSN_SYNTAX(MANT ACx, ACy :: NEXP ACx, Tx),
			},
			{
				// SSddxxxtxxSS10100001000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,10),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,SS), INSN_FLAG(16,t), INSN_FLAG(20,dd), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(BCNT ACx, ACy, TCx, Tx),
			},
			{
				// SSDDnnnnDDSS11000001000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,12),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,SS), INSN_FLAG(14,DD), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MAXDIFF ACx, ACy, ACz, ACw),
			},
			{
				// SSDDxxxrDDSS11010001000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,13),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,SS), INSN_FLAG(14,DD), INSN_FLAG(16,r), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(DMAXDIFF ACx, ACy, ACz, ACw, TRNx),
			},
			{
				// SSDDxxxxDDSS11100001000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,14),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,SS), INSN_FLAG(14,DD), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MINDIFF ACx, ACy, ACz, ACw),
			},
			{
				// SSDDxxxrDDSS11110001000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,15),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,SS), INSN_FLAG(14,DD), INSN_FLAG(16,r), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(DMINDIFF ACx, ACy, ACz, ACw, TRNx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x12,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// FDDD0uttFSSScc010001001E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,2,1), INSN_MASK(19,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(10,cc), INSN_FLAG(12,FSSS), INSN_FLAG(16,tt), INSN_FLAG(18,u), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(CMPAND[U] src RELOP dst, TCy, TCx),
			},
			{
				// FDDD1uttFSSScc010001001E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,2,1), INSN_MASK(19,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(10,cc), INSN_FLAG(12,FSSS), INSN_FLAG(16,tt), INSN_FLAG(18,u), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(CMPAND[U] src RELOP dst, !TCy, TCx),
			},
			{
				// FDDD0uttFSSScc100001001E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,2,2), INSN_MASK(19,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(10,cc), INSN_FLAG(12,FSSS), INSN_FLAG(16,tt), INSN_FLAG(18,u), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(CMPOR[U] src RELOP dst, TCy, TCx),
			},
			{
				// FDDD1uttFSSScc100001001E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,2,2), INSN_MASK(19,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(10,cc), INSN_FLAG(12,FSSS), INSN_FLAG(16,tt), INSN_FLAG(18,u), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(CMPOR[U] src RELOP dst, !TCy, TCx),
			},
			{
				// FDDD0xvvFSSSxx110001001E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,2,3), INSN_MASK(19,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FSSS), INSN_FLAG(16,vv), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(ROL BitOut, src, BitIn, dst),
			},
			{
				// FDDD1xvvFSSSxx110001001E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,2,3), INSN_MASK(19,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FSSS), INSN_FLAG(16,vv), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(ROR BitIn, src, BitOut, dst),
			},
			{
				// FDDDxuxtFSSScc000001001E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(10,cc), INSN_FLAG(12,FSSS), INSN_FLAG(16,t), INSN_FLAG(18,u), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(CMP[U] src RELOP dst, TCx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x14,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// XACD0000XACS00010001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,1), INSN_MASK(16,4,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,XACS), INSN_FLAG(20,XACD),  LIST_END },
				.syntax = INSN_SYNTAX(AADD XACsrc, XACdst),
			},
			{
				// XACD0001XACS00010001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,1), INSN_MASK(16,4,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,XACS), INSN_FLAG(20,XACD),  LIST_END },
				.syntax = INSN_SYNTAX(AMOV XACsrc, XACdst),
			},
			{
				// XACD0010XACS00010001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,1), INSN_MASK(16,4,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,XACS), INSN_FLAG(20,XACD),  LIST_END },
				.syntax = INSN_SYNTAX(ASUB XACsrc, XACdst),
			},
			{
				// XACD1000XACS00010001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,1), INSN_MASK(16,4,8),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,XACS), INSN_FLAG(20,XACD),  LIST_END },
				.syntax = INSN_SYNTAX(AADD XACsrc, XACdst),
			},
			{
				// XACD1001XACS00010001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,1), INSN_MASK(16,4,9),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,XACS), INSN_FLAG(20,XACD),  LIST_END },
				.syntax = INSN_SYNTAX(AMOV XACsrc, XACdst),
			},
			{
				// XACD1010XACS00010001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,1), INSN_MASK(16,4,10),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,XACS), INSN_FLAG(20,XACD),  LIST_END },
				.syntax = INSN_SYNTAX(ASUB XACsrc, XACdst),
			},
			{
				// FDDD0000FSSSxxxx0001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FSSS), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(AADD TAx, TAy),
			},
			{
				// FDDD0001FSSSxxxx0001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FSSS), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(AMOV TAx, TAy),
			},
			{
				// FDDD0010FSSSxxxx0001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FSSS), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(ASUB TAx, TAy),
			},
			{
				// FDDD0100PPPPPPPP0001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,P8), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(AADD P8, TAx),
			},
			{
				// FDDD0101PPPPPPPP0001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,P8), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(AMOV P8, TAx),
			},
			{
				// FDDD0110PPPPPPPP0001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,6),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,P8), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(ASUB P8, TAx),
			},
			{
				// FDDD1000FSSSxxxx0001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,8),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FSSS), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(AADD TAx, TAy),
			},
			{
				// FDDD1001FSSSxxxx0001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,9),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FSSS), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(AMOV TAx, TAy),
			},
			{
				// FDDD1010FSSSxxxx0001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,10),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FSSS), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(ASUB TAx, TAy),
			},
			{
				// FDDD1100PPPPPPPP0001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,12),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,P8), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(AADD P8, TAx),
			},
			{
				// FDDD1101PPPPPPPP0001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,13),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,P8), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(AMOV P8, TAx),
			},
			{
				// FDDD1110PPPPPPPP0001010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,14),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,P8), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(ASUB P8, TAx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x16,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// kkkk0000xxxxxkkk0001011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,k3), INSN_FLAG(20,k4),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k7, DPH),
			},
			{
				// kkkk0011xxxkkkkk0001011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,k5), INSN_FLAG(20,k4),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k9, PDP),
			},
			{
				// kkkk0100kkkkkkkk0001011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,k8), INSN_FLAG(20,k4),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k12, BK03),
			},
			{
				// kkkk0101kkkkkkkk0001011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,k8), INSN_FLAG(20,k4),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k12, BK47),
			},
			{
				// kkkk0110kkkkkkkk0001011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,6),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,k8), INSN_FLAG(20,k4),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k12, BKC),
			},
			{
				// kkkk1000kkkkkkkk0001011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,8),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,k8), INSN_FLAG(20,k4),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k12, CSR),
			},
			{
				// kkkk1001kkkkkkkk0001011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,9),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,k8), INSN_FLAG(20,k4),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k12, BRC0),
			},
			{
				// kkkk1010kkkkkkkk0001011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,10),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,k8), INSN_FLAG(20,k4),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k12, BRC1),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x18,
	.size = 0x03,
	.insn = {
		// FDDDFSSSkkkkkkkk0001100E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,k8), INSN_FLAG(16,FSSS), INSN_FLAG(20,FDDD),  LIST_END },
		.syntax = INSN_SYNTAX(AND k8, src, dst),
	},
},
{
	.byte = 0x1a,
	.size = 0x03,
	.insn = {
		// FDDDFSSSkkkkkkkk0001101E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,k8), INSN_FLAG(16,FSSS), INSN_FLAG(20,FDDD),  LIST_END },
		.syntax = INSN_SYNTAX(OR k8, src, dst),
	},
},
{
	.byte = 0x1c,
	.size = 0x03,
	.insn = {
		// FDDDFSSSkkkkkkkk0001110E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,k8), INSN_FLAG(16,FSSS), INSN_FLAG(20,FDDD),  LIST_END },
		.syntax = INSN_SYNTAX(XOR k8, src, dst),
	},
},
{
	.byte = 0x1e,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// SSDDxx0%KKKKKKKK0001111E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,K8), INSN_FLAG(16,R), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MPYK[R] K8, [ACx,] ACy),
			},
			{
				// SSDDss1%KKKKKKKK0001111E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,K8), INSN_FLAG(16,R), INSN_FLAG(18,ss), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MACK[R] Tx, K8, [ACx,] ACy),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x20,
	.size = 0x01,
	.insn = {
		// 0010000E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E),  LIST_END },
		.syntax = INSN_SYNTAX(NOP),
	},
},
{
	.byte = 0x22,
	.size = 0x02,
	.insn = {
		// FSSSFDDD0010001E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,FSSS),  LIST_END },
		.syntax = INSN_SYNTAX(MOV src, dst),
	},
},
{
	.byte = 0x24,
	.size = 0x02,
	.insn = {
		// FSSSFDDD0010010E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,FSSS),  LIST_END },
		.syntax = INSN_SYNTAX(ADD [src,] dst),
	},
},
{
	.byte = 0x26,
	.size = 0x02,
	.insn = {
		// FSSSFDDD0010011E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,FSSS),  LIST_END },
		.syntax = INSN_SYNTAX(SUB [src,] dst),
	},
},
{
	.byte = 0x28,
	.size = 0x02,
	.insn = {
		// FSSSFDDD0010100E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,FSSS),  LIST_END },
		.syntax = INSN_SYNTAX(AND src, dst),
	},
},
{
	.byte = 0x2a,
	.size = 0x02,
	.insn = {
		// FSSSFDDD0010101E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,FSSS),  LIST_END },
		.syntax = INSN_SYNTAX(OR src, dst),
	},
},
{
	.byte = 0x2c,
	.size = 0x02,
	.insn = {
		// FSSSFDDD0010110E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,FSSS),  LIST_END },
		.syntax = INSN_SYNTAX(XOR src, dst),
	},
},
{
	.byte = 0x2e,
	.size = 0x02,
	.insn = {
		// FSSSFDDD0010111E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,FSSS),  LIST_END },
		.syntax = INSN_SYNTAX(MAX [src,] dst),
	},
},
{
	.byte = 0x30,
	.size = 0x02,
	.insn = {
		// FSSSFDDD0011000E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,FSSS),  LIST_END },
		.syntax = INSN_SYNTAX(MIN [src,] dst),
	},
},
{
	.byte = 0x32,
	.size = 0x02,
	.insn = {
		// FSSSFDDD0011001E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,FSSS),  LIST_END },
		.syntax = INSN_SYNTAX(ABS [src,] dst),
	},
},
{
	.byte = 0x34,
	.size = 0x02,
	.insn = {
		// FSSSFDDD0011010E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,FSSS),  LIST_END },
		.syntax = INSN_SYNTAX(NEG [src,] dst),
	},
},
{
	.byte = 0x36,
	.size = 0x02,
	.insn = {
		// FSSSFDDD0011011E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,FSSS),  LIST_END },
		.syntax = INSN_SYNTAX(NOT [src,] dst),
	},
},
{
	.byte = 0x38,
	.size = 0x02,
	.insn = {
		// FSSSFDDD0011100E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,FSSS),  LIST_END },
		.syntax = INSN_SYNTAX(PSH src1, src2),
	},
},
{
	.byte = 0x3a,
	.size = 0x02,
	.insn = {
		// FSSSFDDD0011101E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,FSSS),  LIST_END },
		.syntax = INSN_SYNTAX(POP dst1, dst2),
	},
},
{
	.byte = 0x3c,
	.size = 0x02,
	.insn = {
		// kkkkFDDD0011110E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,k4),  LIST_END },
		.syntax = INSN_SYNTAX(MOV k4, dst),
	},
},
{
	.byte = 0x3e,
	.size = 0x02,
	.insn = {
		// kkkkFDDD0011111E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,k4),  LIST_END },
		.syntax = INSN_SYNTAX(MOV -k4, dst),
	},
},
{
	.byte = 0x40,
	.size = 0x02,
	.insn = {
		// kkkkFDDD0100000E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,k4),  LIST_END },
		.syntax = INSN_SYNTAX(ADD k4, dst),
	},
},
{
	.byte = 0x42,
	.size = 0x02,
	.insn = {
		// kkkkFDDD0100001E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,k4),  LIST_END },
		.syntax = INSN_SYNTAX(SUB k4, dst),
	},
},
{
	.byte = 0x44,
	.size = 0x02,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// 1000FDDD0100010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(12,4,8),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV SP, TAx),
			},
			{
				// 1001FDDD0100010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(12,4,9),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV SSP, TAx),
			},
			{
				// 1010FDDD0100010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(12,4,10),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV CDP, TAx),
			},
			{
				// 1100FDDD0100010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(12,4,12),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV BRC0, TAx),
			},
			{
				// 1101FDDD0100010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(12,4,13),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV BRC1, TAx),
			},
			{
				// 1110FDDD0100010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(12,4,14),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV RPTC, TAx),
			},
			{
				// 01x0FDDD0100010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(12,1,0), INSN_MASK(14,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(SFTS dst, #-1),
			},
			{
				// 01x1FDDD0100010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(12,1,1), INSN_MASK(14,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(SFTS dst, #1),
			},
			{
				// 00SSFDDD0100010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(14,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV HI(ACx), TAx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x46,
	.size = 0x02,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// kkkk00000100011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,k4),  LIST_END },
				.syntax = INSN_SYNTAX(BCLR k4, ST0_55),
			},
			{
				// kkkk00010100011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,k4),  LIST_END },
				.syntax = INSN_SYNTAX(BSET k4, ST0_55),
			},
			{
				// kkkk00100100011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,k4),  LIST_END },
				.syntax = INSN_SYNTAX(BCLR k4, ST1_55),
			},
			{
				// kkkk00110100011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,k4),  LIST_END },
				.syntax = INSN_SYNTAX(BSET k4, ST1_55),
			},
			{
				// kkkk01000100011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,k4),  LIST_END },
				.syntax = INSN_SYNTAX(BCLR k4, ST2_55),
			},
			{
				// kkkk01010100011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,k4),  LIST_END },
				.syntax = INSN_SYNTAX(BSET k4, ST2_55),
			},
			{
				// kkkk01100100011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,6),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,k4),  LIST_END },
				.syntax = INSN_SYNTAX(BCLR k4, ST3_55),
			},
			{
				// kkkk01110100011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,7),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,k4),  LIST_END },
				.syntax = INSN_SYNTAX(BSET k4, ST3_55),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x48,
	.size = 0x02,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// xxxxx10101001000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,3,5),  LIST_END },
				.f_list = NULL,
				.syntax = INSN_SYNTAX(RETI),
			},
			{
				// xxxxx0000100100E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,3,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E),  LIST_END },
				.syntax = INSN_SYNTAX(RPT CSR),
			},
			{
				// FSSSx0010100100E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,3,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(RPTADD CSR, TAx),
			},
			{
				// kkkkx0100100100E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,3,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,k4),  LIST_END },
				.syntax = INSN_SYNTAX(RPTADD CSR, k4),
			},
			{
				// kkkkx0110100100E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,3,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,k4),  LIST_END },
				.syntax = INSN_SYNTAX(RPTSUB CSR, k4),
			},
			{
				// xxxxx1000100100E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,3,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E),  LIST_END },
				.syntax = INSN_SYNTAX(RET),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x4a,
	.size = 0x02,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// 0LLLLLLL0100101E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(15,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,L7),  LIST_END },
				.syntax = INSN_SYNTAX(B L7),
			},
			{
				// 1lllllll0100101E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(15,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,l7),  LIST_END },
				.syntax = INSN_SYNTAX(RPTBLOCAL pmad),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x4c,
	.size = 0x02,
	.insn = {
		// kkkkkkkk0100110E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,k8),  LIST_END },
		.syntax = INSN_SYNTAX(RPT k8),
	},
},
{
	.byte = 0x4e,
	.size = 0x02,
	.insn = {
		// KKKKKKKK0100111E
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,K8),  LIST_END },
		.syntax = INSN_SYNTAX(AADD K8, SP),
	},
},
{
	.byte = 0x50,
	.size = 0x02,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// XDDD01000101000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,XDDD),  LIST_END },
				.syntax = INSN_SYNTAX(POPBOTH xdst),
			},
			{
				// XSSS01010101000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,XSSS),  LIST_END },
				.syntax = INSN_SYNTAX(PSHBOTH xsrc),
			},
			{
				// FDDDx0000101000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,3,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(SFTL dst, #1),
			},
			{
				// FDDDx0010101000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,3,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(SFTL dst, #-1),
			},
			{
				// FDDDx0100101000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,3,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(POP dst),
			},
			{
				// xxDDx0110101000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,3,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,DD),  LIST_END },
				.syntax = INSN_SYNTAX(POP dbl(ACx)),
			},
			{
				// FSSSx1100101000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,3,6),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(PSH src),
			},
			{
				// xxSSx1110101000E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,3,7),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,SS),  LIST_END },
				.syntax = INSN_SYNTAX(PSH dbl(ACx)),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x52,
	.size = 0x02,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// FSSS10000101001E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,8),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV TAx, SP),
			},
			{
				// FSSS10010101001E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,9),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV TAx, SSP),
			},
			{
				// FSSS10100101001E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,10),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV TAx, CDP),
			},
			{
				// FSSS11000101001E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,12),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV TAx, CSR),
			},
			{
				// FSSS11010101001E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,13),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV TAx, BRC1),
			},
			{
				// FSSS11100101001E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,4,14),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(12,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV TAx, BRC0),
			},
			{
				// FSSS00DD0101001E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(10,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,DD), INSN_FLAG(12,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV TAx, HI(ACx)),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x54,
	.size = 0x02,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// DDSS000%0101010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(9,3,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,R), INSN_FLAG(12,SS), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(ADD[R]V [ACx,] ACy),
			},
			{
				// DDSS001%0101010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(9,3,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,R), INSN_FLAG(12,SS), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(SQA[R] [ACx,] ACy),
			},
			{
				// DDSS010%0101010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(9,3,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,R), INSN_FLAG(12,SS), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(SQS[R] [ACx,] ACy),
			},
			{
				// DDSS011%0101010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(9,3,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,R), INSN_FLAG(12,SS), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MPY[R] [ACx,] ACy),
			},
			{
				// DDSS100%0101010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(9,3,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,R), INSN_FLAG(12,SS), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(SQR[R] [ACx,] ACy),
			},
			{
				// DDSS101%0101010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(9,3,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,R), INSN_FLAG(12,SS), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(ROUND [ACx,] ACy),
			},
			{
				// DDSS110%0101010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(9,3,6),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,R), INSN_FLAG(12,SS), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(SAT[R] [ACx,] ACy),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x56,
	.size = 0x02,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// DDSSss0%0101011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(9,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,R), INSN_FLAG(10,ss), INSN_FLAG(12,SS), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R] ACx, Tx, ACy[, ACy]),
			},
			{
				// DDSSss1%0101011E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(9,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,R), INSN_FLAG(10,ss), INSN_FLAG(12,SS), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAS[R] Tx, [ACx,] ACy),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x58,
	.size = 0x02,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// DDSSss0%0101100E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(9,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,R), INSN_FLAG(10,ss), INSN_FLAG(12,SS), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MPY[R] Tx, [ACx,] ACy),
			},
			{
				// DDSSss1%0101100E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(9,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,R), INSN_FLAG(10,ss), INSN_FLAG(12,SS), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R] ACy, Tx, ACx, ACy),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x5a,
	.size = 0x02,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// DDSSss000101101E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(10,ss), INSN_FLAG(12,SS), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(ADD ACx << Tx, ACy),
			},
			{
				// DDSSss010101101E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(10,ss), INSN_FLAG(12,SS), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(SUB ACx << Tx, ACy),
			},
			{
				// DDxxxx1t0101101E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(9,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,t), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(SFTCC ACx, TCx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x5c,
	.size = 0x02,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// DDSSss000101110E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(10,ss), INSN_FLAG(12,SS), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(SFTL ACx, Tx[, ACy]),
			},
			{
				// DDSSss010101110E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(10,ss), INSN_FLAG(12,SS), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(SFTS ACx, Tx[, ACy]),
			},
			{
				// DDSSss100101110E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(10,ss), INSN_FLAG(12,SS), INSN_FLAG(14,DD),  LIST_END },
				.syntax = INSN_SYNTAX(SFTSC ACx, Tx[, ACy]),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x5e,
	.size = 0x02,
	.insn = {
		// 00kkkkkk0101111E
		.i_list = NULL,
		.m_list = (insn_mask_t []) { INSN_MASK(14,2,0),  LIST_END },
		.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,k6),  LIST_END },
		.syntax = INSN_SYNTAX(SWAP ( )),
	},
},
{
	.byte = 0x60,
	.size = 0x02,
	.insn = {
		// lCCCCCCC01100lll
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,l3), INSN_FLAG(8,CCCCCCC), INSN_FLAG(15,l1),  LIST_END },
		.syntax = INSN_SYNTAX(BCC l4, cond),
	},
},
{
	.byte = 0x68,
	.size = 0x05,
	.insn = {
		// PPPPPPPPPPPPPPPPPPPPPPPPxCCCCCCC01101000
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,CCCCCCC), INSN_FLAG(16,P24),  LIST_END },
		.syntax = INSN_SYNTAX(BCC P24, cond),
	},
},
{
	.byte = 0x69,
	.size = 0x05,
	.insn = {
		// PPPPPPPPPPPPPPPPPPPPPPPPxCCCCCCC01101001
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,CCCCCCC), INSN_FLAG(16,P24),  LIST_END },
		.syntax = INSN_SYNTAX(CALLCC P24, cond),
	},
},
{
	.byte = 0x6a,
	.size = 0x04,
	.insn = {
		// PPPPPPPPPPPPPPPPPPPPPPPP01101010
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,P24),  LIST_END },
		.syntax = INSN_SYNTAX(B P24),
	},
},
{
	.byte = 0x6c,
	.size = 0x04,
	.insn = {
		// PPPPPPPPPPPPPPPPPPPPPPPP01101100
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,P24),  LIST_END },
		.syntax = INSN_SYNTAX(CALL P24),
	},
},
{
	.byte = 0x6d,
	.size = 0x04,
	.insn = {
		// LLLLLLLLLLLLLLLLxCCCCCCC01101101
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,CCCCCCC), INSN_FLAG(16,L16),  LIST_END },
		.syntax = INSN_SYNTAX(BCC L16, cond),
	},
},
{
	.byte = 0x6e,
	.size = 0x04,
	.insn = {
		// LLLLLLLLLLLLLLLLxCCCCCCC01101110
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,CCCCCCC), INSN_FLAG(16,L16),  LIST_END },
		.syntax = INSN_SYNTAX(CALLCC L16, cond),
	},
},
{
	.byte = 0x6f,
	.size = 0x04,
	.insn = {
		// LLLLLLLLKKKKKKKKFSSSccxu01101111
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,u), INSN_FLAG(10,cc), INSN_FLAG(12,FSSS), INSN_FLAG(16,K8), INSN_FLAG(24,L8),  LIST_END },
		.syntax = INSN_SYNTAX(BCC[U] L8, src RELOP K8),
	},
},
{
	.byte = 0x70,
	.size = 0x04,
	.insn = {
		// SSDDSHFTKKKKKKKKKKKKKKKK01110000
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,K16), INSN_FLAG(24,SHFT), INSN_FLAG(28,DD), INSN_FLAG(30,SS),  LIST_END },
		.syntax = INSN_SYNTAX(ADD K16 << #SHFT, [ACx,] ACy),
	},
},
{
	.byte = 0x71,
	.size = 0x04,
	.insn = {
		// SSDDSHFTKKKKKKKKKKKKKKKK01110001
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,K16), INSN_FLAG(24,SHFT), INSN_FLAG(28,DD), INSN_FLAG(30,SS),  LIST_END },
		.syntax = INSN_SYNTAX(SUB K16 << #SHFT, [ACx,] ACy),
	},
},
{
	.byte = 0x72,
	.size = 0x04,
	.insn = {
		// SSDDSHFTkkkkkkkkkkkkkkkk01110010
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,k16), INSN_FLAG(24,SHFT), INSN_FLAG(28,DD), INSN_FLAG(30,SS),  LIST_END },
		.syntax = INSN_SYNTAX(AND k16 << #SHFT, [ACx,] ACy),
	},
},
{
	.byte = 0x73,
	.size = 0x04,
	.insn = {
		// SSDDSHFTkkkkkkkkkkkkkkkk01110011
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,k16), INSN_FLAG(24,SHFT), INSN_FLAG(28,DD), INSN_FLAG(30,SS),  LIST_END },
		.syntax = INSN_SYNTAX(OR k16 << #SHFT, [ACx,] ACy),
	},
},
{
	.byte = 0x74,
	.size = 0x04,
	.insn = {
		// SSDDSHFTkkkkkkkkkkkkkkkk01110100
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,k16), INSN_FLAG(24,SHFT), INSN_FLAG(28,DD), INSN_FLAG(30,SS),  LIST_END },
		.syntax = INSN_SYNTAX(XOR k16 << #SHFT, [ACx,] ACy),
	},
},
{
	.byte = 0x75,
	.size = 0x04,
	.insn = {
		// xxDDSHFTKKKKKKKKKKKKKKKK01110101
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,K16), INSN_FLAG(24,SHFT), INSN_FLAG(28,DD),  LIST_END },
		.syntax = INSN_SYNTAX(MOV K16 << #SHFT, ACx),
	},
},
{
	.byte = 0x76,
	.size = 0x04,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// FDDD00SSkkkkkkkkkkkkkkkk01110110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(26,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,k16), INSN_FLAG(24,SS), INSN_FLAG(28,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(BFXTR k16, ACx, dst),
			},
			{
				// FDDD01SSkkkkkkkkkkkkkkkk01110110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(26,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,k16), INSN_FLAG(24,SS), INSN_FLAG(28,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(BFXPA k16, ACx, dst),
			},
			{
				// FDDD10xxKKKKKKKKKKKKKKKK01110110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(26,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,K16), INSN_FLAG(28,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV K16, dst),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x77,
	.size = 0x04,
	.insn = {
		// FDDDxxxxDDDDDDDDDDDDDDDD01110111
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,D16), INSN_FLAG(28,FDDD),  LIST_END },
		.syntax = INSN_SYNTAX(AMOV D16, TAx),
	},
},
{
	.byte = 0x78,
	.size = 0x04,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// xxx0000xkkkkkkkkkkkkkkkk01111000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,4,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,k16),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k16, DP),
			},
			{
				// xxx0001xkkkkkkkkkkkkkkkk01111000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,4,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,k16),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k16, SSP),
			},
			{
				// xxx0010xkkkkkkkkkkkkkkkk01111000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,4,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,k16),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k16, CDP),
			},
			{
				// xxx0011xkkkkkkkkkkkkkkkk01111000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,4,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,k16),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k16, BSA01),
			},
			{
				// xxx0100xkkkkkkkkkkkkkkkk01111000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,4,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,k16),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k16, BSA23),
			},
			{
				// xxx0101xkkkkkkkkkkkkkkkk01111000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,4,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,k16),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k16, BSA45),
			},
			{
				// xxx0110xkkkkkkkkkkkkkkkk01111000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,4,6),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,k16),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k16, BSA67),
			},
			{
				// xxx0111xkkkkkkkkkkkkkkkk01111000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,4,7),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,k16),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k16, BSAC),
			},
			{
				// xxx1000xkkkkkkkkkkkkkkkk01111000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,4,8),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,k16),  LIST_END },
				.syntax = INSN_SYNTAX(MOV k16, SP),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x79,
	.size = 0x04,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// SSDDxx0%KKKKKKKKKKKKKKKK01111001
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,K16), INSN_FLAG(24,R), INSN_FLAG(28,DD), INSN_FLAG(30,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MPYK[R] K16, [ACx,] ACy),
			},
			{
				// SSDDss1%KKKKKKKKKKKKKKKK01111001
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,K16), INSN_FLAG(24,R), INSN_FLAG(26,ss), INSN_FLAG(28,DD), INSN_FLAG(30,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MACK[R] Tx, K16, [ACx,] ACy),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x7a,
	.size = 0x04,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// SSDD000xKKKKKKKKKKKKKKKK01111010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,3,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,K16), INSN_FLAG(28,DD), INSN_FLAG(30,SS),  LIST_END },
				.syntax = INSN_SYNTAX(ADD K16 << #16, [ACx,] ACy),
			},
			{
				// SSDD001xKKKKKKKKKKKKKKKK01111010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,3,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,K16), INSN_FLAG(28,DD), INSN_FLAG(30,SS),  LIST_END },
				.syntax = INSN_SYNTAX(SUB K16 << #16, [ACx,] ACy),
			},
			{
				// SSDD010xkkkkkkkkkkkkkkkk01111010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,3,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,k16), INSN_FLAG(28,DD), INSN_FLAG(30,SS),  LIST_END },
				.syntax = INSN_SYNTAX(AND k16 << #16, [ACx,] ACy),
			},
			{
				// SSDD011xkkkkkkkkkkkkkkkk01111010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,3,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,k16), INSN_FLAG(28,DD), INSN_FLAG(30,SS),  LIST_END },
				.syntax = INSN_SYNTAX(OR k16 << #16, [ACx,] ACy),
			},
			{
				// SSDD100xkkkkkkkkkkkkkkkk01111010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,3,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,k16), INSN_FLAG(28,DD), INSN_FLAG(30,SS),  LIST_END },
				.syntax = INSN_SYNTAX(XOR k16 << #16, [ACx,] ACy),
			},
			{
				// xxDD101xKKKKKKKKKKKKKKKK01111010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,3,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,K16), INSN_FLAG(28,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV K16 << #16, ACx),
			},
			{
				// xxxx110xxxxxxxxxxxxxxxxx01111010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(25,3,6),  LIST_END },
				.f_list = NULL,
				.syntax = INSN_SYNTAX(IDLE),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x7b,
	.size = 0x04,
	.insn = {
		// FDDDFSSSKKKKKKKKKKKKKKKK01111011
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,K16), INSN_FLAG(24,FSSS), INSN_FLAG(28,FDDD),  LIST_END },
		.syntax = INSN_SYNTAX(ADD K16, [src,] dst),
	},
},
{
	.byte = 0x7c,
	.size = 0x04,
	.insn = {
		// FDDDFSSSKKKKKKKKKKKKKKKK01111100
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,K16), INSN_FLAG(24,FSSS), INSN_FLAG(28,FDDD),  LIST_END },
		.syntax = INSN_SYNTAX(SUB K16, [src,] dst),
	},
},
{
	.byte = 0x7d,
	.size = 0x04,
	.insn = {
		// FDDDFSSSkkkkkkkkkkkkkkkk01111101
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,k16), INSN_FLAG(24,FSSS), INSN_FLAG(28,FDDD),  LIST_END },
		.syntax = INSN_SYNTAX(AND k16, src, dst),
	},
},
{
	.byte = 0x7e,
	.size = 0x04,
	.insn = {
		// FDDDFSSSkkkkkkkkkkkkkkkk01111110
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,k16), INSN_FLAG(24,FSSS), INSN_FLAG(28,FDDD),  LIST_END },
		.syntax = INSN_SYNTAX(OR k16, src, dst),
	},
},
{
	.byte = 0x7f,
	.size = 0x04,
	.insn = {
		// FDDDFSSSkkkkkkkkkkkkkkkk01111111
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,k16), INSN_FLAG(24,FSSS), INSN_FLAG(28,FDDD),  LIST_END },
		.syntax = INSN_SYNTAX(XOR k16, src, dst),
	},
},
{
	.byte = 0x80,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// YMMM00xxXXXMMMYY10000000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(20,MMM), INSN_FLAG(23,Y),  LIST_END },
				.syntax = INSN_SYNTAX(MOV dbl(Xmem), dbl(Ymem)),
			},
			{
				// YMMM01xxXXXMMMYY10000000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(20,MMM), INSN_FLAG(23,Y),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Xmem, Ymem),
			},
			{
				// YMMM10SSXXXMMMYY10000000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,SS), INSN_FLAG(20,MMM), INSN_FLAG(23,Y),  LIST_END },
				.syntax = INSN_SYNTAX(MOV ACx, Xmem, Ymem),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x81,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// YMMM00DDXXXMMMYY10000001
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(20,MMM), INSN_FLAG(23,Y),  LIST_END },
				.syntax = INSN_SYNTAX(ADD Xmem, Ymem, ACx),
			},
			{
				// YMMM01DDXXXMMMYY10000001
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(20,MMM), INSN_FLAG(23,Y),  LIST_END },
				.syntax = INSN_SYNTAX(SUB Xmem, Ymem, ACx),
			},
			{
				// YMMM10DDXXXMMMYY10000001
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(20,MMM), INSN_FLAG(23,Y),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Xmem, Ymem, ACx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x82,
	.size = 0x04,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// uuDDDDg%YMMM00mmXXXMMMYY10000010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,DD), INSN_FLAG(28,DD), INSN_FLAG(30,uu),  LIST_END },
				.syntax = INSN_SYNTAX(MPY[R][40] [uns(]Xmem[)], [uns(]Cmem[)], ACx :: MPY[R][40] [uns(]Ymem[)], [uns(]Cmem[)], ACy),
			},
			{
				// uuDDDDg%YMMM01mmXXXMMMYY10000010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,DD), INSN_FLAG(28,DD), INSN_FLAG(30,uu),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]Xmem[)], [uns(]Cmem[)], ACx :: MPY[R][40] [uns(]Ymem[)], [uns(]Cmem[)], ACy),
			},
			{
				// uuDDDDg%YMMM10mmXXXMMMYY10000010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,DD), INSN_FLAG(28,DD), INSN_FLAG(30,uu),  LIST_END },
				.syntax = INSN_SYNTAX(MAS[R][40] [uns(]Xmem[)], [uns(]Cmem[)], ACx :: MPY[R][40] [uns(]Ymem[)], [uns(]Cmem[)], ACy),
			},
			{
				// uuxxDDg%YMMM11mmXXXMMMYY10000010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,DD), INSN_FLAG(30,uu),  LIST_END },
				.syntax = INSN_SYNTAX(AMAR Xmem :: MPY[R][40] [uns(]Ymem[)], [uns(]Cmem[)], ACx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x83,
	.size = 0x04,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// uuDDDDg%YMMM00mmXXXMMMYY10000011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,DD), INSN_FLAG(28,DD), INSN_FLAG(30,uu),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]Xmem[)], [uns(]Cmem[)], ACx :: MAC[R][40] [uns(]Ymem[)], [uns(]Cmem[)], ACy),
			},
			{
				// uuDDDDg%YMMM01mmXXXMMMYY10000011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,DD), INSN_FLAG(28,DD), INSN_FLAG(30,uu),  LIST_END },
				.syntax = INSN_SYNTAX(MAS[R][40] [uns(]Xmem[)], [uns(]Cmem[)], ACx :: MAC[R][40] [uns(]Ymem[)], [uns(]Cmem[)], ACy),
			},
			{
				// uuDDDDg%YMMM10mmXXXMMMYY10000011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,DD), INSN_FLAG(28,DD), INSN_FLAG(30,uu),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]Xmem[)], [uns(]Cmem[)], ACx >> #16 :: MAC[R][40] [uns(]Ymem[)], [uns(]Cmem[)], ACy),
			},
			{
				// uuxxDDg%YMMM11mmXXXMMMYY10000011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,DD), INSN_FLAG(30,uu),  LIST_END },
				.syntax = INSN_SYNTAX(AMAR Xmem :: MAC[R][40] [uns(]Ymem[)], [uns(]Cmem[)], ACx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x84,
	.size = 0x04,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// uuDDDDg%YMMM00mmXXXMMMYY10000100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,DD), INSN_FLAG(28,DD), INSN_FLAG(30,uu),  LIST_END },
				.syntax = INSN_SYNTAX(MAS[R][40] [uns(]Xmem[)], [uns(]Cmem[)], ACx :: MAC[R][40] [uns(]Ymem[)], [uns(]Cmem[)], ACy >> #16),
			},
			{
				// uuxxDDg%YMMM01mmXXXMMMYY10000100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,DD), INSN_FLAG(30,uu),  LIST_END },
				.syntax = INSN_SYNTAX(AMAR Xmem :: MAC[R][40] [uns(]Ymem[)], [uns(]Cmem[)], ACx >> #16),
			},
			{
				// uuDDDDg%YMMM10mmXXXMMMYY10000100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,DD), INSN_FLAG(28,DD), INSN_FLAG(30,uu),  LIST_END },
				.syntax = INSN_SYNTAX(MPY[R][40] [uns(]Xmem[)], [uns(]Cmem[)], ACx :: MAC[R][40] [uns(]Ymem[)], [uns(]Cmem[)], ACy >> #16),
			},
			{
				// uuDDDDg%YMMM11mmXXXMMMYY10000100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,DD), INSN_FLAG(28,DD), INSN_FLAG(30,uu),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]Xmem[)], [uns(]Cmem[)], ACx >> #16 :: MAC[R][40] [uns(]Ymem[)], [uns(]Cmem[)], ACy >> #16),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x85,
	.size = 0x04,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// DDx0DDU%YMMM11mmXXXMMMYY10000101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,3), INSN_MASK(28,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,U), INSN_FLAG(26,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(FIRSADD Xmem, Ymem, Cmem, ACx, ACy),
			},
			{
				// DDx1DDU%YMMM11mmXXXMMMYY10000101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,3), INSN_MASK(28,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,U), INSN_FLAG(26,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(FIRSSUB Xmem, Ymem, Cmem, ACx, ACy),
			},
			{
				// uuxxDDg%YMMM00mmXXXMMMYY10000101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,DD), INSN_FLAG(30,uu),  LIST_END },
				.syntax = INSN_SYNTAX(AMAR Xmem :: MAS[R][40] [uns(]Ymem[)], [uns(]Cmem[)], ACx),
			},
			{
				// uuDDDDg%YMMM01mmXXXMMMYY10000101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,DD), INSN_FLAG(28,DD), INSN_FLAG(30,uu),  LIST_END },
				.syntax = INSN_SYNTAX(MAS[R][40] [uns(]Xmem[)], [uns(]Cmem[)], ACx :: MAS[R][40] [uns(]Ymem[)], [uns(]Cmem[)], ACy),
			},
			{
				// xxxxxxxxYMMM10mmXXXMMMYY10000101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,mm), INSN_FLAG(20,MMM), INSN_FLAG(23,Y),  LIST_END },
				.syntax = INSN_SYNTAX(AMAR Xmem, Ymem, Cmem),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x86,
	.size = 0x04,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// 1110xxn%YMMMDDDDXXXMMMYY10000110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(28,4,14),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(18,DD), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R),  LIST_END },
				.syntax = INSN_SYNTAX(SQDST Xmem, Ymem, ACx, ACy),
			},
			{
				// 1111xxn%YMMMDDDDXXXMMMYY10000110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(28,4,15),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(18,DD), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R),  LIST_END },
				.syntax = INSN_SYNTAX(ABDST Xmem, Ymem, ACx, ACy),
			},
			{
				// 000guuU%YMMMxxDDXXXMMMYY10000110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(29,3,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,U), INSN_FLAG(26,uu), INSN_FLAG(28,g),  LIST_END },
				.syntax = INSN_SYNTAX(MPYM[R][40] [T3 = ][uns(]Xmem[)], [uns(]Ymem[)], ACx),
			},
			{
				// 001guuU%YMMMSSDDXXXMMMYY10000110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(29,3,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(18,SS), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,U), INSN_FLAG(26,uu), INSN_FLAG(28,g),  LIST_END },
				.syntax = INSN_SYNTAX(MACM[R][40] [T3 = ][uns(]Xmem[)], [uns(]Ymem[)], [ACx,] ACy),
			},
			{
				// 010guuU%YMMMSSDDXXXMMMYY10000110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(29,3,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(18,SS), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,U), INSN_FLAG(26,uu), INSN_FLAG(28,g),  LIST_END },
				.syntax = INSN_SYNTAX(MACM[R][40] [T3 = ][uns(]Xmem[)], [uns(]Ymem[)], ACx >> #16[, ACy]),
			},
			{
				// 011guuU%YMMMSSDDXXXMMMYY10000110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(29,3,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(18,SS), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,U), INSN_FLAG(26,uu), INSN_FLAG(28,g),  LIST_END },
				.syntax = INSN_SYNTAX(MASM[R][40] [T3 = ][uns(]Xmem[)], [uns(]Ymem[)], [ACx,] ACy),
			},
			{
				// 100xssU%YMMMDDDDXXXMMMYY10000110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(29,3,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(18,DD), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,U), INSN_FLAG(26,ss),  LIST_END },
				.syntax = INSN_SYNTAX(MASM[R] [T3 = ]Xmem, Tx, ACx :: MOV Ymem << #16, ACy),
			},
			{
				// 101xssU%YMMMDDDDXXXMMMYY10000110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(29,3,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(18,DD), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,U), INSN_FLAG(26,ss),  LIST_END },
				.syntax = INSN_SYNTAX(MACM[R] [T3 = ]Xmem, Tx, ACx :: MOV Ymem << #16, ACy),
			},
			{
				// 110xxxx%YMMMDDDDXXXMMMYY10000110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(29,3,6),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(18,DD), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R),  LIST_END },
				.syntax = INSN_SYNTAX(LMS Xmem, Ymem, ACx, ACy),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x87,
	.size = 0x04,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// 01100001YMMMSSDDXXXMMMYY10000111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(24,8,97),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(18,SS), INSN_FLAG(20,MMM), INSN_FLAG(23,Y),  LIST_END },
				.syntax = INSN_SYNTAX(LMSF Xmem, Ymem, ACx, ACy),
			},
			{
				// 000xssU%YMMMSSDDXXXMMMYY10000111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(29,3,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(18,SS), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,U), INSN_FLAG(26,ss),  LIST_END },
				.syntax = INSN_SYNTAX(MPYM[R] [T3 = ]Xmem, Tx, ACy :: MOV HI(ACx << T2), Ymem),
			},
			{
				// 001xssU%YMMMSSDDXXXMMMYY10000111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(29,3,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(18,SS), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,U), INSN_FLAG(26,ss),  LIST_END },
				.syntax = INSN_SYNTAX(MACM[R] [T3 = ]Xmem, Tx, ACy :: MOV HI(ACx << T2), Ymem),
			},
			{
				// 010xssU%YMMMSSDDXXXMMMYY10000111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(29,3,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(18,SS), INSN_FLAG(20,MMM), INSN_FLAG(23,Y), INSN_FLAG(24,R), INSN_FLAG(25,U), INSN_FLAG(26,ss),  LIST_END },
				.syntax = INSN_SYNTAX(MASM[R] [T3 = ]Xmem, Tx, ACy :: MOV HI(ACx << T2), Ymem),
			},
			{
				// 100xxxxxYMMMSSDDXXXMMMYY10000111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(29,3,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(18,SS), INSN_FLAG(20,MMM), INSN_FLAG(23,Y),  LIST_END },
				.syntax = INSN_SYNTAX(ADD Xmem << #16, ACx, ACy :: MOV HI(ACy << T2), Ymem),
			},
			{
				// 101xxxxxYMMMSSDDXXXMMMYY10000111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(29,3,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(18,SS), INSN_FLAG(20,MMM), INSN_FLAG(23,Y),  LIST_END },
				.syntax = INSN_SYNTAX(SUB Xmem << #16, ACx, ACy :: MOV HI(ACy << T2), Ymem),
			},
			{
				// 110xxxxxYMMMSSDDXXXMMMYY10000111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(29,3,6),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(18,SS), INSN_FLAG(20,MMM), INSN_FLAG(23,Y),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Xmem << #16, ACy :: MOV HI(ACx << T2), Ymem),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x90,
	.size = 0x02,
	.insn = {
		// XSSSXDDD10010000
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,XDDD), INSN_FLAG(12,XSSS),  LIST_END },
		.syntax = INSN_SYNTAX(MOV xsrc, xdst),
	},
},
{
	.byte = 0x91,
	.size = 0x02,
	.insn = {
		// xxxxxxSS10010001
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,SS),  LIST_END },
		.syntax = INSN_SYNTAX(B ACx),
	},
},
{
	.byte = 0x92,
	.size = 0x02,
	.insn = {
		// xxxxxxSS10010010
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,SS),  LIST_END },
		.syntax = INSN_SYNTAX(CALL ACx),
	},
},
{
	.byte = 0x94,
	.size = 0x02,
	.insn = {
		// xxxxxxxx10010100
		.i_list = NULL,
		.m_list = NULL,
		.f_list = NULL,
		.syntax = INSN_SYNTAX(RESET),
	},
},
{
	.byte = 0x95,
	.size = 0x02,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// 0xxkkkkk10010101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(15,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,k5),  LIST_END },
				.syntax = INSN_SYNTAX(INTR k5),
			},
			{
				// 1xxkkkkk10010101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(15,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,k5),  LIST_END },
				.syntax = INSN_SYNTAX(TRAP k5),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x96,
	.size = 0x02,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// 0CCCCCCC10010110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(15,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,CCCCCCC),  LIST_END },
				.syntax = INSN_SYNTAX(XCC [label, ]cond),
			},
			{
				// 1CCCCCCC10010110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(15,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,CCCCCCC),  LIST_END },
				.syntax = INSN_SYNTAX(XCCPART [label, ]cond),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x9e,
	.size = 0x02,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// 0CCCCCCC10011110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(15,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,CCCCCCC),  LIST_END },
				.syntax = INSN_SYNTAX(XCC [label, ]cond),
			},
			{
				// 1CCCCCCC10011110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(15,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,CCCCCCC),  LIST_END },
				.syntax = INSN_SYNTAX(XCCPART [label, ]cond),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0x9f,
	.size = 0x02,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// 0CCCCCCC10011111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(15,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,CCCCCCC),  LIST_END },
				.syntax = INSN_SYNTAX(XCC [label, ]cond),
			},
			{
				// 1CCCCCCC10011111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(15,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,CCCCCCC),  LIST_END },
				.syntax = INSN_SYNTAX(XCCPART [label, ]cond),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xa0,
	.size = 0x02,
	.insn = {
		// AAAAAAAI1010FDDD
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,FDDD), INSN_FLAG(8,AAAAAAAI),  LIST_END },
		.syntax = INSN_SYNTAX(MOV Smem, dst),
	},
},
{
	.byte = 0xb0,
	.size = 0x02,
	.insn = {
		// AAAAAAAI101100DD
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,DD), INSN_FLAG(8,AAAAAAAI),  LIST_END },
		.syntax = INSN_SYNTAX(MOV Smem << #16, ACx),
	},
},
{
	.byte = 0xb4,
	.size = 0x02,
	.insn = {
		// AAAAAAAI10110100
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
		.syntax = INSN_SYNTAX(AMAR Smem),
	},
},
{
	.byte = 0xb5,
	.size = 0x02,
	.insn = {
		// AAAAAAAI10110101
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
		.syntax = INSN_SYNTAX(PSH Smem),
	},
},
{
	.byte = 0xb6,
	.size = 0x02,
	.insn = {
		// AAAAAAAI10110110
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
		.syntax = INSN_SYNTAX(DELAY Smem),
	},
},
{
	.byte = 0xb7,
	.size = 0x02,
	.insn = {
		// AAAAAAAI10110111
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
		.syntax = INSN_SYNTAX(PSH dbl(Lmem)),
	},
},
{
	.byte = 0xb8,
	.size = 0x02,
	.insn = {
		// AAAAAAAI10111000
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
		.syntax = INSN_SYNTAX(POP dbl(Lmem)),
	},
},
{
	.byte = 0xbb,
	.size = 0x02,
	.insn = {
		// AAAAAAAI10111011
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
		.syntax = INSN_SYNTAX(POP Smem),
	},
},
{
	.byte = 0xbc,
	.size = 0x02,
	.insn = {
		// AAAAAAAI101111SS
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,SS), INSN_FLAG(8,AAAAAAAI),  LIST_END },
		.syntax = INSN_SYNTAX(MOV HI(ACx), Smem),
	},
},
{
	.byte = 0xc0,
	.size = 0x02,
	.insn = {
		// AAAAAAAI1100FSSS
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(0,FSSS), INSN_FLAG(8,AAAAAAAI),  LIST_END },
		.syntax = INSN_SYNTAX(MOV src, Smem),
	},
},
{
	.byte = 0xd0,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// 0%DD01mmAAAAAAAI11010000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,1), INSN_MASK(23,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(20,DD), INSN_FLAG(22,R),  LIST_END },
				.syntax = INSN_SYNTAX(MPY[R] Smem, uns(Cmem), ACx),
			},
			{
				// 0%DD10mmAAAAAAAI11010000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,2), INSN_MASK(23,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(20,DD), INSN_FLAG(22,R),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R] Smem, uns(Cmem), ACx),
			},
			{
				// 0%DD11mmAAAAAAAI11010000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,3), INSN_MASK(23,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(20,DD), INSN_FLAG(22,R),  LIST_END },
				.syntax = INSN_SYNTAX(MAS[R] Smem, uns(Cmem), ACx),
			},
			{
				// U%DDxxmmAAAAAAAI11010000
				.i_list = NULL,
				.m_list = NULL,
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(20,DD), INSN_FLAG(22,R), INSN_FLAG(23,U),  LIST_END },
				.syntax = INSN_SYNTAX(MACM[R]Z [T3 = ]Smem, Cmem, ACx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xd1,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// U%DD00mmAAAAAAAI11010001
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(20,DD), INSN_FLAG(22,R), INSN_FLAG(23,U),  LIST_END },
				.syntax = INSN_SYNTAX(MPYM[R] [T3 = ]Smem, Cmem, ACx),
			},
			{
				// U%DD01mmAAAAAAAI11010001
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(20,DD), INSN_FLAG(22,R), INSN_FLAG(23,U),  LIST_END },
				.syntax = INSN_SYNTAX(MACM[R] [T3 = ]Smem, Cmem, ACx),
			},
			{
				// U%DD10mmAAAAAAAI11010001
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(20,DD), INSN_FLAG(22,R), INSN_FLAG(23,U),  LIST_END },
				.syntax = INSN_SYNTAX(MASM[R] [T3 = ]Smem, Cmem, ACx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xd2,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// U%DD00SSAAAAAAAI11010010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,SS), INSN_FLAG(20,DD), INSN_FLAG(22,R), INSN_FLAG(23,U),  LIST_END },
				.syntax = INSN_SYNTAX(MACM[R] [T3 = ]Smem, [ACx,] ACy),
			},
			{
				// U%DD01SSAAAAAAAI11010010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,SS), INSN_FLAG(20,DD), INSN_FLAG(22,R), INSN_FLAG(23,U),  LIST_END },
				.syntax = INSN_SYNTAX(MASM[R] [T3 = ]Smem, [ACx,] ACy),
			},
			{
				// U%DD10SSAAAAAAAI11010010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,SS), INSN_FLAG(20,DD), INSN_FLAG(22,R), INSN_FLAG(23,U),  LIST_END },
				.syntax = INSN_SYNTAX(SQAM[R] [T3 = ]Smem, [ACx,] ACy),
			},
			{
				// U%DD11SSAAAAAAAI11010010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,SS), INSN_FLAG(20,DD), INSN_FLAG(22,R), INSN_FLAG(23,U),  LIST_END },
				.syntax = INSN_SYNTAX(SQSM[R] [T3 = ]Smem, [ACx,] ACy),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xd3,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// U%DD00SSAAAAAAAI11010011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,SS), INSN_FLAG(20,DD), INSN_FLAG(22,R), INSN_FLAG(23,U),  LIST_END },
				.syntax = INSN_SYNTAX(MPYM[R] [T3 = ]Smem, [ACx,] ACy),
			},
			{
				// U%DD10xxAAAAAAAI11010011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,R), INSN_FLAG(23,U),  LIST_END },
				.syntax = INSN_SYNTAX(SQRM[R] [T3 = ]Smem, ACx),
			},
			{
				// U%DDu1ssAAAAAAAI11010011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,ss), INSN_FLAG(19,u), INSN_FLAG(20,DD), INSN_FLAG(22,R), INSN_FLAG(23,U),  LIST_END },
				.syntax = INSN_SYNTAX(MPYM[R][U] [T3 = ]Smem, Tx, ACx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xd4,
	.size = 0x03,
	.insn = {
		// U%DDssSSAAAAAAAI11010100
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,SS), INSN_FLAG(18,ss), INSN_FLAG(20,DD), INSN_FLAG(22,R), INSN_FLAG(23,U),  LIST_END },
		.syntax = INSN_SYNTAX(MACM[R] [T3 = ]Smem, Tx, [ACx,] ACy),
	},
},
{
	.byte = 0xd5,
	.size = 0x03,
	.insn = {
		// U%DDssSSAAAAAAAI11010101
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,SS), INSN_FLAG(18,ss), INSN_FLAG(20,DD), INSN_FLAG(22,R), INSN_FLAG(23,U),  LIST_END },
		.syntax = INSN_SYNTAX(MASM[R] [T3 = ]Smem, Tx, [ACx,] ACy),
	},
},
{
	.byte = 0xd6,
	.size = 0x03,
	.insn = {
		// FDDDFSSSAAAAAAAI11010110
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,FSSS), INSN_FLAG(20,FDDD),  LIST_END },
		.syntax = INSN_SYNTAX(ADD Smem, [src,] dst),
	},
},
{
	.byte = 0xd7,
	.size = 0x03,
	.insn = {
		// FDDDFSSSAAAAAAAI11010111
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,FSSS), INSN_FLAG(20,FDDD),  LIST_END },
		.syntax = INSN_SYNTAX(SUB Smem, [src,] dst),
	},
},
{
	.byte = 0xd8,
	.size = 0x03,
	.insn = {
		// FDDDFSSSAAAAAAAI11011000
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,FSSS), INSN_FLAG(20,FDDD),  LIST_END },
		.syntax = INSN_SYNTAX(SUB src, Smem, dst),
	},
},
{
	.byte = 0xd9,
	.size = 0x03,
	.insn = {
		// FDDDFSSSAAAAAAAI11011001
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,FSSS), INSN_FLAG(20,FDDD),  LIST_END },
		.syntax = INSN_SYNTAX(AND Smem, src, dst),
	},
},
{
	.byte = 0xda,
	.size = 0x03,
	.insn = {
		// FDDDFSSSAAAAAAAI11011010
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,FSSS), INSN_FLAG(20,FDDD),  LIST_END },
		.syntax = INSN_SYNTAX(OR Smem, src, dst),
	},
},
{
	.byte = 0xdb,
	.size = 0x03,
	.insn = {
		// FDDDFSSSAAAAAAAI11011011
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,FSSS), INSN_FLAG(20,FDDD),  LIST_END },
		.syntax = INSN_SYNTAX(XOR Smem, src, dst),
	},
},
{
	.byte = 0xdc,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// 0000xx10AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,2), INSN_MASK(20,4,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, DP),
			},
			{
				// 0001xx10AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,2), INSN_MASK(20,4,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, CDP),
			},
			{
				// 0010xx10AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,2), INSN_MASK(20,4,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, BSA01),
			},
			{
				// 0011xx10AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,2), INSN_MASK(20,4,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, BSA23),
			},
			{
				// 0100xx10AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,2), INSN_MASK(20,4,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, BSA45),
			},
			{
				// 0101xx10AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,2), INSN_MASK(20,4,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, BSA67),
			},
			{
				// 0110xx10AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,2), INSN_MASK(20,4,6),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, BSAC),
			},
			{
				// 0111xx10AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,2), INSN_MASK(20,4,7),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, SP),
			},
			{
				// 1000xx10AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,2), INSN_MASK(20,4,8),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, SSP),
			},
			{
				// 1001xx10AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,2), INSN_MASK(20,4,9),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, BK03),
			},
			{
				// 1010xx10AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,2), INSN_MASK(20,4,10),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, BK47),
			},
			{
				// 1011xx10AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,2), INSN_MASK(20,4,11),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, BKC),
			},
			{
				// 1100xx10AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,2), INSN_MASK(20,4,12),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, DPH),
			},
			{
				// 1111xx10AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,2), INSN_MASK(20,4,15),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, PDP),
			},
			{
				// x000xx11AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,3), INSN_MASK(20,3,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, CSR),
			},
			{
				// x001xx11AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,3), INSN_MASK(20,3,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, BRC0),
			},
			{
				// x010xx11AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,3), INSN_MASK(20,3,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, BRC1),
			},
			{
				// x011xx11AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,3), INSN_MASK(20,3,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, TRN0),
			},
			{
				// x100xx11AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,3), INSN_MASK(20,3,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, TRN1),
			},
			{
				// kkkkxx00AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,k4),  LIST_END },
				.syntax = INSN_SYNTAX(BTST k4, Smem, TC1),
			},
			{
				// kkkkxx01AAAAAAAI11011100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,k4),  LIST_END },
				.syntax = INSN_SYNTAX(BTST k4, Smem, TC2),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xdd,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// SSDDss00AAAAAAAI11011101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(18,ss), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(ADD Smem << Tx, [ACx,] ACy),
			},
			{
				// SSDDss01AAAAAAAI11011101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(18,ss), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(SUB Smem << Tx, [ACx,] ACy),
			},
			{
				// SSDDss10AAAAAAAI11011101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(18,ss), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(ADDSUB2CC Smem, ACx, Tx, TC1, TC2, ACy),
			},
			{
				// x%DDss11AAAAAAAI11011101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,2,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(18,ss), INSN_FLAG(20,DD), INSN_FLAG(22,R),  LIST_END },
				.syntax = INSN_SYNTAX(MOV [rnd(]Smem << Tx[)], ACx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xde,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// SSDD0000AAAAAAAI11011110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(ADDSUBCC Smem, ACx, TC1, ACy),
			},
			{
				// SSDD0001AAAAAAAI11011110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(ADDSUBCC Smem, ACx, TC2, ACy),
			},
			{
				// SSDD0010AAAAAAAI11011110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(ADDSUBCC Smem, ACx, TC1, TC2, ACy),
			},
			{
				// SSDD0011AAAAAAAI11011110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(SUBC Smem, [ACx,] ACy),
			},
			{
				// SSDD0100AAAAAAAI11011110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(ADD Smem << #16, [ACx,] ACy),
			},
			{
				// SSDD0101AAAAAAAI11011110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(SUB Smem << #16, [ACx,] ACy),
			},
			{
				// SSDD0110AAAAAAAI11011110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,6),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(SUB ACx, Smem << #16, ACy),
			},
			{
				// ssDD1000AAAAAAAI11011110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,8),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,ss),  LIST_END },
				.syntax = INSN_SYNTAX(ADDSUB Tx, Smem, ACx),
			},
			{
				// ssDD1001AAAAAAAI11011110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,9),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,ss),  LIST_END },
				.syntax = INSN_SYNTAX(SUBADD Tx, Smem, ACx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xdf,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// FDDD000uAAAAAAAI11011111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,u), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV [uns(]high_byte(Smem)[)], dst),
			},
			{
				// FDDD001uAAAAAAAI11011111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,u), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV [uns(]low_byte(Smem)[)], dst),
			},
			{
				// xxDD010uAAAAAAAI11011111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,u), INSN_FLAG(20,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV [uns(]Smem[)], ACx),
			},
			{
				// SSDD100uAAAAAAAI11011111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,u), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(ADD [uns(]Smem[)], CARRY, [ACx,] ACy),
			},
			{
				// SSDD101uAAAAAAAI11011111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,u), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(SUB [uns(]Smem[)], BORROW, [ACx,] ACy),
			},
			{
				// SSDD110uAAAAAAAI11011111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,6),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,u), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(ADD [uns(]Smem[)], [ACx,] ACy),
			},
			{
				// SSDD111uAAAAAAAI11011111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,7),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,u), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(SUB [uns(]Smem[)], [ACx,] ACy),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xe0,
	.size = 0x03,
	.insn = {
		// FSSSxxxtAAAAAAAI11100000
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,t), INSN_FLAG(20,FSSS),  LIST_END },
		.syntax = INSN_SYNTAX(BTST src, Smem, TCx),
	},
},
{
	.byte = 0xe1,
	.size = 0x03,
	.insn = {
		// DDSHIFTWAAAAAAAI11100001
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,SHIFTW), INSN_FLAG(22,DD),  LIST_END },
		.syntax = INSN_SYNTAX(MOV low_byte(Smem) << #SHIFTW, ACx),
	},
},
{
	.byte = 0xe2,
	.size = 0x03,
	.insn = {
		// DDSHIFTWAAAAAAAI11100010
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,SHIFTW), INSN_FLAG(22,DD),  LIST_END },
		.syntax = INSN_SYNTAX(MOV high_byte(Smem) << #SHIFTW, ACx),
	},
},
{
	.byte = 0xe3,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// FSSS1100AAAAAAAI11100011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,12),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(BSET src, Smem),
			},
			{
				// FSSS1101AAAAAAAI11100011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,13),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(BCLR src, Smem),
			},
			{
				// kkkk000xAAAAAAAI11100011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,k4),  LIST_END },
				.syntax = INSN_SYNTAX(BTSTSET k4, Smem, TC1),
			},
			{
				// kkkk001xAAAAAAAI11100011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,k4),  LIST_END },
				.syntax = INSN_SYNTAX(BTSTSET k4, Smem, TC2),
			},
			{
				// kkkk010xAAAAAAAI11100011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,k4),  LIST_END },
				.syntax = INSN_SYNTAX(BTSTCLR k4, Smem, TC1),
			},
			{
				// kkkk011xAAAAAAAI11100011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,k4),  LIST_END },
				.syntax = INSN_SYNTAX(BTSTCLR k4, Smem, TC2),
			},
			{
				// kkkk100xAAAAAAAI11100011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,k4),  LIST_END },
				.syntax = INSN_SYNTAX(BTSTNOT k4, Smem, TC1),
			},
			{
				// kkkk101xAAAAAAAI11100011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,k4),  LIST_END },
				.syntax = INSN_SYNTAX(BTSTNOT k4, Smem, TC2),
			},
			{
				// FSSS111xAAAAAAAI11100011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,7),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(BNOT src, Smem),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xe4,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// FSSSx0xxAAAAAAAI11100100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(PSH src,Smem),
			},
			{
				// FDDDx1xxAAAAAAAI11100100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(POP dst, Smem),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xe5,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// 000010xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV DP, Smem),
			},
			{
				// 000110xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,6),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV CDP, Smem),
			},
			{
				// 001010xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,10),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV BSA01, Smem),
			},
			{
				// 001110xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,14),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV BSA23, Smem),
			},
			{
				// 010010xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,18),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV BSA45, Smem),
			},
			{
				// 010110xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,22),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV BSA67, Smem),
			},
			{
				// 011010xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,26),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV BSAC, Smem),
			},
			{
				// 011110xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,30),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV SP, Smem),
			},
			{
				// 100010xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,34),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV SSP, Smem),
			},
			{
				// 100110xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,38),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV BK03, Smem),
			},
			{
				// 101010xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,42),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV BK47, Smem),
			},
			{
				// 101110xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,46),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV BKC, Smem),
			},
			{
				// 110010xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,50),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV DPH, Smem),
			},
			{
				// 111110xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,62),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV PDP, Smem),
			},
			{
				// x00011xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,5,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV CSR, Smem),
			},
			{
				// x00111xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,5,7),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV BRC0, Smem),
			},
			{
				// x01011xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,5,11),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV BRC1, Smem),
			},
			{
				// x01111xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,5,15),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV TRN0, Smem),
			},
			{
				// x10011xxAAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,5,19),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV TRN1, Smem),
			},
			{
				// FSSS01x0AAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,1,0), INSN_MASK(18,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV src, high_byte(Smem)),
			},
			{
				// FSSS01x1AAAAAAAI11100101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,1,1), INSN_MASK(18,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV src, low_byte(Smem)),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xe6,
	.size = 0x03,
	.insn = {
		// KKKKKKKKAAAAAAAI11100110
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,K8),  LIST_END },
		.syntax = INSN_SYNTAX(MOV K8, Smem),
	},
},
{
	.byte = 0xe7,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// SSss00xxAAAAAAAI11100111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,ss), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV ACx << Tx, Smem),
			},
			{
				// SSss10x%AAAAAAAI11100111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,R), INSN_FLAG(20,ss), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV [rnd(]HI(ACx << Tx)[)], Smem),
			},
			{
				// SSss11u%AAAAAAAI11100111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,R), INSN_FLAG(17,u), INSN_FLAG(20,ss), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV [uns(] [rnd(]HI[(saturate](ACx << Tx)[)))], Smem),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xe8,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// SSxxx0x%AAAAAAAI11101000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,R), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV [rnd(]HI(ACx)[)], Smem),
			},
			{
				// SSxxx1u%AAAAAAAI11101000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,R), INSN_FLAG(17,u), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV [uns(] [rnd(]HI[(saturate](ACx)[)))], Smem),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xe9,
	.size = 0x03,
	.insn = {
		// SSSHIFTWAAAAAAAI11101001
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,SHIFTW), INSN_FLAG(22,SS),  LIST_END },
		.syntax = INSN_SYNTAX(MOV ACx << #SHIFTW, Smem),
	},
},
{
	.byte = 0xea,
	.size = 0x03,
	.insn = {
		// SSSHIFTWAAAAAAAI11101010
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,SHIFTW), INSN_FLAG(22,SS),  LIST_END },
		.syntax = INSN_SYNTAX(MOV HI(ACx << #SHIFTW), Smem),
	},
},
{
	.byte = 0xeb,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// FSSS1100AAAAAAAI11101011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,12),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV pair(TAx), dbl(Lmem)),
			},
			{
				// xxSS1101AAAAAAAI11101011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,13),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV ACx >> #1, dual(Lmem)),
			},
			{
				// xxSS10x0AAAAAAAI11101011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,1,0), INSN_MASK(18,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV ACx, dbl(Lmem)),
			},
			{
				// xxSS10u1AAAAAAAI11101011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,1,1), INSN_MASK(18,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(17,u), INSN_FLAG(20,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV [uns(]saturate(ACx)[)], dbl(Lmem)),
			},
			{
				// xxxx01xxAAAAAAAI11101011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV RETA, dbl(Lmem)),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xec,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// XDDD1110AAAAAAAI11101100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,14),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,XDDD),  LIST_END },
				.syntax = INSN_SYNTAX(AMAR Smem, XAdst),
			},
			{
				// FSSS000xAAAAAAAI11101100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(BSET Baddr, src),
			},
			{
				// FSSS001xAAAAAAAI11101100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(BCLR Baddr, src),
			},
			{
				// FSSS010xAAAAAAAI11101100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(BTSTP Baddr, src),
			},
			{
				// FSSS011xAAAAAAAI11101100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(BNOT Baddr, src),
			},
			{
				// FSSS100tAAAAAAAI11101100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,t), INSN_FLAG(20,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(BTST Baddr, src, TCx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xed,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// 00DD1010AAAAAAAI11101101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,10), INSN_MASK(22,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV dbl(Lmem), pair(HI(ACx))),
			},
			{
				// 00DD1100AAAAAAAI11101101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,12), INSN_MASK(22,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV dbl(Lmem), pair(LO(ACx))),
			},
			{
				// 00SS1110AAAAAAAI11101101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,14), INSN_MASK(22,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV pair(HI(ACx)), dbl(Lmem)),
			},
			{
				// 00SS1111AAAAAAAI11101101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,15), INSN_MASK(22,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV pair(LO(ACx)), dbl(Lmem)),
			},
			{
				// XDDD1111AAAAAAAI11101101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,15),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,XDDD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV dbl(Lmem), XAdst),
			},
			{
				// XSSS0101AAAAAAAI11101101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,XSSS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV XAsrc, dbl(Lmem)),
			},
			{
				// SSDD000nAAAAAAAI11101101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(ADD dbl(Lmem), [ACx,] ACy),
			},
			{
				// SSDD001nAAAAAAAI11101101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(SUB dbl(Lmem), [ACx,] ACy),
			},
			{
				// SSDD010xAAAAAAAI11101101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(SUB ACx, dbl(Lmem), ACy),
			},
			{
				// xxxx011xAAAAAAAI11101101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV dbl(Lmem), RETA),
			},
			{
				// xxDD100gAAAAAAAI11101101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,g), INSN_FLAG(20,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV[40] dbl(Lmem), ACx),
			},
			{
				// FDDD111xAAAAAAAI11101101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,7),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV dbl(Lmem), pair(TAx)),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xee,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// SSDD000xAAAAAAAI11101110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(ADD dual(Lmem), [ACx,] ACy),
			},
			{
				// SSDD001xAAAAAAAI11101110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(SUB dual(Lmem), [ACx,] ACy),
			},
			{
				// SSDD010xAAAAAAAI11101110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,SS),  LIST_END },
				.syntax = INSN_SYNTAX(SUB ACx, dual(Lmem), ACy),
			},
			{
				// ssDD011xAAAAAAAI11101110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,ss),  LIST_END },
				.syntax = INSN_SYNTAX(SUB dual(Lmem), Tx, ACx),
			},
			{
				// ssDD100xAAAAAAAI11101110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,ss),  LIST_END },
				.syntax = INSN_SYNTAX(ADD dual(Lmem), Tx, ACx),
			},
			{
				// ssDD101xAAAAAAAI11101110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,ss),  LIST_END },
				.syntax = INSN_SYNTAX(SUB Tx, dual(Lmem), ACx),
			},
			{
				// ssDD110xAAAAAAAI11101110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,6),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,ss),  LIST_END },
				.syntax = INSN_SYNTAX(ADDSUB Tx, dual(Lmem), ACx),
			},
			{
				// ssDD111xAAAAAAAI11101110
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(17,3,7),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,DD), INSN_FLAG(22,ss),  LIST_END },
				.syntax = INSN_SYNTAX(SUBADD Tx, dual(Lmem), ACx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xef,
	.size = 0x03,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// xxxx00mmAAAAAAAI11101111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Cmem, Smem),
			},
			{
				// xxxx01mmAAAAAAAI11101111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Smem, Cmem),
			},
			{
				// xxxx10mmAAAAAAAI11101111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm),  LIST_END },
				.syntax = INSN_SYNTAX(MOV Cmem,dbl(Lmem)),
			},
			{
				// xxxx11mmAAAAAAAI11101111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm),  LIST_END },
				.syntax = INSN_SYNTAX(MOV dbl(Lmem), Cmem),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xf0,
	.size = 0x04,
	.insn = {
		// KKKKKKKKKKKKKKKKAAAAAAAI11110000
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,K16),  LIST_END },
		.syntax = INSN_SYNTAX(CMP Smem == K16, TC1),
	},
},
{
	.byte = 0xf1,
	.size = 0x04,
	.insn = {
		// KKKKKKKKKKKKKKKKAAAAAAAI11110001
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,K16),  LIST_END },
		.syntax = INSN_SYNTAX(CMP Smem == K16, TC2),
	},
},
{
	.byte = 0xf2,
	.size = 0x04,
	.insn = {
		// kkkkkkkkkkkkkkkkAAAAAAAI11110010
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,k16),  LIST_END },
		.syntax = INSN_SYNTAX(BAND Smem, k16, TC1),
	},
},
{
	.byte = 0xf3,
	.size = 0x04,
	.insn = {
		// kkkkkkkkkkkkkkkkAAAAAAAI11110011
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,k16),  LIST_END },
		.syntax = INSN_SYNTAX(BAND Smem, k16, TC2),
	},
},
{
	.byte = 0xf4,
	.size = 0x04,
	.insn = {
		// kkkkkkkkkkkkkkkkAAAAAAAI11110100
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,k16),  LIST_END },
		.syntax = INSN_SYNTAX(AND k16, Smem),
	},
},
{
	.byte = 0xf5,
	.size = 0x04,
	.insn = {
		// kkkkkkkkkkkkkkkkAAAAAAAI11110101
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,k16),  LIST_END },
		.syntax = INSN_SYNTAX(OR k16, Smem),
	},
},
{
	.byte = 0xf6,
	.size = 0x04,
	.insn = {
		// kkkkkkkkkkkkkkkkAAAAAAAI11110110
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,k16),  LIST_END },
		.syntax = INSN_SYNTAX(XOR k16, Smem),
	},
},
{
	.byte = 0xf7,
	.size = 0x04,
	.insn = {
		// KKKKKKKKKKKKKKKKAAAAAAAI11110111
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,K16),  LIST_END },
		.syntax = INSN_SYNTAX(ADD K16, Smem),
	},
},
{
	.byte = 0xf8,
	.size = 0x04,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// xxDDx0U%KKKKKKKKAAAAAAAI11111000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(26,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,K8), INSN_FLAG(24,R), INSN_FLAG(25,U), INSN_FLAG(28,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MPYMK[R] [T3 = ]Smem, K8, ACx),
			},
			{
				// SSDDx1U%KKKKKKKKAAAAAAAI11111000
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(26,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,K8), INSN_FLAG(24,R), INSN_FLAG(25,U), INSN_FLAG(28,DD), INSN_FLAG(30,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MACMK[R] [T3 = ]Smem, K8, [ACx,] ACy),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xf9,
	.size = 0x04,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// SSDD00xxuxSHIFTWAAAAAAAI11111001
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(26,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,SHIFTW), INSN_FLAG(23,u), INSN_FLAG(28,DD), INSN_FLAG(30,SS),  LIST_END },
				.syntax = INSN_SYNTAX(ADD [uns(]Smem[)] << #SHIFTW, [ACx,] ACy),
			},
			{
				// SSDD01xxuxSHIFTWAAAAAAAI11111001
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(26,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,SHIFTW), INSN_FLAG(23,u), INSN_FLAG(28,DD), INSN_FLAG(30,SS),  LIST_END },
				.syntax = INSN_SYNTAX(SUB [uns(]Smem[)] << #SHIFTW, [ACx,] ACy),
			},
			{
				// xxDD10xxuxSHIFTWAAAAAAAI11111001
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(26,2,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,SHIFTW), INSN_FLAG(23,u), INSN_FLAG(28,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MOV [uns(]Smem[)] << #SHIFTW, ACx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xfa,
	.size = 0x04,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// SSxxx0x%xxSHIFTWAAAAAAAI11111010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(26,1,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,SHIFTW), INSN_FLAG(24,R), INSN_FLAG(30,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV [rnd(]HI(ACx << #SHIFTW)[)], Smem),
			},
			{
				// SSxxx1x%uxSHIFTWAAAAAAAI11111010
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(26,1,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,SHIFTW), INSN_FLAG(23,u), INSN_FLAG(24,R), INSN_FLAG(30,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV [uns(] [rnd(]HI[(saturate](ACx << #SHIFTW)[)))], Smem),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
{
	.byte = 0xfb,
	.size = 0x04,
	.insn = {
		// KKKKKKKKKKKKKKKKAAAAAAAI11111011
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,K16),  LIST_END },
		.syntax = INSN_SYNTAX(MOV K16, Smem),
	},
},
{
	.byte = 0xfc,
	.size = 0x04,
	.insn = {
		// LLLLLLLLLLLLLLLLAAAAAAAI11111100
		.i_list = NULL,
		.m_list = NULL,
		.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,L16),  LIST_END },
		.syntax = INSN_SYNTAX(BCC L16, ARn_mod ! = #0),
	},
},
{
	.byte = 0xfd,
	.size = 0x04,
	.insn = {
		.i_list = (insn_item_t []) {
			{
				// DDDDuug%000000mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MPY[R][40] [uns(]Smem[)], [uns(]HI(Cmem)[)], ACy :: MPY[R][40] [uns(]Smem[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%000001mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MPY[R][40] [uns(]Smem[)], [uns(]HI(Cmem)[)], ACy :: MAC[R][40] [uns(]Smem[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%000010mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,2),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]Smem[)], [uns(]HI(Cmem)[)], ACy :: MPY[R][40] [uns(]Smem[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%000011mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,3),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MPY[R][40] [uns(]Smem[)], [uns(]HI(Cmem)[)], ACy :: MAS[R][40] [uns(]Smem[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%000100mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,4),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAS[R][40] [uns(]Smem[)], [uns(]HI(Cmem)[)], ACy :: MPY[R][40] [uns(]Smem[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%000101mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,5),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]Smem[)], [uns(]HI(Cmem)[)], ACy :: MAC[R][40] [uns(]Smem[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%000110mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,6),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]Smem[)], [uns(]HI(Cmem)[)], ACy :: MAS[R][40] [uns(]Smem[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%000111mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,7),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAS[R][40] [uns(]Smem[)], [uns(]HI(Cmem)[)], ACy :: MAC[R][40] [uns(]Smem[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%001000mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,8),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]Smem[)], [uns(]HI(Cmem)[)], ACy :: MAC[R][40] [uns(]Smem[)], [uns(]LO(Cmem)[)], ACx>>#16),
			},
			{
				// DDDDuug%001001mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,9),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]Smem[)], [uns(]HI(Cmem)[)], ACy>>#16 :: MAS[R][40] [uns(]Smem[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%001010mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,10),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]Smem[)], [uns(]HI(Cmem)[)], ACy>>#16 :: MPY[R][40] [uns(]Smem[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%001011mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,11),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]Smem[)], [uns(]HI(Cmem)[)], ACy>>#16 :: MAC[R][40] [uns(]Smem[)], [uns(]LO(Cmem)[)], ACx>>#16),
			},
			{
				// DDDDuug%001100mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,12),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAS[R][40] [uns(]Smem[)], [uns(]HI(Cmem)[)], ACy :: MAS[R][40] [uns(]Smem[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%010000mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,16),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MPY[R][40] [uns(]HI(Lmem)[)], [uns(]HI(Cmem)[)], ACy :: MPY[R][40] [uns(]LO(Lmem)[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%010001mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,17),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MPY[R][40] [uns(]HI(Lmem)[)], [uns(]HI(Cmem)[)], ACy :: MAC[R][40] [uns(]LO(Lmem)[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%010010mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,18),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]HI(Lmem)[)], [uns(]HI(Cmem)[)], ACy :: MPY[R][40] [uns(]LO(Lmem)[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%010011mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,19),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MPY[R][40] [uns(]HI(Lmem)[)], [uns(]HI(Cmem)[)], ACy :: MAS[R][40] [uns(]LO(Lmem)[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%010100mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,20),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAS[R][40] [uns(]HI(Lmem)[)], [uns(]HI(Cmem)[)], ACy :: MPY[R][40] [uns(]LO(Lmem)[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%010101mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,21),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]HI(Lmem)[)], [uns(]HI(Cmem)[)], ACy :: MAC[R][40] [uns(]LO(Lmem)[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%010110mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,22),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]HI(Lmem)[)], [uns(]HI(Cmem)[)], ACy :: MAS[R][40] [uns(]LO(Lmem)[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%010111mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,23),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAS[R][40] [uns(]HI(Lmem)[)], [uns(]HI(Cmem)[)], ACy :: MAC[R][40] [uns(]LO(Lmem)[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%011000mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,24),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]HI(Lmem)[)], [uns(]HI(Cmem)[)], ACy :: MAC[R][40] [uns(]LO(Lmem)[)], [uns(]LO(Cmem)[)], ACx>>#16),
			},
			{
				// DDDDuug%011001mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,25),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]HI(Lmem)[)], [uns(]HI(Cmem)[)], ACy>>#16 :: MAS[R][40] [uns(]LO(Lmem)[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%011010mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,26),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]HI(Lmem)[)], [uns(]HI(Cmem)[)], ACy>>#16 :: MPY[R][40] [uns(]LO(Lmem)[)], [uns(]LO(Cmem)[)], ACx),
			},
			{
				// DDDDuug%011011mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,27),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAC[R][40] [uns(]HI(Lmem)[)], [uns(]HI(Cmem)[)], ACy>>#16 :: MAC[R][40] [uns(]LO(Lmem)[)], [uns(]LO(Cmem)[)], ACx>>#16),
			},
			{
				// DDDDuug%011100mmAAAAAAAI11111101
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,6,28),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(16,mm), INSN_FLAG(24,R), INSN_FLAG(25,g), INSN_FLAG(26,uu), INSN_FLAG(28,DD), INSN_FLAG(30,DD),  LIST_END },
				.syntax = INSN_SYNTAX(MAS[R][40] [uns(]HI(Lmem)[)], [uns(]HI(Cmem)[)], ACy :: MAS[R][40] [uns(]LO(Lmem)[)], [uns(]LO(Cmem)[)], ACx),
			},
			LIST_END,
		},
		.m_list = NULL,
		.f_list = NULL,
		.syntax = NULL,
	},
},
