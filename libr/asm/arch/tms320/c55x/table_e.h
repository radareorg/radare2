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
				.syntax = INSN_SYNTAX(BCNT ACx, ACy,TCx, Tx),
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
				// FDDDxuxtFSSScc000001001E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(8,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(10,cc), INSN_FLAG(12,FSSS), INSN_FLAG(16,t), INSN_FLAG(18,u), INSN_FLAG(20,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(CMP[U] src RELOP dst, TCx),
			},
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
		.syntax = INSN_SYNTAX(MOV –k4, dst),
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
				// 00SSFDDD0100010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(14,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD), INSN_FLAG(12,SS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV HI(ACx), TAx),
			},
			{
				// 01x0FDDD0100010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(12,1,0), INSN_MASK(14,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(SFTS dst, #−1),
			},
			{
				// 01x1FDDD0100010E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(12,1,1), INSN_MASK(14,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,FDDD),  LIST_END },
				.syntax = INSN_SYNTAX(SFTS dst, #1),
			},
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
		.syntax = INSN_SYNTAX(AADD K8,SP),
	},
},
{
	.byte = 0x50,
	.size = 0x02,
	.insn = {
		.i_list = (insn_item_t []) {
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
				.syntax = INSN_SYNTAX(SFTL dst, #−1),
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
				// FSSS00DD0101001E
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(10,2,0),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(0,E), INSN_FLAG(8,DD), INSN_FLAG(12,FSSS),  LIST_END },
				.syntax = INSN_SYNTAX(MOV TAx, HI(ACx)),
			},
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
