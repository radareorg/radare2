{
	.byte = 0x48,
	.size = 0x02,
	.insn = {
		// xxxxx10001001000
		.i_list = NULL,
		.m_list = (insn_mask_t []) { INSN_MASK(8,3,4),  LIST_END },
		.f_list = NULL,
		.syntax = INSN_SYNTAX(RETI),
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
				// 01100001YMMMSSDDXXXMMMYY10000111
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(24,8,97),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,YY), INSN_FLAG(10,MMM), INSN_FLAG(13,XXX), INSN_FLAG(16,DD), INSN_FLAG(18,SS), INSN_FLAG(20,MMM), INSN_FLAG(23,Y),  LIST_END },
				.syntax = INSN_SYNTAX(LMSF Xmem, Ymem, ACx, ACy),
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
				// xxxx01xxAAAAAAAI11101011
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(18,2,1),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI),  LIST_END },
				.syntax = INSN_SYNTAX(MOV RETA, dbl(Lmem)),
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
			{
				// XDDD1110AAAAAAAI11101100
				.i_list = NULL,
				.m_list = (insn_mask_t []) { INSN_MASK(16,4,14),  LIST_END },
				.f_list = (insn_flag_t []) { INSN_FLAG(8,AAAAAAAI), INSN_FLAG(20,XDDD),  LIST_END },
				.syntax = INSN_SYNTAX(AMAR Smem, XAdst),
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
