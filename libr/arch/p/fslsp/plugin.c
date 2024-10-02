/* radare - LGPL3 - Copyright 2023 - eibachd, pancake */

/*
 * QorIQ platform's trust architecture 3.0 Service processor (SP) provides
 * pre-boot initialization and secure-boot capabilities
 *
 * PBI (Pre-Boot Initialization) Command Summary
 *
 * Command 						| Number | Size(bytes) | Description
 * ### Configuration Write Commands
 * CCSR Write 						-		8 			32-byte write to a CCSR register
 * Alternate Configuration Write	-		variable	variable size write to offset from current value of ALTCFG_BAR
 * ### Block Copy Commands
 * Block Copy						0x00	16			Copy data from any of the available memory interfaces to a RAM
 * CCSR Write from Address			0x02				Update large number of CCSR register consecutively from random accessible memory(OCRAM, SPRAM).
 * ### Special Load commands
 * Load RCW with Checksum			0x10	136			Read Reset Configuration Word, perform simple 32-bit checksum, and update RCW registers
 * Load RCW w/o Checksum			0x11	136			Read Reset Configuration Word and update RCW registers without performing checksum
 * Load Alternate Config Window		0x12	4			Read in condition 14-bit base pointer for alternate configuration space
 * Load Condition 					0x14	12			Read in condition information for subsequent Conditional Jump
 * Load Security Header				0x20	84			Read CSF Header for authentication of PBI Image
 * Load Boot 1 CSF Header Ptr		0x22	8			Read in a pointer to CSF header for authentication of Boot 1 code
 * CCSR Read, Modify and Write		0x42				Reads a CCSR register and changes (SET/CLEAR ) its bits as per mask specified in the command
 * ### Control Commands
 * Poll Short						0x80	16			Poll a specified address for a specified address for a specified value
 * Poll Long						0x81
 * Wait								0x82	4			Pause PBI sequence for specified number of iteration of a FOR loop
 * Jump								0x84	8			Unconditional jump forward in PBI command sequence
 * Jump Conditional					0x85	12			Conditional jump forward in PBI boot sequence
 * CRC and Stop						0x8F	8			Stop the PBI sequence and indicate the expected CRC value
 * Stop								0xFF	8			Stop the PBI sequence
 */

#include <r_arch.h>

static bool fslsp_ancmd(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	RStrBuf *buf_asm = NULL;
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (s->config);
	const bool disasm = mask & R_ARCH_OP_MASK_DISASM;
	ut8 cmd = (r_read_ble32 (op->bytes, be) >> 16) & 0xff;

	switch (cmd) {
	case 0x00:
		if (disasm)
			buf_asm = r_strbuf_newf ("Block Copy src 0x%x, from 0x%x, to 0x%x, size 0x%x",
				r_read_ble32 (op->bytes, be) & 0xffff,
				r_read_ble32 (op->bytes + 4, be),
				r_read_ble32 (op->bytes + 8, be),
				r_read_ble32 (op->bytes + 12, be));
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 16;
		break;

	case 0x02:
		if (disasm)
			buf_asm = r_strbuf_newf ("CCSR Write from Address word type %d, from 0x%x, to 0x%x, size 0x%x",
				r_read_ble32 (op->bytes, be) & 3,
				r_read_ble32 (op->bytes + 4, be),
				r_read_ble32 (op->bytes + 8, be),
				r_read_ble32 (op->bytes + 12, be));
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 16;
		break;

	case 0x10:
		if (disasm)
			buf_asm = r_strbuf_new ("Load RCW with Checksum");
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 136;
		break;

	case 0x11:
		if (disasm)
			buf_asm = r_strbuf_new ("Load RCW w/o Checksum");
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 136;
		break;

	case 0x12:
		if (disasm)
			buf_asm = r_strbuf_newf ("Load Alternate Config Window %d",
				(r_read_ble32 (op->bytes, be) >> 1) & 0x3fff);
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 4;
		break;

	case 0x14:
		if (disasm)
			buf_asm = r_strbuf_newf ("Load Condition from 0x%x, mask 0x%x",
				r_read_ble32 (op->bytes + 4, be),
				r_read_ble32 (op->bytes + 8, be));
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 12;
		break;

	case 0x20:
		if (disasm)
			buf_asm = r_strbuf_new ("Load Security Header");
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 84;
		break;

	case 0x22:
		if (disasm)
			buf_asm = r_strbuf_newf ("Load Boot 1 CSF Header Ptr %08x",
				r_read_ble32 (op->bytes + 4, be));
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 8;
		break;

	case 0x42:
		if (disasm)
			buf_asm = r_strbuf_newf ("CCSR Read, Modify and Write from Address ops type %d, mask type %d, CCSR 0x%x, mask 0x%x, data 0x%x",
				(r_read_ble32 (op->bytes, be) >> 2) & 3,
				r_read_ble32 (op->bytes, be) & 3,
				r_read_ble32 (op->bytes + 4, be),
				r_read_ble32 (op->bytes + 8, be),
				r_read_ble32 (op->bytes + 12, be));
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 16;
		break;

	case 0x80:
	case 0x81:
		if (disasm)
			buf_asm = r_strbuf_newf ("Poll %s addr 0x%x, mask 0x%x, condition 0x%x",
				(cmd == 0x80)? "Short": "Long",
				r_read_ble32 (op->bytes + 4, be),
				r_read_ble32 (op->bytes + 8, be),
				r_read_ble32 (op->bytes + 12, be));
		op->type = R_ANAL_OP_TYPE_NOP;
		op->size = 16;
		break;

	case 0x82:
		if (disasm)
			buf_asm = r_strbuf_newf ("Wait %d cycles",
				r_read_ble32 (op->bytes, be) & 0xffff);
		op->type = R_ANAL_OP_TYPE_NOP;
		op->size = 4;
		break;

	case 0x84:
		if (disasm)
			buf_asm = r_strbuf_newf ("Jump offset 0x%x",
				r_read_ble32 (op->bytes + 4, be));
		op->type = R_ANAL_OP_TYPE_JMP;
		op->size = 8;
		op->jump = r_read_ble32 (op->bytes + 4, be);
		break;

	case 0x85:
		if (disasm)
			buf_asm = r_strbuf_newf ("Jump Conditional offset 0x%x, condition %x",
				r_read_ble32 (op->bytes + 4, be),
				r_read_ble32 (op->bytes + 8, be));
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = 12;
		op->jump = r_read_ble32 (op->bytes + 4, be);
		break;

	case 0x8F:
		if (disasm)
			buf_asm = r_strbuf_newf ("CRC and Stop crc 0x%x",
				r_read_ble32 (op->bytes + 4, be));
		op->type = R_ANAL_OP_TYPE_TRAP;
		op->size = 8;
		op->jump = r_read_ble32 (op->bytes + 4, be);
		break;

	case 0xFF:
		if (disasm)
			buf_asm = r_strbuf_new ("Stop");
		op->type = R_ANAL_OP_TYPE_TRAP;
		op->size = 8;
		break;

	default:
		return false;
	}

	op->nopcode = 2;

	if (buf_asm) {
		if (disasm) {
			op->mnemonic = r_strbuf_drain (buf_asm);
		} else {
			r_warn_if_reached ();
			r_strbuf_free (buf_asm);
		}
	}

	return true;
}

static bool fslsp_anop(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	RStrBuf *buf_asm = NULL;
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (s->config);
	const bool disasm = mask & R_ARCH_OP_MASK_DISASM;
	ut32 word = r_read_ble32 (op->bytes, be);
	ut8 header = word >> 24;

	if (header == 0x80) {
		return fslsp_ancmd (s, op, mask);
	} else if ((header & 0xc0) == 0) {
		if (disasm) {
			ut8 len = (header >> 4) & 0x03;
			ut32 mask;
			switch (len) {
			case 1:
				mask = 0x000000ff;
				break;
			case 3:
				mask = 0xffffffff;
				break;
			default:
				return false;
			}
			buf_asm = r_strbuf_newf ("CCSR Write sys_addr 0x%07x, data 0x%x",
				word & 0xfffffff,
				r_read_ble32 (op->bytes + 4, be) & mask);
		}
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 8;
	} else if (((header & 0xc0) == 0x80) && (header & 0x3c)) {
		if (disasm)
			buf_asm = r_strbuf_new ("Alternate Configuration Write");
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 8;
	} else {
		return false;
	}

	if (buf_asm) {
		if (disasm) {
			op->mnemonic = r_strbuf_drain (buf_asm);
		} else {
			r_warn_if_reached ();
			r_strbuf_free (buf_asm);
		}
	}
	return true;
}

const RArchPlugin r_arch_plugin_fslsp = {
	.meta = {
		.name = "fslsp",
		.author = "eibachd",
		.desc = "Freescale QorIQ service processor analysis plugin",
		.license = "LGPL3",
	},
	.arch = "fslsp",
	.bits = R_SYS_BITS_PACK1 (32),
	.decode = &fslsp_anop,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_anal_plugin_fslsp,
	.version = R2_VERSION
};
#endif
