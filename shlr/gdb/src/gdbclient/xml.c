/* libgdbr - LGPL - Copyright 2017 - srimanta.barua1 */

#include "gdbclient/xml.h"
#include "gdbclient/core.h"
#include "arch.h"
#include "gdbr_common.h"
#include "packet.h"
#include <r_util.h>

static char *gdbr_read_feature(libgdbr_t *g, const char *file, ut64 *tot_len);
static int gdbr_parse_target_xml(libgdbr_t *g, char *xml_data, ut64 len);

// If xml target description is supported, read it
int gdbr_read_target_xml(libgdbr_t *g) {
	if (!g->stub_features.qXfer_features_read) {
		return -1;
	}
	char *data;
	ut64 len;
	if (!(data = gdbr_read_feature (g, "target.xml", &len))) {
		return -1;
	}
	gdbr_parse_target_xml (g, data, len);
	free (data);
	return 0;
}

static char *gdbr_read_feature(libgdbr_t *g, const char *file, ut64 *tot_len) {
	ut64 retlen = 0, retmax = 0, off = 0, len = g->stub_features.pkt_sz - 2,
	     blksz = g->data_max, subret_space = 0, subret_len = 0;
	char *tmp, *tmp2, *tmp3, *ret = NULL, *subret = NULL, msg[128] = { 0 },
	     status, tmpchar;
	while (1) {
		snprintf (msg, sizeof (msg), "qXfer:features:read:%s:%"PFMT64x
			",%"PFMT64x, file, off, len);
		if (send_msg (g, msg) < 0
		    || read_packet (g) < 0 || send_ack (g) < 0) {
			free (ret);
			*tot_len = 0;
			return NULL;
		}
		if (g->data_len == 0) {
			free (ret);
			*tot_len = 0;
			return NULL;
		}
		if (g->data_len == 1 && g->data[0] == 'l') {
			break;
		}
		status = g->data[0];
		if (retmax - retlen < g->data_len) {
			if (!(tmp = realloc (ret, retmax + blksz))) {
				free (ret);
				*tot_len = 0;
				return NULL;
			}
			retmax += blksz;
			ret = tmp;
		}
		strcpy (ret + retlen, g->data + 1);
		retlen += g->data_len - 1;
		off = retlen;
		if (status == 'l') {
			break;
		}
		if (status != 'm') {
			free (ret);
			*tot_len = 0;
			return NULL;
		}
	}
	if (!ret) {
		*tot_len = 0;
		return NULL;
	}
	tmp = strstr (ret, "<xi:include");
	while (tmp) {
		// inclusion
		if (!(tmp2 = strstr (tmp, "/>"))) {
			free (ret);
			*tot_len = 0;
			return NULL;
		}
		subret_space = tmp2 + 2 - tmp;
		if (!(tmp2 = strstr (tmp, "href="))) {
			free (ret);
			*tot_len = 0;
			return NULL;
		}
		tmp2 += 6;
		if (!(tmp3 = strchr (tmp2, '"'))) {
			free (ret);
			*tot_len = 0;
			return NULL;
		}
		tmpchar = *tmp3;
		*tmp3 = '\0';
		subret = gdbr_read_feature (g, tmp2, &subret_len);
		*tmp3 = tmpchar;
		if (subret) {
			if (subret_len <= subret_space) {
				memcpy (tmp, subret, subret_len);
				memcpy (tmp + subret_len, tmp + subret_space,
					retlen - (tmp + subret_space - ret));
				retlen -= subret_space - subret_len;
				ret[retlen] = '\0';
				tmp = strstr (tmp3, "<xi:include");
				continue;
			}
			if (subret_len > retmax - retlen - 1) {
				tmp3 = NULL;
				if (!(tmp3 = realloc (ret, retmax + subret_len))) {
					free (ret);
					free (subret);
					*tot_len = 0;
					return NULL;
				}
				tmp = tmp3 + (tmp - ret);
				ret = tmp3;
				retmax += subret_len + 1;
			}
			memmove (tmp + subret_len, tmp + subret_space,
				retlen - (tmp + subret_space - ret));
			memcpy (tmp, subret, subret_len);
			retlen += subret_len - subret_space;
			ret[retlen] = '\0';
			free (subret);
		}
		tmp = strstr (tmp3, "<xi:include");
	}
	*tot_len = retlen;
	return ret;
}

// NOTE:
typedef struct {
	char type[32];
	struct {
		char name[32];
		ut32 bit_num;
		ut32 sz; // size in bits
	} fields[64];
	ut32 num_bits;
	ut32 num_fields;
} gdbr_flags_reg_t;

// sizeof (buf) needs to be atleast flags->num_bits + 1
static void write_flag_bits(char *buf, const gdbr_flags_reg_t *flags) {
	bool fc[26] = { false };
	ut32 i, c;
	memset (buf, '.', flags->num_bits);
	buf[flags->num_bits] = '\0';
	for (i = 0; i < flags->num_fields; i++) {
		// How do we show multi-bit flags?
		if (flags->fields[i].sz != 1) {
			continue;
		}
		// To avoid duplicates. This skips flags if first char is same. i.e.
		// for x86_64, it will skip VIF because VM already occured. This is
		// same as default reg-profiles in r2
		c = tolower (flags->fields[i].name[0]) - 'a';
		if (fc[c]) {
			continue;
		}
		fc[c] = true;
		buf[flags->fields[i].bit_num] = 'a' + c;
	}
}

static int gdbr_parse_target_xml(libgdbr_t *g, char *xml_data, ut64 len) {
	char *arch, *feature, *reg, *reg_end, *regname, *reg_typ, *tmp1, *tmp2,
	     tmpchar, pc_alias[64] = { 0 }, *profile = NULL;
	ut64 reg_off = 0, reg_sz, reg_name_len, profile_line_len, profile_len = 0,
	     profile_max_len = 0, blk_sz = 4096;
	bool is_pc = false;
	gdb_reg_t *arch_regs = NULL, *tmp_regs = NULL;
	ut64 num_regs = 0, max_num_regs = 0, regs_blk_sz = 8;
	gdbr_flags_reg_t *flags = NULL, *tmpflags = NULL;
	ut64 num_flags = 0, num_fields = 0, name_sz = 0, cur_flag_num = 0, i = 0;
	char *flagstr, *flagsend, *field_start, *field_end, flagtmpchar, fieldtmpchar;
	char flag_bits[65];
	// Find architecture
	g->target.arch = R_SYS_ARCH_NONE;
	if ((arch = strstr (xml_data, "<architecture"))) {
		if (!(arch = strchr (arch, '>'))) {
			return -1;
		}
		arch++;
		if (r_str_startswith (arch, "i386")) {
			g->target.arch = R_SYS_ARCH_X86;
			g->target.bits = 32;
			arch += 4;
			if (r_str_startswith (arch, ":x86-64")) {
				g->target.bits = 64;
			}
		} else if (r_str_startswith (arch, "aarch64")) {
			g->target.arch = R_SYS_ARCH_ARM;
			g->target.bits = 64;
		} else if (r_str_startswith (arch, "arm")) {
			g->target.arch = R_SYS_ARCH_ARM;
			g->target.bits = 32;
		}
		// TODO others
	} else {
		// apple's debugserver on ios9
		if (strstr (xml_data, "com.apple.debugserver.arm64")) {
			g->target.arch = R_SYS_ARCH_ARM;
			g->target.bits = 64;
		} else {
			eprintf ("Unknown architecture parsing XML (%s)\n", xml_data);
		}
	}
	// Features
	feature = xml_data;
	while ((feature = strstr (feature, "<feature"))) {
		reg = feature;
		flagstr = reg;
		if (!(feature = strstr (feature, "</feature>"))) {
			goto exit_err;
		}
		*feature = '\0';
		feature += strlen ("</feature>");
		// Get flags
		while ((flagstr = strstr (flagstr, "<flags"))) {
			if (!(flagsend = strstr (flagstr, "</flags>"))) {
				goto exit_err;
			}
			flagtmpchar = *flagsend;
			*flagsend = '\0';
			tmpflags = realloc (flags, (num_flags + 1) * sizeof (gdbr_flags_reg_t));
			if (!tmpflags) {
				goto exit_err;
			}
			flags = tmpflags;
			memset (&flags[num_flags], 0, sizeof (gdbr_flags_reg_t));
			// Get id
			if (!(tmp1 = strstr (flagstr, "id="))) {
				goto exit_err;
			}
			tmp1 += 4;
			if (!(tmp2 = strchr (tmp1, '"'))) {
				goto exit_err;
			}
			tmpchar = *tmp2;
			*tmp2 = '\0';
			name_sz = sizeof (flags[num_flags].type);
			strncpy (flags[num_flags].type, tmp1, name_sz - 1);
			flags[num_flags].type[name_sz - 1] = '\0';
			*tmp2 = tmpchar;
			// Get size of flags register
			if (!(tmp1 = strstr (flagstr, "size="))) {
				goto exit_err;
			}
			tmp1 += 6;
			if (!(flags[num_flags].num_bits = (ut32) strtoul (tmp1, NULL, 10))) {
				goto exit_err;
			}
			flags[num_flags].num_bits *= 8;
			field_start = flagstr;
			num_fields = 0;
			while ((field_start = strstr (field_start, "<field"))) {
				if (num_fields == 64) {
					break;
				}
				if (!(field_end = strstr (field_start, "/>"))) {
					goto exit_err;
				}
				fieldtmpchar = *field_end;
				*field_end = '\0';
				// Get name
				if (!(tmp1 = strstr (field_start, "name="))) {
					goto exit_err;
				}
				tmp1 += 6;
				if (!(tmp2 = strchr (tmp1, '"'))) {
					goto exit_err;
				}
				// If name length is 0, it is a 1 field. Don't include
				if (tmp2 - tmp1 <= 1) {
					*field_end = fieldtmpchar;
					field_start = field_end + 1;
					continue;
				}
				tmpchar = *tmp2;
				*tmp2 = '\0';
				name_sz = sizeof (flags[num_flags].fields[num_fields].name);
				strncpy (flags[num_flags].fields[num_fields].name,
					tmp1, name_sz - 1);
				flags[num_flags].fields[num_fields].name[name_sz - 1] = '\0';
				*tmp2 = tmpchar;
				// Get offset
				if (!(tmp1 = strstr (field_start, "start="))) {
					goto exit_err;
				}
				tmp1 += 7;
				if (!isdigit (*tmp1)) {
					goto exit_err;
				}
				flags[num_flags].fields[num_fields].bit_num = (ut32) strtoul (tmp1, NULL, 10);
				// Get end
				if (!(tmp1 = strstr (field_start, "end="))) {
					goto exit_err;
				}
				tmp1 += 5;
				if (!isdigit (*tmp1)) {
					goto exit_err;
				}
				flags[num_flags].fields[num_fields].sz = (ut32) strtoul (tmp1, NULL, 10) + 1;
				flags[num_flags].fields[num_fields].sz -= flags[num_flags].fields[num_fields].bit_num;
				num_fields++;
				*field_end = fieldtmpchar;
				field_start = field_end + 1;
			}
			flags[num_flags].num_fields = num_fields;
			num_flags++;
			*flagsend = flagtmpchar;
			flagstr = flagsend + 1;
		}
		// Get registers
		while ((reg = strstr (reg, "<reg")) && reg < feature) {
			// null out end of reg description
			if (!(reg_end = strchr (reg, '/')) || reg_end >= feature) {
				goto exit_err;
			}
			tmpchar = *reg_end;
			*reg_end = '\0';
			// name
			if (!(regname = strstr (reg, "name="))) {
				goto exit_err;
			}
			regname += 6;
			if (!(tmp1 = strchr (regname, '"'))) {
				goto exit_err;
			}
			reg_name_len = tmp1 - regname;
			// size
			if (!(tmp1 = strstr (reg, "bitsize="))) {
				goto exit_err;
			}
			tmp1 += 9;
			if (!isdigit (*tmp1)) {
				goto exit_err;
			}
			reg_sz = strtoul (tmp1, NULL, 10);
			// type
			reg_typ = "gpr";
			if ((tmp1 = strstr (reg, "group="))) {
				tmp1 += 7;
				if (r_str_startswith (tmp1, "float")) {
					reg_typ = "fpu";
				}
				// We need type information in r2 register profiles
			}
			if ((tmp1 = strstr (reg, "type="))) {
				tmp1 += 6;
				if (r_str_startswith (tmp1, "vec")
				    || r_str_startswith (tmp1, "i387_ext")) {
					reg_typ = "fpu";
				}
				if (r_str_startswith (tmp1, "code_ptr")) {
					if (!is_pc) {
						is_pc = true;
						strcpy (pc_alias, "=PC\t");
						strncpy (pc_alias + 4, regname, reg_name_len);
						strcpy (pc_alias + 4 + reg_name_len, "\n");
					}
				}
				// Check all flags
				for (cur_flag_num = 0; cur_flag_num < num_flags; cur_flag_num++) {
					if (r_str_startswith (tmp1, flags[cur_flag_num].type)) {
						// Max 64-bit :/
						if (flags[cur_flag_num].num_bits > 64) {
							cur_flag_num = num_flags;
							break;
						}
						break;
					}
				}
				// We need type information in r2 register profiles
			}
			*reg_end = tmpchar;
			profile_line_len = strlen (reg_typ) + reg_name_len + 64;
			if (profile_max_len - profile_len <= profile_line_len) {
				if (!(tmp2 = realloc (profile, profile_max_len + blk_sz))) {
					goto exit_err;
				}
				profile = tmp2;
				profile_max_len += blk_sz;
			}
			// reg_size > 64 is not supported? :/
			// We don't handle register names > 31 chars. Re-evaluate?
			if (reg_sz > 64 || reg_name_len > 31) {
				reg_off += reg_sz / 8;
				reg = reg_end;
				continue;
			}
			tmpchar = regname[reg_name_len];
			regname[reg_name_len] = '\0';
			flag_bits[0] = '\0';
			if (cur_flag_num < num_flags) {
				write_flag_bits (flag_bits, &flags[cur_flag_num]);
			}
			snprintf (profile + profile_len, profile_line_len, "%s\t%s\t"
				".%"PFMT64d "\t%"PFMT64d "\t0\t%s\n", reg_typ, regname,
				reg_sz, reg_off, flag_bits);
			profile_len += strlen (profile + profile_len);
			if (cur_flag_num < num_flags) {
				for (i = 0; i < flags[cur_flag_num].num_fields; i++) {
					profile_line_len = strlen (flags[cur_flag_num].fields[i].name) + 64;
					if (profile_max_len - profile_len <= profile_line_len) {
						if (!(tmp2 = realloc (profile, profile_max_len + blk_sz))) {
							goto exit_err;
						}
						profile = tmp2;
						profile_max_len += blk_sz;
					}
					snprintf (profile + profile_len, profile_line_len,
						"gpr\t%s\t.%d\t.%"PFMT64d "\t0\n",
						flags[cur_flag_num].fields[i].name,
						flags[cur_flag_num].fields[i].sz,
						flags[cur_flag_num].fields[i].bit_num + (reg_off * 8));
					profile_len += strlen (profile + profile_len);
				}
			}
			if (num_regs + 1 >= max_num_regs) {
				tmp_regs = realloc (arch_regs, (max_num_regs + regs_blk_sz) * sizeof (gdb_reg_t));
				if (!tmp_regs) {
					goto exit_err;
				}
				arch_regs = tmp_regs;
				max_num_regs += regs_blk_sz;
			}
			if (reg_name_len >= sizeof (arch_regs[num_regs].name)) {
			    eprintf ("Register name too long: %s\n", regname);
			}
			strncpy (arch_regs[num_regs].name, regname,
				 sizeof (arch_regs[num_regs].name) - 1);
			arch_regs[num_regs].name[sizeof (arch_regs[num_regs].name) - 1] = '\0';
			arch_regs[num_regs].offset = reg_off;
			arch_regs[num_regs].size = reg_sz / 8;
			num_regs++;
			arch_regs[num_regs].name[0] = '\0';
			reg_off += reg_sz / 8;
			regname[reg_name_len] = tmpchar;
			reg = reg_end;
		}
	}
	if (*pc_alias) {
		profile_line_len = strlen (pc_alias);
		if (profile_max_len - profile_len <= profile_line_len) {
			if (!(tmp2 = realloc (profile, profile_max_len + profile_line_len + 1 - profile_len))) {
				goto exit_err;
			}
			profile = tmp2;
		}
		strcpy (profile + profile_len, pc_alias);
	}
	// Difficult to parse these out from xml. So manually added from gdb's xml files
	switch (g->target.arch) {
	case R_SYS_ARCH_ARM:
		switch (g->target.bits) {
		case 32:
			if (!(profile = r_str_prefix (profile,
							"=PC    r15\n"
							"=SP    r14\n" // XXX
							"=A0    r0\n"
							"=A1    r1\n"
							"=A2    r2\n"
							"=A3    r3\n"
						      ))) {
				goto exit_err;
			}
			break;
		case 64:
			if (!(profile = r_str_prefix (profile,
							"=PC\tpc\n"
							"=SP\tsp\n"
							"=BP\tx29\n"
							"=A0    x0\n"
							"=A1    x1\n"
							"=A2    x2\n"
							"=A3    x3\n"
							"=ZF    zf\n"
							"=SF    nf\n"
							"=OF    vf\n"
							"=CF    cf\n"
							"=SN    x8\n"
						      ))) {
				goto exit_err;
			}
		}
		break;
		break;
	case R_SYS_ARCH_X86:
		switch (g->target.bits) {
		case 32:
			if (!(profile = r_str_prefix (profile,
						     "=PC\teip\n"
						     "=SP\tesp\n"
						     "=BP\tebp\n"))) {
				goto exit_err;
			}
			break;
		case 64:
			if (!(profile = r_str_prefix (profile,
						     "=PC\trip\n"
						     "=SP\trsp\n"
						     "=BP\trbp\n"))) {
				goto exit_err;
			}
		}
		break;
		// TODO others
	}
	free (g->target.regprofile);
	free (flags);
	g->target.regprofile = profile;
	g->target.valid = true;
	g->registers = arch_regs;
	return 0;

exit_err:
	free (profile);
	free (arch_regs);
	free (flags);
	return -1;
}
