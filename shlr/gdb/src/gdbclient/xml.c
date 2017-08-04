#include "gdbclient/xml.h"
#include "gdbclient/core.h"
#include "arch.h"
#include "gdbr_common.h"
#include "packet.h"
#include <r_util.h>

static char* gdbr_read_feature(libgdbr_t *g, const char *file, ut64 *tot_len);
static int gdbr_parse_target_xml(libgdbr_t *g, char *xml_data, ut64 len);

// If xml target description is supported, read it
int gdbr_read_target_xml(libgdbr_t *g) {
	if (!g->stub_features.qXfer_features_read) {
		return -1;
	}
	char *data;
	ut64 len;
	data = gdbr_read_feature (g, "target.xml", &len);
	gdbr_parse_target_xml (g, data, len);
	free (data);
	return 0;
}


static char* gdbr_read_feature(libgdbr_t *g, const char *file, ut64 *tot_len) {
	ut64 retlen = 0, retmax = 0, off = 0, len = g->stub_features.pkt_sz - 2,
		blksz = g->data_max, subret_space = 0, subret_len = 0;
	char *tmp, *tmp2, *tmp3, *ret = NULL, *subret = NULL, msg[128] = { 0 },
		status, tmpchar;
	while (1) {
		snprintf (msg, sizeof (msg), "qXfer:features:read:%s:%"PFMT64x
			  ",%"PFMT64x, file, off, len);
		if (send_msg (g, msg) < 0
		    || read_packet (g) < 0 || send_ack (g) < 0) {
			free(ret);
			return NULL;
		}
		if (g->data_len == 0) {
			free(ret);
			return NULL;
		}
		if (g->data_len == 1 && g->data[0] == 'l') {
			*tot_len = retlen;
			return ret;
		}
		status = g->data[0];
		if (retmax - retlen < g->data_len) {
			if (!(tmp = realloc (ret, retmax + blksz))) {
				free (ret);
				return NULL;
			}
			retmax += blksz;
			ret = tmp;
		}
		strcpy (ret + retlen, g->data + 1);
		tmp = strstr (ret + retlen, "<xi:include");
		retlen += g->data_len - 1;
		off = retlen;
		while (tmp) {
			// inclusion
			if (!(tmp2 = strstr (tmp, "/>"))) {
				free (ret);
				return NULL;
			}
			subret_space = tmp2 + 2 - tmp;
			if (!(tmp2 = strstr (tmp, "href="))) {
				free (ret);
				return NULL;
			}
			tmp2 += 6;
			if (!(tmp3 = strchr (tmp2, '"'))) {
				free (ret);
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
		if (status == 'l') {
			*tot_len = retlen;
			return ret;
		}
		if (status != 'm') {
			free(ret);
			return NULL;
		}
	}
	free(ret);
	return NULL;
}

static int gdbr_parse_target_xml(libgdbr_t *g, char *xml_data, ut64 len) {
	char *arch, *feature, *reg, *reg_end, *regname, *reg_typ, *tmp1, *tmp2,
		tmpchar, pc_alias[64] = { 0 }, *profile = NULL;
	ut64 reg_off = 0, reg_sz, reg_name_len, profile_line_len, profile_len = 0,
		profile_max_len = 0, blk_sz = 4096;
	bool is_pc = false;
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
	}
	// Features
	feature = xml_data;
	while ((feature = strstr (feature, "<feature"))) {
		reg = feature;
		if (!(feature = strstr (feature, "</feature>"))) {
			free (profile);
			return -1;
		}
		feature += strlen ("</feature>");
		// Get registers
		while ((reg = strstr (reg, "<reg")) && reg < feature) {
			// null out end of reg description
			if (!(reg_end = strchr (reg, '/')) || reg_end >= feature) {
				free (profile);
				return -1;
			}
			tmpchar = *reg_end;
			*reg_end = '\0';
			// name
			if (!(regname = strstr (reg, "name="))) {
				free (profile);
				*reg_end = tmpchar;
				return -1;
			}
			regname += 6;
			if (!(tmp1 = strchr (regname, '"'))) {
				free (profile);
				*reg_end = tmpchar;
				return -1;
			}
			reg_name_len = tmp1 - regname;
			// size
			if (!(tmp1 = strstr (reg, "bitsize="))) {
				free (profile);
				*reg_end = tmpchar;
				return -1;
			}
			tmp1 += 9;
			if (!isdigit (*tmp1)) {
				free (profile);
				*reg_end = tmpchar;
				return -1;
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
						strcpy (pc_alias, "=PC ");
						strncpy (pc_alias + 4, regname, reg_name_len);
						pc_alias[reg_name_len + 4] = '\n';
						pc_alias[reg_name_len + 5] = '\0';
					}
				}
				// We need type information in r2 register profiles
			}
			*reg_end = tmpchar;
			profile_line_len = strlen (reg_typ) + reg_name_len + 64;
			if (profile_max_len - profile_len <= profile_line_len) {
				if (!(tmp2 = realloc (profile, profile_max_len + blk_sz))) {
					free (profile);
					return -1;
				}
				profile = tmp2;
				profile_max_len += blk_sz;
			}
			// reg_size > 64 is not supported? :/
			if (reg_sz > 64) {
				reg_off += reg_sz / 8;
				reg = reg_end;
				continue;
			}
			tmpchar = regname[reg_name_len];
			regname[reg_name_len] = '\0';
			snprintf (profile + profile_len, profile_line_len, "%s\t%s\t"
				  ".%"PFMT64d"\t%"PFMT64d"\t0\n", reg_typ, regname,
				  reg_sz, reg_off);
			reg_off += reg_sz / 8;
			regname[reg_name_len] = tmpchar;
			profile_len += strlen (profile + profile_len);
			reg = reg_end;
		}
	}
	if (*pc_alias) {
		profile_line_len = strlen (pc_alias);
		if (profile_max_len - profile_len <= profile_line_len) {
			if (!(tmp2 = realloc (profile, profile_max_len + profile_line_len + 1 - profile_len))) {
				free (profile);
				return -1;
			}
		}
		strcpy (profile + profile_len, pc_alias);
	}
	free (g->target.regprofile);
	g->target.regprofile = profile;
	g->target.valid = true;
	return 0;
}
