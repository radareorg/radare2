/* libgdbr - LGPL - Copyright 2017-2018 - srimanta.barua1 */

#include "gdbclient/xml.h"
#include "gdbclient/commands.h"
#include "gdbclient/core.h"
#include "arch.h"
#include "gdbr_common.h"
#include "packet.h"
#include <r_util.h>
#include <r_debug.h>

#define MAX_PID_CHARS (5)

static char *gdbr_read_feature(libgdbr_t *g, const char *file, ut64 *tot_len) {
	ut64 retlen = 0, retmax = 0, off = 0, len = g->stub_features.pkt_sz - 2,
		blksz = g->data_max, subret_space = 0, subret_len = 0;
	char *tmp, *tmp2, *tmp3, *ret = NULL, *subret = NULL, msg[128] = { 0 },
		status, tmpchar;
	while (1) {
		snprintf (msg, sizeof (msg), "qXfer:features:read:%s:%"PFMT64x
			",%"PFMT64x, file, off, len);
		if (send_msg (g, msg) < 0
		    || read_packet (g, false) < 0 || send_ack (g) < 0) {
			goto exit_err;
		}
		if (g->data_len == 0) {
			goto exit_err;
		}
		if (g->data_len == 1 && g->data[0] == 'l') {
			break;
		}
		status = g->data[0];
		if (retmax - retlen < g->data_len) {
			if (!(tmp = realloc (ret, retmax + blksz))) {
				goto exit_err;
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
			goto exit_err;
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
			goto exit_err;
		}
		subret_space = tmp2 + 2 - tmp;
		if (!(tmp2 = strstr (tmp, "href="))) {
			goto exit_err;
		}
		tmp2 += 6;
		if (!(tmp3 = strchr (tmp2, '"'))) {
			goto exit_err;
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
				free (subret);
				continue;
			}
			if (subret_len > retmax - retlen - 1) {
				tmp3 = NULL;
				if (!(tmp3 = realloc (ret, retmax + subret_len))) {
					free (subret);
					goto exit_err;
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
exit_err:
	free (ret);
	*tot_len = 0;
	return NULL;
}

static char *gdbr_read_osdata(libgdbr_t *g, const char *file, ut64 *tot_len) {
	ut64 retlen = 0, retmax = 0, off = 0, len = g->stub_features.pkt_sz - 2,
		blksz = g->data_max;
	char *tmp, *ret = NULL, msg[128] = { 0 }, status;
	while (1) {
		snprintf (msg, sizeof (msg), "qXfer:osdata:read:%s:%" PFMT64x ",%" PFMT64x, file, off, len);
		if (send_msg (g, msg) < 0 || read_packet (g, false) < 0 || send_ack (g) < 0) {
			goto exit_err;
		}
		if (g->data_len == 0) {
			goto exit_err;
		}
		if (g->data_len == 1 && g->data[0] == 'l') {
			break;
		}
		status = g->data[0];
		if (retmax - retlen < g->data_len) {
			if (!(tmp = realloc (ret, retmax + blksz))) {
				goto exit_err;
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
	}
	if (!ret) {
		*tot_len = 0;
		return NULL;
	}
	*tot_len = retlen;
	return ret;
exit_err:
	free (ret);
	*tot_len = 0;
	return NULL;
}

typedef struct {
	char type[32];
	struct {
		char name[32];
		ut32 bit_num;
		ut32 sz; // size in bits
	} fields[64];
	ut32 num_bits;
	ut32 num_fields;
} gdbr_xml_flags_t;

typedef struct {
	char name[32];
	char type[8];
	ut32 size;
	ut32 flagnum;
} gdbr_xml_reg_t;

static void _write_flag_bits(char *buf, const gdbr_xml_flags_t *flags);
static int _resolve_arch(libgdbr_t *g, char *xml_data);
static RList *_extract_flags(char *flagstr);
static RList *_extract_regs(char *regstr, RList *flags, char *pc_alias);
static RDebugPid *_extract_pid_info(const char *info, const char *path, int tid);

static int gdbr_parse_target_xml(libgdbr_t *g, char *xml_data, ut64 len) {
	char *regstr, *flagstr, *tmp, *profile = NULL, pc_alias[64], flag_bits[65];
	RList *flags, *regs;
	RListIter *iter;
	gdbr_xml_flags_t *tmpflag;
	gdbr_xml_reg_t *tmpreg;
	int packed_size = 0;
	ut64 profile_len = 0, profile_max_len, regnum = 0, regoff = 0;
	pc_alias[0] = '\0';
	gdb_reg_t *arch_regs = NULL;
	if (_resolve_arch (g, xml_data) < 0) {
		return -1;
	}
	if (!(flagstr = strstr (xml_data, "<feature"))) {
		return -1;
	}
	regstr = flagstr;
	if (!(flags = _extract_flags (flagstr))) {
		return -1;
	}
	if (!(regs = _extract_regs (regstr, flags, pc_alias))) {
		r_list_free (flags);
		return -1;
	}
	if (!(arch_regs = calloc (sizeof (gdb_reg_t), (r_list_length (regs) + 1)))) {
		goto exit_err;
	}
	// approximate per-reg size estimates
	profile_max_len = r_list_length (regs) * 128 + r_list_length (flags) * 128;
	if (!(profile = calloc (1, profile_max_len))) {
		goto exit_err;
	}
	r_list_foreach (regs, iter, tmpreg) {
		if (!tmpreg) {
			continue;
		}
		memcpy (arch_regs[regnum].name, tmpreg->name, sizeof (tmpreg->name));
		arch_regs[regnum].size = tmpreg->size;
		arch_regs[regnum].offset = regoff;
		if (profile_len + 128 >= profile_max_len) {
			if (!(tmp = realloc (profile, profile_max_len + 512))) {
				goto exit_err;
			}
			profile = tmp;
			profile_max_len += 512;
		}
		flag_bits[0] = '\0';
		tmpflag = NULL;
		if (tmpreg->flagnum < r_list_length (flags)) {
			tmpflag = r_list_get_n (flags, tmpreg->flagnum);
			_write_flag_bits (flag_bits, tmpflag);
		}
		packed_size = 0;
		if (tmpreg->size >= 64 &&
			(strstr (tmpreg->type, "fpu") ||
				strstr (tmpreg->type, "mmx") ||
				strstr (tmpreg->type, "xmm") ||
				strstr (tmpreg->type, "ymm"))) {
			packed_size = tmpreg->size / 8;
		}
		profile_len += snprintf (profile + profile_len, 128,
			"%s\t%s\t.%u\t.%" PFMT64d "\t%d\t%s\n", tmpreg->type,
			tmpreg->name, tmpreg->size, regoff,
			packed_size,
			flag_bits);
		// TODO write flag subregisters
		if (tmpflag) {
			int i;
			for (i = 0; i < tmpflag->num_fields; i++) {
				if (profile_len + 128 >= profile_max_len) {
					if (!(tmp = realloc (profile, profile_max_len + 512))) {
						goto exit_err;
					}
					profile = tmp;
					profile_max_len += 512;
				}
				profile_len += snprintf (profile + profile_len, 128, "gpr\t%s\t"
							".%u\t.%"PFMT64d"\t0\n", tmpflag->fields[i].name,
							tmpflag->fields[i].sz, tmpflag->fields[i].bit_num + regoff);
			}
		}
		regnum++;
		regoff += tmpreg->size;
	}
	// Difficult to parse these out from xml. So manually added from gdb's xml files
	switch (g->target.arch) {
	case R_SYS_ARCH_ARM:
		switch (g->target.bits) {
		case 32:
			if (!(profile = r_str_prepend (profile,
							"=PC	pc\n"
							"=SP	sp\n" // XXX
							"=A0	r0\n"
							"=A1	r1\n"
							"=A2	r2\n"
							"=A3	r3\n"
						      ))) {
				goto exit_err;
			}
			break;
		case 64:
			if (!(profile = r_str_prepend (profile,
							"=PC	pc\n"
							"=SP	sp\n"
							"=BP	x29\n"
							"=A0	x0\n"
							"=A1	x1\n"
							"=A2	x2\n"
							"=A3	x3\n"
							"=ZF	zf\n"
							"=SF	nf\n"
							"=OF	vf\n"
							"=CF	cf\n"
							"=SN	x8\n"
						      ))) {
				goto exit_err;
			}
		}
		break;
	case R_SYS_ARCH_X86:
		switch (g->target.bits) {
		case 32:
			if (!(profile = r_str_prepend (profile,
						     "=PC	eip\n"
						     "=SP	esp\n"
						     "=BP	ebp\n"))) {
				goto exit_err;
			}
			break;
		case 64:
			if (!(profile = r_str_prepend (profile,
						     "=PC	rip\n"
						     "=SP	rsp\n"
						     "=BP	rbp\n"))) {
				goto exit_err;
			}
		}
		break;
	case R_SYS_ARCH_MIPS:
		if (!(profile = r_str_prepend (profile,
						"=PC	pc\n"
						"=SP	r29\n"))) {
			goto exit_err;
		}
		break;
	default:
		// TODO others
		if (*pc_alias) {
			if (!(profile = r_str_prepend (profile, pc_alias))) {
				goto exit_err;
			}
		}
	}
	// Special case for MIPS, since profile doesn't separate 32/64 bit MIPS
	if (g->target.arch == R_SYS_ARCH_MIPS) {
		if (arch_regs && arch_regs[0].size == 8) {
			g->target.bits = 64;
		}
	}
	r_list_free (flags);
	r_list_free (regs);
	R_FREE (g->target.regprofile);
	if (profile) {
		g->target.regprofile = strdup (profile);
		free (profile);
	}
	g->target.valid = true;
	g->registers = arch_regs;
	return 0;

exit_err:
	r_list_free (flags);
	r_list_free (regs);
	free (profile);
	free (arch_regs);
	return -1;
}

/* Reference:
<osdata type="processes">
<item>
<column name="pid">1</column>
<column name="user">root</column>
<column name="command">/sbin/init maybe-ubiquity </column>
<column name="cores">0</column>
</item>
</osdata>
*/
static int gdbr_parse_processes_xml(libgdbr_t *g, char *xml_data, ut64 len, int pid, RList *list) {
	char pidstr[MAX_PID_CHARS + 1], status[1024], cmdline[1024];
	char *itemstr, *itemstr_end, *column, *column_end, *proc_filename;
	int ret = -1, ipid, column_data_len;
	RDebugPid *pid_info = NULL;

	// Make sure the given xml is valid
	if (!r_str_startswith (xml_data, "<osdata type=\"processes\">")) {
		ret = -1;
		goto end;
	}

	column = xml_data;
	while ((itemstr = strstr (column, "<item>"))) {
		if (!(itemstr_end = strstr (itemstr, "</item>"))) {
			ret = -1;
			goto end;
		}
		// Get PID
		if (!(column = strstr (itemstr, "<column name=\"pid\">"))) {
			ret = -1;
			goto end;
		}
		if (!(column_end = strstr (column, "</column>"))) {
			ret = -1;
			goto end;
		}

		column += sizeof ("<column name=\"pid\">") - 1;
		column_data_len = column_end - column;

		memcpy (pidstr, column, column_data_len);
		pidstr[column_data_len] = '\0';

		ipid = atoi (pidstr);

		// Get cmdline
		if (!(column = strstr (itemstr, "<column name=\"command\">"))) {
			ret = -1;
			goto end;
		}
		if (!(column_end = strstr (column, "</column>"))) {
			ret = -1;
			goto end;
		}

		column += sizeof ("<column name=\"command\">") - 1;
		column_data_len = column_end - column;

		memcpy (cmdline, column, column_data_len);
		cmdline[column_data_len] = '\0';

		// Attempt to read the pid's info from /proc. Non UNIX systems will have the
		// correct pid and cmdline from the xml with everything else set to default
		proc_filename = r_str_newf ("/proc/%d/status", ipid);
		if (gdbr_open_file (g, proc_filename, O_RDONLY, 0) == 0) {
			if (gdbr_read_file (g, (unsigned char *)status, sizeof (status)) != -1) {
				pid_info = _extract_pid_info (status, cmdline, ipid);
			} else {
				eprintf ("Failed to read from data from procfs file of pid (%d)\n", ipid);
			}
			if (gdbr_close_file (g) != 0) {
				eprintf ("Failed to close procfs file of pid (%d)\n", ipid);
			}
		} else {
			eprintf ("Failed to open procfs file of pid (%d)\n", ipid);
			if (!(pid_info = R_NEW0 (RDebugPid)) || !(pid_info->path = strdup (cmdline))) {
				ret = -1;
				goto end;
			}
			pid_info->pid = ipid;
			pid_info->ppid = 0;
			pid_info->uid = pid_info->gid = -1;
			pid_info->runnable = true;
			pid_info->status = R_DBG_PROC_STOP;
		}
		// Unless pid 0 is requested, only add the requested pid and it's child processes
		if (0 == pid || ipid == pid || pid_info->ppid == pid) {
			r_list_append (list, pid_info);
		} else {
			if (pid_info) {
				free (pid_info);
				pid_info = NULL;
			}
		}
	}

	ret = 0;
end:
	if (ret != 0) {
		if (pid_info) {
			free (pid_info);
		}
	}
	return ret;
}

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

int gdbr_read_processes_xml(libgdbr_t *g, int pid, RList *list) {
	if (!g->stub_features.qXfer_features_read) {
		return -1;
	}
	ut64 len;
	int ret = -1;
	char *data;

	if (!(data = gdbr_read_osdata (g, "processes", &len))) {
		ret = -1;
		goto end;
	}

	if (gdbr_parse_processes_xml (g, data, len, pid, list) != 0) {
		ret = -1;
		goto end;
	}

	ret = 0;
end:
	if (data) {
		free (data);
	}
	return ret;
}

// sizeof (buf) needs to be atleast flags->num_bits + 1
static void _write_flag_bits(char *buf, const gdbr_xml_flags_t *flags) {
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
		// for x86_64, it will skip VIF because VM already occurred. This is
		// same as default reg-profiles in r2
		c = tolower ((unsigned char)flags->fields[i].name[0]) - 'a';
		if (fc[c]) {
			continue;
		}
		fc[c] = true;
		buf[flags->fields[i].bit_num] = 'a' + c;
	}
}

static int _resolve_arch(libgdbr_t *g, char *xml_data) {
	char *arch;
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
		} else if (r_str_startswith (arch, "mips")) {
			g->target.arch = R_SYS_ARCH_MIPS;
			g->target.bits = 32;
		}
		// TODO others
	} else {
		// apple's debugserver on ios9
		if (strstr (xml_data, "com.apple.debugserver.arm64")) {
			g->target.arch = R_SYS_ARCH_ARM;
			g->target.bits = 64;
		} else if (strstr (xml_data, "org.gnu.gdb.riscv")) {
			// openocd mips?
			g->target.arch = R_SYS_ARCH_RISCV;
			g->target.bits = 64;
		} else if (strstr (xml_data, "org.gnu.gdb.mips")) {
			// openocd mips?
			g->target.arch = R_SYS_ARCH_MIPS;
			g->target.bits = 32;
		} else if (strstr(xml_data, "com.apple.debugserver.x86_64")) {
			g->target.arch = R_SYS_ARCH_X86;
			g->target.bits = 64;
		} else {
			eprintf ("Warning: Unknown architecture parsing XML (%s)\n", xml_data);
		}
	}
	return 0;
}

static RList *_extract_flags(char *flagstr) {
	char *tmp1, *tmp2, *flagsend, *field_start, *field_end;
	ut64 num_fields, type_sz, name_sz;
	gdbr_xml_flags_t *tmpflag = NULL;
	RList *flags;
	if (!(flags = r_list_new ())) {
		return NULL;
	}
	flags->free = free;
	while ((flagstr = strstr (flagstr, "<flags"))) {
		if (!(flagsend = strstr (flagstr, "</flags>"))) {
			goto exit_err;
		}
		*flagsend = '\0';
		if (!(tmpflag = calloc (1, sizeof (gdbr_xml_flags_t)))) {
			goto exit_err;
		}
		// Get id
		if (!(tmp1 = strstr (flagstr, "id="))) {
			goto exit_err;
		}
		tmp1 += 4;
		if (!(tmp2 = strchr (tmp1, '"'))) {
			goto exit_err;
		}
		*tmp2 = '\0';
		type_sz = sizeof (tmpflag->type);
		strncpy (tmpflag->type, tmp1, type_sz - 1);
		tmpflag->type[type_sz - 1] = '\0';
		*tmp2 = '"';
		// Get size of flags register
		if (!(tmp1 = strstr (flagstr, "size="))) {
			goto exit_err;
		}
		tmp1 += 6;
		if (!(tmpflag->num_bits = (ut32) strtoul (tmp1, NULL, 10))) {
			goto exit_err;
		}
		tmpflag->num_bits *= 8;
		// Get fields
		num_fields = 0;
		field_start = flagstr;
		while ((field_start = strstr (field_start, "<field"))) {
			// Max 64 fields
			if (num_fields >= 64) {
				break;
			}
			if (!(field_end = strstr (field_start, "/>"))) {
				goto exit_err;
			}
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
				*field_end = '/';
				field_start = field_end + 1;
				continue;
			}
			*tmp2 = '\0';
			name_sz = sizeof (tmpflag->fields[num_fields].name);
			strncpy (tmpflag->fields[num_fields].name, tmp1, name_sz - 1);
			tmpflag->fields[num_fields].name[name_sz - 1] = '\0';
			*tmp2 = '"';
			// Get offset
			if (!(tmp1 = strstr (field_start, "start="))) {
				goto exit_err;
			}
			tmp1 += 7;
			if (!isdigit ((unsigned char)*tmp1)) {
				goto exit_err;
			}
			tmpflag->fields[num_fields].bit_num = (ut32) strtoul (tmp1, NULL, 10);
			// Get end
			if (!(tmp1 = strstr (field_start, "end="))) {
				goto exit_err;
			}
			tmp1 += 5;
			if (!isdigit ((unsigned char)*tmp1)) {
				goto exit_err;
			}
			tmpflag->fields[num_fields].sz = (ut32) strtoul (tmp1, NULL, 10) + 1;
			tmpflag->fields[num_fields].sz -= tmpflag->fields[num_fields].bit_num;
			num_fields++;
			*field_end = '/';
			field_start = field_end + 1;
		}
		tmpflag->num_fields = num_fields;
		r_list_push (flags, tmpflag);
		*flagsend = '<';
		flagstr = flagsend + 1;
	}
	return flags;
exit_err:
	if (flags) {
		r_list_free (flags);
	}
	free (tmpflag);
	return NULL;
}

static RDebugPid *_extract_pid_info(const char *info, const char *path, int tid) {
	RDebugPid *pid_info = R_NEW0 (RDebugPid);
	if (!pid_info) {
		return NULL;
	}
	char *ptr = strstr (info, "State:");
	if (ptr) {
		switch (*(ptr + 7)) {
		case 'R':
			pid_info->status = R_DBG_PROC_RUN;
			break;
		case 'S':
			pid_info->status = R_DBG_PROC_SLEEP;
			break;
		case 'T':
		case 't':
			pid_info->status = R_DBG_PROC_STOP;
			break;
		case 'Z':
			pid_info->status = R_DBG_PROC_ZOMBIE;
			break;
		case 'X':
			pid_info->status = R_DBG_PROC_DEAD;
			break;
		default:
			pid_info->status = R_DBG_PROC_SLEEP;
			break;
		}
	}
	ptr = strstr (info, "PPid:");
	if (ptr) {
		pid_info->ppid = atoi (ptr + 5);
	}
	ptr = strstr (info, "Uid:");
	if (ptr) {
		pid_info->uid = atoi (ptr + 5);
	}
	ptr = strstr (info, "Gid:");
	if (ptr) {
		pid_info->gid = atoi (ptr + 5);
	}
	pid_info->pid = tid;
	pid_info->path = path ? strdup (path) : NULL;
	pid_info->runnable = true;
	pid_info->pc = 0;
	return pid_info;
}

static RList *_extract_regs(char *regstr, RList *flags, char *pc_alias) {
	char *regstr_end, *regname, *tmp1, *tmpregstr, *feature_end;
	const char *typegroup, *regtype;
	ut32 flagnum, regname_len, regsize, regnum;
	RList *regs;
	RListIter *iter;
	gdbr_xml_reg_t *tmpreg;
	gdbr_xml_flags_t *tmpflag;
	if (!(regs = r_list_new ())) {
		return NULL;
	}
	// Set gpr as the default register type for all of the following registers until `feature` is found
	typegroup = "gpr";
	while ((tmpregstr = strstr (regstr, "<reg"))) {
		if (!(regstr_end = strchr (tmpregstr, '/'))) {
			goto exit_err;
		}
		// Most regs don't have group/type params, attempt to get the type from `feature`.
		// Multiple registers can be wrapped with a certain feature so this typegroup
		// applies on all of the following registers until </feature>
		if (r_str_startswith (regstr, "<feature")) {
			// Verify that we found the feature in the current node
			feature_end = strchr (regstr, '>');
			// To parse features of other architectures refer to:
			// https://sourceware.org/gdb/onlinedocs/gdb/Standard-Target-Features.html#Standard-Target-Features
            // - x86
			if ((tmp1 = strstr (regstr, "core")) != NULL && tmp1 < feature_end) {
				typegroup = "gpr";
			} else if ((tmp1 = strstr (regstr, "segments")) != NULL && tmp1 < feature_end) {
				typegroup = "seg";
			} else if ((tmp1 = strstr (regstr, "linux")) != NULL && tmp1 < feature_end) {
				typegroup = "gpr";
			// Includes avx.512
			} else if ((tmp1 = strstr (regstr, "avx")) != NULL && tmp1 < feature_end) {
				typegroup = "ymm";
			} else if ((tmp1 = strstr (regstr, "mpx")) != NULL && tmp1 < feature_end) {
				typegroup = "seg";
			// - arm
			} else if ((tmp1 = strstr (regstr, "m-profile")) != NULL && tmp1 < feature_end) {
				typegroup = "gpr";
			} else if ((tmp1 = strstr (regstr, "pfe")) != NULL && tmp1 < feature_end) {
				typegroup = "fpu";
			} else if ((tmp1 = strstr (regstr, "vfp")) != NULL && tmp1 < feature_end) {
				typegroup = "fpu";
			} else if ((tmp1 = strstr (regstr, "iwmmxt")) != NULL && tmp1 < feature_end) {
				typegroup = "xmm";
			// -- Aarch64
			} else if ((tmp1 = strstr (regstr, "sve")) != NULL && tmp1 < feature_end) {
				typegroup = "ymm";
			} else {
				typegroup = "gpr";
			}
		}
		// Reset to typegroup in case the previous register had a group/type parameter
		// that indicated it's specific type which doesn't correspond to type defined by
		// the parent feature tag
		regtype = typegroup;
		regstr = tmpregstr;
		*regstr_end = '\0';
		// name
		if (!(regname = strstr (regstr, "name="))) {
			goto exit_err;
		}
		regname += 6;
		if (!(tmp1 = strchr (regname, '"'))) {
			goto exit_err;
		}
		regname_len = tmp1 - regname;
		// size
		if (!(tmp1 = strstr (regstr, "bitsize="))) {
			goto exit_err;
		}
		tmp1 += 9;
		if (!isdigit ((unsigned char)*tmp1)) {
			goto exit_err;
		}
		regsize = strtoul (tmp1, NULL, 10);
		// regnum
		regnum = UINT32_MAX;
		if ((tmp1 = strstr (regstr, "regnum="))) {
			tmp1 += 8;
			if (!isdigit ((unsigned char)*tmp1)) {
				goto exit_err;
			}
			regnum = strtoul (tmp1, NULL, 10);
		}
		flagnum = r_list_length (flags);
		if ((tmp1 = strstr (regstr, "group="))) {
			tmp1 += 7;
			if (r_str_startswith (tmp1, "float")) {
				regtype = "fpu";
			} else if (r_str_startswith (tmp1, "mmx")) {
				regtype = "mmx";
			} else if (r_str_startswith (tmp1, "sse")) {
				regtype = "xmm";
			} else if (r_str_startswith (tmp1, "vector")) {
				regtype = "ymm";
			} else if (r_str_startswith (tmp1, "system")) {
				regtype = "seg";
			}
			// We need type information in r2 register profiles
		}
		if ((tmp1 = strstr (regstr, "type="))) {
			tmp1 += 6;
			if (r_str_startswith (tmp1, "vec")
			    || r_str_startswith (tmp1, "i387_ext")
			    || r_str_startswith (tmp1, "ieee_single")
			    || r_str_startswith (tmp1, "ieee_double")) {
				regtype = "fpu";
			} else if (r_str_startswith (tmp1, "code_ptr")) {
				strcpy (pc_alias, "=PC	");
				strncpy (pc_alias + 4, regname, regname_len);
				strcpy (pc_alias + 4 + regname_len, "\n");
			} else {
				// Check all flags. If reg is a flag, write flag data
				flagnum = 0;
				r_list_foreach (flags, iter, tmpflag) {
					if (r_str_startswith (tmp1, tmpflag->type)) {
						// Max 64-bit :/
						if (tmpflag->num_bits <= 64) {
							break;
						}
					}
					flagnum++;
				}
			}
			// We need type information in r2 register profiles
		}
		// Move unidentified vector/large registers from gpr to xmm since r2 set/get
		// registers doesn't support >64bit registers atm(but it's still possible to
		// read them using gdbr's implementation through dr/drt)
		if (regsize > 64 && !strcmp (regtype, "gpr")) {
			regtype = "xmm";
		}
		// Move appropriately sized unidentified xmm registers from fpu to xmm
		if (regsize == 128 && !strcmp (regtype, "fpu")) {
			regtype = "xmm";
		}
		if (!(tmpreg = calloc (1, sizeof (gdbr_xml_reg_t)))) {
			goto exit_err;
		}
		regname[regname_len] = '\0';
		if (regname_len > sizeof (tmpreg->name) - 1) {
			eprintf ("Register name too long: %s\n", regname);
		}
		strncpy (tmpreg->name, regname, sizeof (tmpreg->name) - 1);
		tmpreg->name[sizeof (tmpreg->name) - 1] = '\0';
		regname[regname_len] = '"';
		strncpy (tmpreg->type, regtype, sizeof (tmpreg->type) - 1);
		tmpreg->type[sizeof (tmpreg->type) - 1] = '\0';
		tmpreg->size = regsize;
		tmpreg->flagnum = flagnum;
		if (regnum == UINT32_MAX) {
			r_list_push (regs, tmpreg);
		} else if (regnum >= r_list_length (regs)) {
			int i;
			for (i = regnum - r_list_length (regs); i > 0; i--) {
				// temporary placeholder reg. we trust the xml is correct and this will be replaced.
				r_list_push (regs, tmpreg);
				r_list_tail (regs)->data = NULL;
			}
			r_list_push (regs, tmpreg);
		} else {
			// this is where we replace those placeholder regs
			r_list_set_n (regs, regnum, tmpreg);
		}
		*regstr_end = '/';
		regstr = regstr_end + 3;
		if (r_str_startswith (regstr, "</feature>")) {
			regstr += sizeof ("</feature>");
			// Revert to default
			typegroup = "gpr";
		}
	}
	regs->free = free;
	return regs;
exit_err:
	if (regs) {
		regs->free = free;
		r_list_free (regs);
	}
	return NULL;
}
