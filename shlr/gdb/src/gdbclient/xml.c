/* libgdbr - LGPL - Copyright 2017-2018 - srimanta.barua1 */

#include "gdbclient/xml.h"
#include "gdbclient/commands.h"
#include "gdbclient/core.h"
#include "arch.h"
#include "gdbr_common.h"
#include "packet.h"
#include <r_util.h>
#include <r_debug.h>
#include <errno.h>

#define MAX_PID_CHARS (5)
#define MAX_FEATURE_DEPTH (16)

typedef struct {
	gdb_reg_t reg;
	const RXmlNode *type;
	const char *group;
	bool pc;
} TargetReg;

typedef struct {
	libgdbr_t *g;
	RList *documents;
	RList *registers;
	size_t remaining;
	ut64 next_regnum;
	const char *osabi;
	int arch;
	int bits;
} TargetDescription;

static RDebugPid *_extract_pid_info(const char *info, const char *path, int tid);

static bool decimal_attribute(const RXmlNode *node, const char *key, ut64 *value) {
	const char *text = rxml_dom_get_attribute (node, key);
	if (!text || !isdigit ((ut8)*text)) {
		return false;
	}
	char *end;
	errno = 0;
	*value = strtoull (text, &end, 10);
	return !*end && errno != ERANGE;
}

static void resolve_arch(TargetDescription *target, const char *arch) {
	arch = r_str_trim_head_ro (arch);
	if (r_str_startswith (arch, "i386")) {
		target->arch = R_SYS_ARCH_X86;
		target->bits = strstr (arch, ":x86-64")? 64: 32;
	} else if (r_str_startswith (arch, "x86_64")) {
		target->arch = R_SYS_ARCH_X86;
		target->bits = 64;
	} else if (r_str_startswith (arch, "aarch64") || r_str_startswith (arch, "arm64")) {
		target->arch = R_SYS_ARCH_ARM;
		target->bits = 64;
	} else if (r_str_startswith (arch, "arm")) {
		target->arch = R_SYS_ARCH_ARM;
		target->bits = 32;
	} else if (r_str_startswith (arch, "mips")) {
		target->arch = R_SYS_ARCH_MIPS;
		target->bits = strstr (arch, "64")? 64: 32;
	} else if (r_str_startswith (arch, "riscv")) {
		target->arch = R_SYS_ARCH_RISCV;
		target->bits = strstr (arch, "32")? 32: 64;
	} else {
		char *name = r_str_trim_dup (arch);
		target->arch = name? r_sys_arch_id (name): R_SYS_ARCH_NONE;
		free (name);
	}
}

static const char *register_group(const char *feature, const char *group, const char *type,
		const RXmlNode *definition, ut64 bits) {
	if ((group && (strstr (group, "float") || strstr (group, "Float")))
	    || (type && (r_str_startswith (type, "ieee_") || r_str_startswith (type, "i387_") || !strcmp (type, "float")))
	    || (feature && (strstr (feature, "vfp") || strstr (feature, "pfe")))) {
		if (bits != 128) {
			return "fpu";
		}
	}
	if ((group && (!strcmp (group, "system") || !strcmp (group, "segment")))
	    || (feature && (strstr (feature, "segments") || strstr (feature, "mpx")))) {
		return "seg";
	}
	if (bits > 64 || (group && (!strcmp (group, "vector") || !strcmp (group, "sse") || !strcmp (group, "mmx")))
	    || (definition && !strcmp (definition->name, "vector"))) {
		return bits <= 64? "vec64": bits <= 128? "vec128": bits <= 256? "vec256": "vec512";
	}
	return "gpr";
}

static bool read_register_xml(TargetDescription *target, const RXmlNode *node, const char *feature, HtPP *types) {
	const char *name = rxml_dom_get_attribute (node, "name");
	ut64 bits;
	if (R_STR_ISEMPTY (name) || !decimal_attribute (node, "bitsize", &bits) || !bits || bits > GDBR_REGS_MAX * 8) {
		return false;
	}
	ut64 number = target->next_regnum;
	if ((rxml_dom_get_attribute (node, "regnum") && !decimal_attribute (node, "regnum", &number))
	    || number >= R_REG_VBANK_MAX_REGS || r_list_length (target->registers) >= R_REG_VBANK_MAX_REGS) {
		return false;
	}
	ut64 offset = UT64_MAX;
	if (rxml_dom_get_attribute (node, "offset")) {
		if (!decimal_attribute (node, "offset", &offset) || offset >= GDBR_REGS_MAX) {
			return false;
		}
		offset *= 8;
	}
	TargetReg *info = R_NEW0 (TargetReg);
	r_str_ncpy (info->reg.name, name, sizeof (info->reg.name));
	r_name_filter (info->reg.name, -1);
	info->reg.regnum = number;
	info->reg.offset = offset;
	info->reg.size = bits;
	const char *type = rxml_dom_get_attribute (node, "type");
	info->type = type? ht_pp_find (types, type, NULL): NULL;
	info->group = register_group (feature, rxml_dom_get_attribute (node, "group"), type, info->type, bits);
	info->pc = type && !strcmp (type, "code_ptr");
	target->next_regnum = number + 1;
	if (!*info->reg.name || !r_list_append (target->registers, info)) {
		free (info);
		return false;
	}
	return true;
}

static bool read_feature_xml(TargetDescription *target, const RXmlNode *feature) {
	HtPP *types = ht_pp_new0 ();
	if (!types) {
		return false;
	}
	const char *name = rxml_dom_get_attribute (feature, "name");
	if (!target->arch && name) {
		if (strstr (name, "com.apple.debugserver.arm64")) {
			resolve_arch (target, "arm64");
		} else if (strstr (name, "com.apple.debugserver.x86_64")) {
			resolve_arch (target, "x86_64");
		} else if (strstr (name, "org.gnu.gdb.riscv")) {
			resolve_arch (target, "riscv");
		} else if (strstr (name, "org.gnu.gdb.mips")) {
			resolve_arch (target, "mips");
		}
	}
	const RXmlNode *node;
	bool ok = true;
	for (node = feature->children; node && ok; node = node->next) {
		if (!node->name) {
			continue;
		}
		const char *id = rxml_dom_get_attribute (node, "id");
		if (!strcmp (node->name, "reg")) {
			ok = read_register_xml (target, node, name, types);
		} else if (id) {
			ok = ht_pp_insert (types, id, (void *)node);
		}
	}
	ht_pp_free (types);
	return ok;
}

static bool read_target_nodes(TargetDescription *target, const RXmlNode *root, int depth);

static bool read_target_document(TargetDescription *target, const char *annex, int depth) {
	if (depth >= MAX_FEATURE_DEPTH || !target->remaining || R_STR_ISEMPTY (annex) || strchr (annex, ':')) {
		return false;
	}
	size_t size;
	char *xml = gdbr_read_xfer (target->g, "features", annex, target->remaining, &size);
	if (!xml) {
		return false;
	}
	RXmlNode *document = rxml_dom_parse (xml);
	free (xml);
	if (!document || !r_list_append (target->documents, document)) {
		rxml_dom_free (document);
		return false;
	}
	target->remaining -= size;
	return read_target_nodes (target, document, depth);
}

static bool read_target_nodes(TargetDescription *target, const RXmlNode *root, int depth) {
	const RXmlNode *arch = rxml_dom_child (root, "architecture");
	const char *text = arch? rxml_dom_child_value (arch): NULL;
	if (text) {
		resolve_arch (target, text);
	}
	const RXmlNode *osabi = rxml_dom_child (root, "osabi");
	if (osabi) {
		target->osabi = rxml_dom_child_value (osabi);
	}
	const RXmlNode *node;
	for (node = root->children; node; node = node->next) {
		if (!node->name) {
			continue;
		}
		if (!strcmp (node->name, "target")) {
			if (root->name || !read_target_nodes (target, node, depth)) {
				return false;
			}
		} else if (!strcmp (node->name, "feature")) {
			if (!read_feature_xml (target, node)) {
				return false;
			}
		} else if (!strcmp (node->name, "xi:include")) {
			if (!read_target_document (target, rxml_dom_get_attribute (node, "href"), depth + 1)) {
				return false;
			}
		}
	}
	return true;
}

static int compare_registers(const void *a, const void *b) {
	const TargetReg *left = a, *right = b;
	return (int)left->reg.regnum - (int)right->reg.regnum;
}

static bool append_register_profile(RStrBuf *profile, const TargetReg *info, const gdb_reg_t *reg) {
	const bool packed = reg->size >= 64 && (r_str_startswith (info->group, "vec") || !strcmp (info->group, "fpu"));
	char bits[65] = {0};
	ut32 letters = 0;
	const RXmlNode *type = info->type;
	const bool bitfields = type && reg->size <= 64 && (!strcmp (type->name, "flags") || !strcmp (type->name, "struct"));
	if (bitfields) {
		memset (bits, '.', reg->size);
		const RXmlNode *field;
		for (field = type->children; field; field = field->next) {
			const char *name = rxml_dom_get_attribute (field, "name");
			ut64 start, end;
			if (R_STR_ISEMPTY (name) || !decimal_attribute (field, "start", &start)
			    || !decimal_attribute (field, "end", &end) || start > end || end >= reg->size) {
				continue;
			}
			char token[32];
			r_str_ncpy (token, name, sizeof (token));
			r_name_filter (token, -1);
			if (*token && !r_strbuf_appendf (profile, "gpr\t%s\t.%"PFMT64u"\t.%"PFMT64u"\t0\n",
					token, end - start + 1, reg->offset + start)) {
				return false;
			}
			int c = tolower ((ut8)token[0]) - 'a';
			if (start == end && c >= 0 && c < 26 && !(letters & (1U << c))) {
				bits[start] = 'a' + c;
				letters |= 1U << c;
			}
		}
	}
	return r_strbuf_appendf (profile, "%s\t%s\t.%"PFMT64u"\t.%"PFMT64u"\t%"PFMT64u"\t%s\n",
		info->group, reg->name, (ut64)reg->size, (ut64)reg->offset, packed? (ut64)reg->size / 8: 0, bits);
}

static void prepend_register_aliases(RStrBuf *profile_buf, int arch, int bits) {
	switch (arch) {
	case R_SYS_ARCH_ARM:
		switch (bits) {
		case 32:
			r_strbuf_prepend (profile_buf,
				"=PC	pc\n"
				"=SP	sp\n" // XXX
				"=A0	r0\n"
				"=A1	r1\n"
				"=A2	r2\n"
				"=A3	r3\n");
			break;
		case 64:
			r_strbuf_prepend (profile_buf,
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
				"=SN	x8\n");
		}
		break;
	case R_SYS_ARCH_X86:
		switch (bits) {
		case 32:
			r_strbuf_prepend (profile_buf,
				"=PC	eip\n"
				"=A0	eax\n"
				"=SP	esp\n"
				"=BP	ebp\n");
			break;
		case 64:
			r_strbuf_prepend (profile_buf,
				"=PC	rip\n"
				"=A0	rax\n"
				"=SP	rsp\n"
				"=BP	rbp\n");
		}
		break;
	case R_SYS_ARCH_MIPS:
		r_strbuf_prepend (profile_buf,
			"=PC	pc\n"
			"=A0	a0\n"
			"=SP	r29\n");
		break;
	default:
		break;
	}
}

static bool apply_target_description(TargetDescription *target) {
	libgdbr_t *g = target->g;
	char *osabi = target->osabi? r_str_trim_dup (target->osabi): NULL;
	if (r_list_empty (target->registers)) {
		if (target->arch && target->bits) {
			gdbr_set_architecture (g, target->arch, target->bits);
		}
		free (g->target.osabi);
		g->target.osabi = osabi;
		return true;
	}
	r_list_sort (target->registers, compare_registers);
	const size_t count = r_list_length (target->registers);
	gdb_reg_t *registers = R_NEWS0 (gdb_reg_t, count + 1);
	if (!registers) {
		free (osabi);
		return false;
	}
	RStrBuf profile;
	r_strbuf_init (&profile);
	const TargetReg *info;
	RListIter *iter;
	ut64 offset = 0;
	size_t index = 0;
	const gdb_reg_t *pc = NULL;
	r_list_foreach (target->registers, iter, info) {
		gdb_reg_t *reg = &registers[index];
		*reg = info->reg;
		if (reg->offset == UT64_MAX) {
			reg->offset = offset;
		}
		size_t end;
		if ((index && reg->regnum == registers[index - 1].regnum)
		    || !gdbr_reg_byte_end (reg, &end) || !append_register_profile (&profile, info, reg)) {
			break;
		}
		offset = R_MAX (offset, reg->offset + reg->size);
		if (info->pc) {
			pc = reg;
		}
		index++;
	}
	bool ok = index == count;
	if (ok) {
		if (target->arch == R_SYS_ARCH_MIPS && registers[0].size == 64) {
			target->bits = 64;
		}
		if (!target->bits) {
			target->bits = pc && (pc->size == 32 || pc->size == 64)? pc->size: g->target.bits;
		}
		if (pc) {
			r_strf_var (alias, 64, "=PC\t%s\n", pc->name);
			r_strbuf_prepend (&profile, alias);
		}
		prepend_register_aliases (&profile, target->arch, target->bits);
		char *text = strdup (r_strbuf_get (&profile));
		ok = text != NULL;
		if (ok) {
			free (g->target.regprofile);
			free (g->target.osabi);
			free (g->registers);
			g->target.regprofile = text;
			g->target.osabi = osabi;
			g->target.arch = target->arch;
			g->target.bits = target->bits;
			g->target.valid = true;
			g->registers = registers;
			gdbr_regs_invalidate (g);
		}
	}
	r_strbuf_fini (&profile);
	if (!ok) {
		free (registers);
		free (osabi);
	}
	return ok;
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
		if (column_data_len < 0 || column_data_len > MAX_PID_CHARS) {
			ret = -1;
			goto end;
		}

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
		if (column_data_len < 0 || (size_t)column_data_len >= sizeof (cmdline)) {
			ret = -1;
			goto end;
		}

		memcpy (cmdline, column, column_data_len);
		cmdline[column_data_len] = '\0';

		// Attempt to read the pid's info from /proc. Non UNIX systems will have the
		// correct pid and cmdline from the xml with everything else set to default
		proc_filename = r_str_newf ("/proc/%d/status", ipid);
		if (gdbr_open_file (g, proc_filename, O_RDONLY, 0) == 0) {
			int read_len = gdbr_read_file (g, (ut8 *)status, sizeof (status) - 1);
			if (read_len >= 0) {
				status[read_len] = '\0';
				pid_info = _extract_pid_info (status, cmdline, ipid);
			} else {
				R_LOG_ERROR ("Failed to read from data from procfs file of pid (%d)", ipid);
			}
			if (gdbr_close_file (g) != 0) {
				R_LOG_ERROR ("Failed to close procfs file of pid (%d)", ipid);
			}
		} else {
			R_LOG_ERROR ("Failed to open procfs file of pid (%d)", ipid);
			pid_info = R_NEW0 (RDebugPid);
			if (!(pid_info->path = strdup (cmdline))) {
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
			pid_info = NULL;
		} else {
			if (pid_info) {
				free (pid_info->path);
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

int gdbr_read_target_xml(libgdbr_t *g) {
	if (!g->stub_features.qXfer_features_read) {
		return -1;
	}
	TargetDescription target = {
		.g = g,
		.documents = r_list_newf ((RListFree)rxml_dom_free),
		.registers = r_list_newf (free),
		.remaining = GDBR_XFER_MAX,
	};
	bool ok = target.documents && target.registers && read_target_document (&target, "target.xml", 0)
		&& apply_target_description (&target);
	r_list_free (target.documents);
	r_list_free (target.registers);
	return ok? 0: -1;
}

int gdbr_read_processes_xml(libgdbr_t *g, int pid, RList *list) {
	if (!g->stub_features.qXfer_osdata_read) {
		return -1;
	}
	size_t len;
	char *data = gdbr_read_xfer (g, "osdata", "processes", GDBR_XFER_MAX, &len);
	if (!data) {
		return -1;
	}
	int ret = gdbr_parse_processes_xml (g, data, len, pid, list);
	free (data);
	return ret;
}

static RDebugPid *_extract_pid_info(const char *info, const char *path, int tid) {
	RDebugPid *pid_info = R_NEW0 (RDebugPid);
	const char *ptr = strstr (info, "State:");
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
