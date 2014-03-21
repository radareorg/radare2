/*
 * ida2rdb.idc
 * ===========
 *
 * Exports an ida database in a format to be handled by radare
 *
 * author: pancake <@youterm.com>
 *
 * TODO:
 * * Add stack frame related information (stack size, and so) as comments
 *
 */

#include <idc.idc>

static dumpMeNot(fd, ea) {
	auto func, comment, sz, i, ref;

	// Loop from start to end in the current segment
	//SegStart(ea);
	for (func=ea; func != BADADDR && func < SegEnd(ea); func=NextFunction(func)) {
		// If the current address is function process it
//		if (GetFunctionFlags(func) != -1) {
			sz = FindFuncEnd(func) - func;
			fprintf(fd, "af+ 0x%08lx %d %s\n", func, sz, GetFunctionName(func));

			comment = GetFunctionCmt(func, 0);
			if (comment != "")
				fprintf(fd, "CC %s@0x%08x\n", comment, func);

			fprintf(fd, "CC framesize=%d@0x%08x\n", func, GetFrameSize(func));

			// Find all code references to func
			for (ref=RfirstB(func); ref != BADADDR; ref=RnextB(func, ref)) {
				//fprintf(fd, "; xref from %08lX (%s)\n", ref, GetFunctionName(ref));
				fprintf(fd, "Cx 0x%08lx 0x%08lx\n", func, ref);
			}
//		}
	}

	for (func=ea; func != BADADDR && func < SegEnd(ea); func=func+1) {
		comment = CommentEx(func, 0);
		if (comment != "")
			fprintf(fd, "CC %s@0x%08x\n", comment, func);
		comment = GetConstCmt(func, 0);
		if (comment != "")
			fprintf(fd, "CC %s@0x%08x\n", comment, func);
		comment = GetEnumCmt(func, 0);
		if (comment != "")
			fprintf(fd, "CC %s@0x%08x\n", comment, func);
	}
}

static main() {
	auto fd;
	auto file;
	auto i, func, ref,sz;
	auto ord,ea;
	auto comment;
	auto entry;

	file = GetInputFile()+".txt";
	fd = fopen(file, "w");
	if (!fd) {
		Message("Cannot open '"+file+"'\n");
		Exit(1);
	}

	entry="";
	// Walk entrypoints
	for ( i=0; ; i++ ) {
		ord = GetEntryOrdinal(i);
		if ( ord == 0 ) break;
		ea = GetEntryPoint(ord);
		fprintf(fd, "entry=0x%08lx %s\n", ea, Name(ea));
		entry = ea;
	}

	// XXX last entrypoint taken as ok??
	dumpMeNot(fd, entry);

	// eof
	fclose(fd);

	Message(file+"file generated.\n");
}
