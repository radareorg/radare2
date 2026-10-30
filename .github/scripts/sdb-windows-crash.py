from pathlib import Path

sdb = Path('subprojects/sdb')
(sdb / 'src/crash.h').write_text(r'''
#include <windows.h>
#include <dbghelp.h>

static LONG WINAPI sdb_crash(EXCEPTION_POINTERS *exception) {
	DWORD code = exception->ExceptionRecord->ExceptionCode;
	fprintf (stderr, "CRASH code=0x%08lx address=%p thread=%lu\n", code,
		exception->ExceptionRecord->ExceptionAddress, GetCurrentThreadId ());
	if (code == EXCEPTION_ACCESS_VIOLATION) {
		fprintf (stderr, "access=%llu target=0x%llx\n",
			(unsigned long long)exception->ExceptionRecord->ExceptionInformation[0],
			(unsigned long long)exception->ExceptionRecord->ExceptionInformation[1]);
	}
	HANDLE process = GetCurrentProcess ();
	SymSetOptions (SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
	SymInitialize (process, NULL, TRUE);
	CONTEXT context = *exception->ContextRecord;
	STACKFRAME64 frame = {0};
	frame.AddrPC.Offset = context.Rip;
	frame.AddrFrame.Offset = context.Rbp;
	frame.AddrStack.Offset = context.Rsp;
	frame.AddrPC.Mode = frame.AddrFrame.Mode = frame.AddrStack.Mode = AddrModeFlat;
	unsigned int i;
	for (i = 0; i < 64 && frame.AddrPC.Offset; i++) {
		char storage[sizeof (SYMBOL_INFO) + MAX_SYM_NAME] = {0};
		SYMBOL_INFO *symbol = (SYMBOL_INFO *)storage;
		symbol->SizeOfStruct = sizeof (SYMBOL_INFO);
		symbol->MaxNameLen = MAX_SYM_NAME;
		DWORD64 displacement = 0;
		IMAGEHLP_LINE64 line = {0};
		line.SizeOfStruct = sizeof (line);
		DWORD line_offset = 0;
		HMODULE module = NULL;
		char module_path[MAX_PATH] = {0};
		GetModuleHandleExA (GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			(LPCSTR)(ULONG_PTR)frame.AddrPC.Offset, &module);
		GetModuleFileNameA (module, module_path, sizeof (module_path));
		fprintf (stderr, "#%u %s+0x%llx", i, module_path,
			(unsigned long long)(frame.AddrPC.Offset - (ULONG_PTR)module));
		if (SymFromAddr (process, frame.AddrPC.Offset, &displacement, symbol)) {
			fprintf (stderr, " %s+0x%llx", symbol->Name, (unsigned long long)displacement);
		}
		if (SymGetLineFromAddr64 (process, frame.AddrPC.Offset, &line_offset, &line)) {
			fprintf (stderr, " %s:%lu", line.FileName, line.LineNumber);
		}
		fprintf (stderr, "\n");
		if (!StackWalk64 (IMAGE_FILE_MACHINE_AMD64, process, GetCurrentThread (), &frame,
			&context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
			break;
		}
	}
	char dump_path[MAX_PATH];
	snprintf (dump_path, sizeof (dump_path), "%s/sdb-%lu.dmp", getenv ("SDB_CRASH_DIR"), GetCurrentProcessId ());
	HANDLE dump = CreateFileA (dump_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	MINIDUMP_EXCEPTION_INFORMATION info = {GetCurrentThreadId (), exception, FALSE};
	if (dump != INVALID_HANDLE_VALUE) {
		BOOL ok = MiniDumpWriteDump (process, GetCurrentProcessId (), dump, MiniDumpWithFullMemory, &info, NULL, NULL);
		fprintf (stderr, "dump=%s written=%d error=%lu\n", dump_path, ok, GetLastError ());
		CloseHandle (dump);
	}
	fflush (stderr);
	return EXCEPTION_EXECUTE_HANDLER;
}
''')
entry = sdb / 'src/entry.c'
text = entry.read_text().replace('#include <sdb/sdb.h>', '#include <sdb/sdb.h>\n#include "crash.h"')
text = text.replace('int main(int argc, const char **argv) {', 'int main(int argc, const char **argv) {\n\tSetUnhandledExceptionFilter (sdb_crash);\n\tif (getenv ("SDB_DIAGNOSTIC_CRASH")) { RaiseException (0xe0424242, 0, 0, NULL); }')
entry.write_text(text)
meson = sdb / 'meson.build'
text = meson.read_text().replace("sdb_exe = executable('sdb', join_paths('src','entry.c'),", "sdb_exe = executable('sdb', join_paths('src','entry.c'),\n  link_args: ['dbghelp.lib'],")
meson.write_text(text)
tool = sdb / 'src/tool.c'
tool.write_text(tool.read_text().replace('content = strbuf_drain (sb);', 'content = strbuf_drain (sb);\n\tsb = NULL;'))
