     ____  ___  ___  ___ ____  ___  _____   ____
    |  _ \/   \|   \/   \  _ \/ _ \ \__  \ /    \
    |    (  V  \ |  ) V  \   (  __/ .-` _/|  ()  |
    |__\__|_|__|___/__|__|_\__\___\ |____(_)____/


0.9.8
=====
--> add test * pdr doesnt works well with antidisasm tricks
* option to disable aslr in rarun2?
* rafind2 : add support for unicode/widestring search
* .dr- # documented... but not working
* libr/debug/p/drx.c <- not used .. debug must have a hw reg api for drx and gpio
* ah -> add hint to define calls that do not return
* continue execution until condition happen (reg, mem, ..)
* rabin2 -x should not work on non-fatmach0 files
* foldable stuff .. was in r1..redo?
* cmp rip+xx -> not resolved wtf
* search for CALL instructions in text segment.
  - analyze the destination address of each call destination
* integrate dwarf parser with disassembler and debugger
* step back .. log all state changes on every debugger stop
* show analized functions in 'aa' -> discuss
* timeout for code analysis (check timestamp)
  - add analysis points continuation, so 'aa' can be used progressively
* Allow to seek to branch N like in visual, but from cmdline
* Colorize multiple ranges of chars in hexdump -- cparse
* refactor vmenus.c -> refresh function must be redefined for each menu
// show hints for
    0x100005eca     ff2540130000     jmp qword [rip+0x1340] [1]             
* highlight search hits in hexdump
* Implement debugger backtrace properly
* p7 : 7bit encoding (sms)
  - variant for stego print? LSB, MSB, ...
  - add base85 api
* crackme mach0 happy with rbin
* if no debugger supported, say so... r_io must ?
* check search multiple keywords and signatures
* search for antidebug/disasm tricks opcodes
  - allows to find interesting points to analyze
* use slices for r_list_iter primitives

BUGS
----
* RBinCreate:
  - mach0 create for darwin-ppc
  - mz
  - pe64
  - plan9 bins
* Implement support for args in 'oo' (like in r1s !load debugger..)
* opening a file from inside r2 doesnt clears internal data (strings..)
* backtrace for linux or osx at least
* implement 'ax' to get/set xrefs (better than afl <addr>) .. or afx?
* shell encoder - get x86-64 one from twitter
  - http://funoverip.net/2011/09/simple-shellcode-obfuscation/
  - shellforge.. and review current shellcodes :?
* rasm2 must support binary creation help message or so..
  - rabin2 integration must be easier
* rabin2 -z /dev/sda1 TAKES TOO LONG. opening r2 /tmp/fs is SLOW as shit.

* Add support for classes in c++, objc binaries
  - command to add new classes
* Tracing support for the debugger
  - "e cmd.trace=dr=;.dr*;pd 2@eip"
  - dca sym.main imp.printf
  - dbc

** BUG **
  * fix for indirect list manipulations -- looks like a similar problem with r_cons recusivity
  - when you are iterating a list you CANT remove items from it
  - this is..you CANT call r_core_cmd() while iterating flags unless you want to crash
  - we probably need to queue the deletions and use a commit-like methodology
  - this way we avoid duplications
 RListBox *b = r_flag_get_list ();
  r_list_foreach (b, iter, item) {
    r_list_delete_iter_later (b, iter);
  }
  r_list_commit (b);

* Add r_cons_prompt () ... calling set_prompt + fgets -- this api needs cleanup
  - set prompt, set line, fgets
  - strict width in visual
* REFACTOR of disasm loop XDDDDD -1 (r2<1.0 plzz)
  - arch dependent anal code must be removed from disasm loop +1

nibble
------
* Analyze this opcode: ff2518130000     jmp qword [rip+0x1318]
* Support for proper analyze of TinyPE binaries
* Do not show XREF info if in the same function?
* r_anal
  - Code analysis (detect when an argument is a flagmask or
    enum and display text format) (ollydbg)
* r_bin
  - PE: native subsystem? http://radare.org/get/w32/mrxnet.tgz
* Fix RAnalCond
* code analysis must resolve jump tables
* allow to hook r_asm_disassemble and assemble with custom callbacks
  - extend a disassembler with own instructions.
* For each "call" or "push offset"+"ret" create a function.
  - And, if deep code analysis is enabled:
  - Search every possible function by searching typical prologs and put them in a queue.
  - Perform the same actions as in the previous steps with the entry points.
* detect strings in code analysis
* register renaming (per-instruction or ranges)
  - r_parser fun? a specific asm.parser plugin that does all this tricks?
* Display getsym() stuff in rabin2, not only legit syms
* dmi command must read from memory if no file path provided
  - rabin from memory ftw, to get libnames of dll, so..
* add support for sign/unsigned registers..or at least a way to cast them
* use r_anal_value everywhere
* diff code analysis
  - diff two programs
     1st level:
        - check all functions EQUAL, DIFFERENT, REMOVED, ADDED
        - check all symbols
        - check all imports
        - check all strings
     2nd level:
        - basic block level diffing (output in graph mode)

earada
------
* Add print support for bitfields (pm b...)
* Fix io_haret memory dump
* refactor rap and raps
* remove all uses of alloca() // mingw and grep reports them all :)
* typedef all function pointers, like in r_bp
* Implement /. to search using a file .. isnt zignatures about this?
* Implement search and replace /s
  - insert or append? (see r1 cfg vars)

Assembler
---------
* Embed bits/arch/endian in a separated structure
  - So one can change from one arch to another with a pointer
  - Cool for defining ranges of memory

* r_io
  - We need a way to get the underlying file which responds
    to the read call (this way we can know which library
    lives at a specified offset. (is this already done?)

* radare2
  - Use r_bin with r_io to get symbols
    - The offset to read will define the module to analyze and retrieve syms
  - Import msdn doc as comments

RDB
---
  - Implement iterators r_db_next() and r_db_prev() (HIGH PRIO)
  - Write test programs to ensure the data is stored correctly

RSearch
-------
* Test r_search_delta()
  - The pattern finding functions are not following the design
    of the rest of the library, it needs a redesign and code cleanup
    (see bytepat.c)
  - Implement radare/src/xrefs.c into r_search
  - Add support to change the case sensitive of searchs (ignore case)
    - This must be keyword-based. Not globally
  - Sync vapi (r_search_regexp not implemented)
  - Enable/disable nested hits? (discuss+ implement in parent app?)
    - Just skip bytes until end of keyword
* AES/RSA Key finding
  http://citp.princeton.edu/memory/code/ <- implement this stuff in r2


Binaries
--------
* add support for .a files (r_fs supports cpio and ar archives...)
* add support for .rar files

# Random
* Implement rap:// upload/download protocol commands (maybe just system() with rsc2+wget?
* Reimplement or fix the delta diffing in C - first we need to do it for ired..
* Ranged/scrollable zoom mode

* Add support for STATIC_PLUGINS in r_lang
  - r_lang_define is implemented in lang.c, but requires the collaboration
    of the plugins to properly setup the environment for the script execution.
  - Add support for STATIC_PLUGINS in r_lang
  - dlerror(/usr/lib/radare2/lang_perl.so): libperl.so: cannot open shared object file: No such file or directory
    This issue is fixed by setting LD_LIBRARY_PATH...looks like dlopen ignores rpath
* gdiff
  - graph based fingerprints? (cyclomatic complexity...)
* rcore
  - do not allow to disassemble unaligned addresses (toggle)
  - r_asm can reduce cpu without disasm on fixed size ops archs.
* Add support for templates -- like in 010
  http://www.sweetscape.com/010editor/templates.html
* templates #!template peheader.template
  - pT template.foo #   r_print_template
  translate into c code and gets compiled. use rcc+rasm?
  it is like a extended regular expression engine


Debugger
--------
* Skip instruction
* Step until end of frame (stack pointer restored) (store sp, check if nsp>sp)
* stepover waits for one unknown event that cannot be stopped
* code injection facilities? (wtf? insert, execute, restore)
* Trace contents of buffers: filter search results..?  cc 8080 @@ hit* .. check for values that has changed.
* Record trace of register status for each function when running
  - r_reg_arena_copy();
* Implement list threads on ALL supported platforms (win,lin,osx)
* All threads must be stopped when a breakpoint is handled..
* Add support for windbg+virtualkd
* Floating point registers
* MMX/XMM/DRX control
* Implement dump+restore as macros (dump,)
* Implement software stepping (with code analysis+breakpoints)
* Implement dbg.bep - in r_core? in r_debug after attach? maybe only in r2 binr?
  - must be refined.. and look for better names

pancake
-------
* Implement PTRACE_BLOCK on Linux
* fork/clone child . inject code to create new threads or pids
* Functions in r_util to get lil/big ut8,16,32 from ut8*
  - already done..must find better names probably
* rarc2 allows to compile invalid code like calling puts() out of context
* Implement RAnalCall (analyze function arguments, return values, propagate types..)
  - define number of arguments for given function
  - warn if signature and analysis differs in number of args or so..
  - when calling a function
    - identify arguments passed and compare with arguments required
    - if they do not match: we need to warn/ask user/store multiple options
       - function signature comparsion if they dont match
       r_anal_fcn_cmp (anal, f1, f2);

Analysis
--------
* split r_anal API functions (too much args) _new, _add...
* Initial analysis looking for xrefs to strings and so? ax? ./a@@entry0 - Launched at startup

To think
--------
* Ranged value:
  - ut64 from, to
  - restrict : %2 (module)
* Add support for aout binaries?
* eprintf should be modified to log into a file
  - eprintf_open() -- start log to file
  - eprintf_close() -- stop log to file
* Only use uppercase KMG for Kilo,Mega,Giga in r_num? - 'g' is for double
* radare2.c:217 . find name for maxfilesize to hash
* r_list_foreach_prev is buggy, review and remove..
* make symstall in r2-bindings/ ?
* Add deltified offset in PC? +10, +30 ... asm.reladdr
* regio not implemented // it is really necessary? imho no..
* distribute 'spp' with 'rarc2' ? imho no
* Add graph.nodecolor graph.bgcolor graph.edgecolor ??

Refactoring
-----------
* Rename r_hashtable -> r_ht
* Review the r_flags api
* Add pipe_to_buffer..not only file descriptors
* r_config set_int and so..simplify
  - find/use more common cases for char* or &int maps
    - automatic callbacks for most common usecases
* Merge r_socket inside r_util ?
* Is RCore->block and blocksize a RBuf ? refactor!11
* Discuss missing r_core_sysenv_update in core/file.c:33
* Add RLog API.. pipeable to disk and stderr..also hookable ..cool for ui (partially done)
* Redesign core/disasm.c to provide a pluggable api
* Move 'r_syscall_t' stuff into r_debug (sync r_core)
* Implement r_bind api to link multiple pointers
  core->asm = r_bind_set (core->asm->bind, r_asm_new ());
* Find a better name for r_buf_fread (really?)

To wipe
-------
 - Move manpages from man/ to binr/*/? (harder to maintain?)
 - Move the content of libr/*/TODO here
 - linestyle?? for disassembly lines
 - remove libr/vm and libr/db
 - imho we should not implement this:
   - Implement BLOCK in r_core_sysenv_begin|end ()
 * Deprecate CiU (remove) those APIs and dependencies!
 - big-ssl.c big-gmp.c ...
 - implement GMP in util/big.c
  - http://etutorials.org/Programming/secure+programming/Chapter+7.+Public+Key+Cryptography/7.5+Generating+a+Prime+Number+Testing+for+Primality/

Optimizations
-------------
* Performance
  - cons_visual_write() should do a single write instead of one per line
  - Refactor get_sym() and so on...
  - TODO: make elf/pe get_os() and others return const and not strdup
  - RAnalValue must be static, not ref
  - save memory and accelerate code analysis
  - basicblock signatures must be just pointers to a big buf
* Optimize /m
  - search only using given file, not loading default library
  - do not read each block byte per byte
  - do not show repeated consecutive hits
 
Future
------
* memset0 the op before calling the plugin analysis -- not really that is a performance cost..
* Add 'S' subcommand to display section size and get by perms rwx
* Implement r_flag_unset_i () ftw
* Honor string metadata for asmsteps ('jk' in visual)
* search.kwidx must be search.lastidx or search.idx ?
* asm.pseudo for brainfuck
* code analysis for msil
* rax2 -k by default?
* r_cons_visual_write_tail() -> fill end of screen with spaces \o/
* Add support for 'expect' like foo in rarun2
  - make rarun live in a lib.. or at least be usable from r2
* use centralized pubsub or memcached to sync data // redis?
* r_file_slurp should work fine for big files (not prio) r_file_slurp_buf?
  - mmap if supported - add r_file_mmap ?  - read file in blocks instead of the whole file in a single syscall
* Realign flags when using project in debug mode
* FileDescriptors: dd -- copy from !fd in r1
* metaflags? support to define relations between flags
    (flag hirearchies)
	r_flagtree
	 - r_flags should have a tree construction to access to them faster
	   - btree? following pointers like bigger,smaller
	    { struct r_flag_t *bigger, *smaller; }
	   - hooks r_flag_add to recalculate in r_flag_optimize(), bigger/smaller pointers
	   - hooks r_flag_del to recalculate too.
	 - the r_flag_get by string should have another construction with btree
	   for the string of the name

Threads
=======
* implement non-threaded thread api (dummy one, when no support)
* test w32 port
* Implement a pure clone(2) backend
* Added a threading pool super-api

# Debug information in binaries
* dwarf, pdb, def, lib
  - from file, from section, ...
  - load symbols from .lib or .def (find signatures)
    .def -> .idt , .lib -> ar2idt
* Useful information in the PDB format
  - programming language used (dwarf only?)
  - offset - file:line
  - elements { position, type, name, length, offset, delta }
  - types // using the r_anal vartype API (not yet implemented)
  - position = { inlined, global, local } enum
  - function = { visibility, position, type, calltype (cc), arglist, return }
  - visibility = { local, exported, qualified }
  Types {
  	// element types
  	array, bitfield, class, struct, union, enum, pointer
  	procedure, function, arglist, vtshape, fieldlist
  	
  	// data types
  	float, char, signed short, bool, address, ..
  }
  Type {
  	char, short, ushort, long, ulong, 
  }

<pre>
.------------------------.
|   ___       ___  ____  |
|  | - ) _ _ | _ |/  _/  |    please!
|  | - \| | |\_  |\_  \  |___.  report! :)
|  |___/\___/|___/|___/   ___/
|                        |
`------------------------`
</pre>
