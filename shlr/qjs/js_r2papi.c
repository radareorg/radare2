static const char *const js_r2papi_qjs = "" \
  "\"use strict\";\n\nObject.defineProperty(exports, \"__esModule\", {"\
  " value: true });\nexports.R2Shell = void 0;\nclass R2Shell {\n c"\
  "onstructor(papi) {\n this.rp = papi;\n }\n mkdir(file, recursive"\
  ") {\n if (recursive === true) {\n this.rp.call(`mkdir -p ${file"\
  "}`);\n }\n else {\n this.rp.call(`mkdir ${file}`);\n }\n return tr"\
  "ue;\n }\n unlink(file) {\n this.rp.call(`rm ${file}`);\n return t"\
  "rue;\n }\n chdir(path) {\n this.rp.call(`cd ${path}`);\n return t"\
  "rue;\n }\n ls() {\n const files = this.rp.call(`ls -q`);\n return"\
  " files.trim().split(\"\\n\");\n }\n fileExists(path) {\n \n return f"\
  "alse;\n }\n open(arg) {\n this.rp.call(`open ${arg}`);\n }\n syste"\
  "m(cmd) {\n this.rp.call(`!${cmd}`);\n return 0;\n }\n mount(fstyp"\
  "e, path, offset) {\n if (!offset) {\n offset = 0;\n }\n this.rp.c"\
  "all(`m ${fstype} ${path} ${offset}`);\n return true;\n }\n umoun"\
  "t(path) {\n this.rp.call(`m-${path}`);\n }\n chdir2(path) {\n thi"\
  "s.rp.call(`mdq ${path}`);\n }\n ls2(path) {\n const files = this"\
  ".rp.call(`mdq ${path}`);\n return files.trim().split(\"\\n\");\n }"\
  "\n enumerateFilesystemTypes() {\n return this.rp.cmdj(\"mLj\");\n "\
  "}\n enumerateMountpoints() {\n const output = this.rp.cmdj(\"mj\""\
  ");\n return output[\"mountpoints\"];\n }\n isSymlink(file) {\n retu"\
  "rn false;\n }\n isDirectory(file) {\n return false;\n }\n}\nexports"\
  ".R2Shell = R2Shell;\n\"use strict\";\nObject.defineProperty(expor"\
  "ts, \"__esModule\", { value: true });\nexports.EsilParser = expo"\
  "rts.EsilNode = exports.EsilToken = void 0;\n\nclass EsilToken {"\
  "\n constructor(text = \"\", position = 0) {\n this.label = \"\";\n t"\
  "his.comment = \"\";\n this.text = \"\";\n this.addr = \"0\"; \n this.p"\
  "osition = 0;\n this.text = text;\n this.position = position;\n }"\
  "\n toString() {\n return this.text;\n }\n}\nexports.EsilToken = Es"\
  "ilToken;\nclass EsilNode {\n constructor(token = new EsilToken("\
  "), type = \"none\") {\n this.type = \"none\";\n this.token = token;"\
  "\n this.children = [];\n }\n setSides(lhs, rhs) {\n this.lhs = lh"\
  "s;\n this.rhs = rhs;\n }\n addChildren(ths, fhs) {\n if (ths !== "\
  "undefined) {\n this.children.push(ths);\n }\n if (fhs !== undefi"\
  "ned) {\n this.children.push(fhs);\n }\n }\n toEsil() {\n if (this."\
  "lhs !== undefined && this.rhs !== undefined) {\n \n let left = "\
  "this.lhs.toEsil();\n if (left !== \"\") {\n left += \",\";\n }\n cons"\
  "t right = this.rhs.toEsil();\n return `${right},${left}${this."\
  "token}`;\n }\n return \"\"; \n }\n toString() {\n let str = \"\";\n if "\
  "(this.token.label !== \"\") {\n str += this.token.label + \":\\n\";"\
  "\n }\n if (this.token.addr !== \"0\") {\n \n }\n if (this.token.comm"\
  "ent !== \"\") {\n static encode(input) {\n return (0, exports.b64"\
  ")(input);\n }\n static decode(input) {\n return (0, exports.b64)"\
  "(input, true);\n }\n}\nexports.Base64 = Base64;\n\"use strict\";\nOb"\
  "ject.defineProperty(exports, \"__esModule\", { value: true });\n"\
  "exports.newAsyncR2PipeFromSync = exports.R2PipeSyncFromSync ="\
  " void 0;\nclass R2PipeSyncFromSync {\n constructor(r2p) {\n this"\
  ".r2p = r2p;\n }\n cmd(command) {\n return this.r2p.cmd(command);"\
  "\n }\n cmdAt(command, address) {\n return this.r2p.cmdAt(command"\
  ", address);\n }\n cmdj(cmd) {\n return this.r2p.cmdj(cmd);\n }\n c"\
  "all(command) {\n return this.r2p.call(command);\n }\n callj(cmd)"\
  " {\n return this.r2p.cmdj(cmd);\n }\n callAt(command, address) {"\
  "\n return this.r2p.cmdAt(command, address);\n }\n log(msg) {\n re"\
  "turn this.r2p.log(msg);\n }\n plugin(type, maker) {\n return thi"\
  "s.r2p.plugin(type, maker);\n }\n unload(type, name) {\n return t"\
  "his.r2p.unload(type, name);\n }\n}\nexports.R2PipeSyncFromSync ="\
  " R2PipeSyncFromSync;\nfunction newAsyncR2PipeFromSync(r2p) {\n "\
  "const asyncR2Pipe = new R2PipeSyncFromSync(r2p);\n return asyn"\
  "cR2Pipe;\n}\nexports.newAsyncR2PipeFromSync = newAsyncR2PipeFro"\
  "mSync;\n\"use strict\";\nObject.defineProperty(exports, \"__esModu"\
  "le\", { value: true });\nexports.R2AI = void 0;\nclass R2AI {\n c"\
  "onstructor(r2, num, model) {\n this.available = false;\n this.m"\
  "odel = \"\";\n this.r2 = r2;\n this.available = false;\n }\n checkA"\
  "vailability() {\n if (this.available) {\n return true;\n }\n this"\
  ".available = r2pipe_js_1.r2.cmd(\"r2ai -h\").trim() !== \"\";\n re"\
  "turn this.available;\n }\n reset() {\n this.checkAvailability();"\
  "\n if (this.available) {\n r2pipe_js_1.r2.call(\"r2ai -R\");\n }\n "\
  "}\n setRole(msg) {\n if (this.available) {\n r2pipe_js_1.r2.call"\
  "(`r2ai -r ${msg}`);\n return true;\n }\n return false;\n }\n setMo"\
  "del(modelName) {\n if (this.available) {\n r2pipe_js_1.r2.call("\
  "`r2ai -m ${this.model}`);\n return true;\n }\n return false;\n }\n"\
  " getModel() {\n if (this.available) {\n this.model = r2pipe_js_"\
  "1.r2.call(\"r2ai -m\").trim();\n }\n return this.model;\n }\n listM"\
  "odels() {\n if (this.available) {\n const models = r2pipe_js_1."\
  "r2.call(\"r2ai -M\");\n return models\n .replace(/-m /, \"\")\n .tri"\
  "m()\n .split(/\\n/g)\n .filter((x) => x.indexOf(\":\") !== -1);\n }"\
  "\n return [];\n }\n query(msg) {\n if (!this.available || msg == "\
  "\"\") {\n return \"\";\n }\n const fmsg = msg.trim().replace(/\\n/g, "\
  "\".\");\n const response = r2pipe_js_1.r2.call(`r2ai ${fmsg}`);\n"\
  " return response.trim();\n }\n}\nexports.R2AI = R2AI;\n\"use stric"\
  "t\";\n\nObject.defineProperty(exports, \"__esModule\", { value: tr"\
  "ue });\nexports.NativePointer = exports.NativeCallback = expor"\
  "ts.NativeFunction = exports.R2PapiSync = exports.Assembler = "\
  "exports.ProcessClass = exports.ModuleClass = exports.ThreadCl"\
  "ass = void 0;\nclass ThreadClass {\n constructor(r2) {\n this.ap"\
  "i = null;\n this.api = r2;\n }\n backtrace() {\n return r2pipe_js"\
  "_1.r2.call(\"dbtj\");\n }\n sleep(seconds) {\n return r2pipe_js_1."\
  "r2.call(\"sleep \" + seconds);\n }\n}\nexports.ThreadClass = Threa"\
  "dClass;\nclass ModuleClass {\n constructor(r2) {\n this.api = nu"\
  "ll;\n this.api = r2;\n }\n fileName() {\n return this.api.call(\"d"\
  "pe\").trim();\n }\n name() {\n return \"Module\";\n }\n findBaseAddre"\
  "ss() {\n return \"TODO\";\n }\n getBaseAddress(name) {\n return \"TO"\
  "DO\";\n }\n getExportByName(name) {\n const res = r2pipe_js_1.r2."\
  "call(\"iE,name/eq/\" + name + \",vaddr/cols,:quiet\");\n return pt"\
  "r(res);\n }\n findExportByName(name) {\n return this.getExportBy"\
  "Name(name);\n }\n enumerateExports() {\n \n return r2pipe_js_1.r2"\
  ".callj(\"iEj\");\n }\n enumerateImports() {\n \n return r2pipe_js_1"\
  ".r2.callj(\"iij\");\n }\n enumerateSymbols() {\n \n return r2pipe_j"\
  "s_1.r2.callj(\"isj\");\n }\n enumerateEntrypoints() {\n \n return r"\
  "2pipe_js_1.r2.callj(\"iej\");\n }\n enumerateRanges() {\n \n return"\
  " r2pipe_js_1.r2.callj(\"omj\");\n }\n}\nexports.ModuleClass = Modu"\
  "leClass;\nclass ProcessClass {\n constructor(r2) {\n this.r2 = n"\
  "ull;\n this.r2 = r2;\n }\n enumerateMallocRanges() { }\n enumerat"\
  "eSystemRanges() { }\n enumerateRanges() { }\n enumerateThreads("\
  ") {\n return r2pipe_js_1.r2.callj(\"dptj\");\n }\n enumerateModule"\
  "s() {\n r2pipe_js_1.r2.call(\"cfg.json.num=string\"); \n if (r2pi"\
  "pe_js_1.r2.callj(\"e cfg.debug\")) {\n const modules = r2pipe_js"\
  "_1.r2.callj(\"dmmj\");\n const res = [];\n for (const mod of modu"\
  "les) {\n const entry = {\n base: new NativePointer(mod.addr),\n "\
  "size: new NativePointer(mod.addr_end).sub(mod.addr),\n path: m"\
  "od.file,\n name: mod.name\n };\n res.push(entry);\n }\n return res"\
  ";\n }\n else {\n const fname = (x) => {\n const y = x.split(\"/\");"\
  "\n return y[y.length - 1];\n };\n const bobjs = r2pipe_js_1.r2.c"\
  "allj(\"obj\");\n const res = [];\n for (const obj of bobjs) {\n co"\
  "nst entry = {\n base: new NativePointer(obj.addr),\n size: obj."\
  "size,\n path: obj.file,\n name: fname(obj.file)\n };\n res.push(e"\
  "ntry);\n }\n const libs = r2pipe_js_1.r2.callj(\"ilj\");\n for (co"\
  "nst lib of libs) {\n const entry = {\n base: 0,\n size: 0,\n path"\
  ": lib,\n name: fname(lib)\n };\n res.push(entry);\n }\n return res"\
  ";\n }\n }\n getModuleByAddress(addr) { }\n getModuleByName(module"\
  "Name) { }\n codeSigningPolicy() {\n return \"optional\";\n }\n getT"\
  "mpDir() {\n return this.r2.call(\"e dir.tmp\").trim();\n }\n getHo"\
  "meDir() {\n return this.r2.call(\"e dir.home\").trim();\n }\n plat"\
  "form() {\n return this.r2.call(\"e asm.os\").trim();\n }\n getCurr"\
  "entDir() {\n return this.r2.call(\"pwd\").trim();\n }\n getCurrent"\
  "ThreadId() {\n return +this.r2.call(\"dpq\");\n }\n pageSize() {\n "\
  "if (this.r2.callj(\"e asm.bits\") === 64 &&\n this.r2.call(\"e as"\
  "m.arch\").startsWith(\"arm\")) {\n return 16384;\n }\n return 4096;"\
  "\n }\n isDebuggerAttached() {\n return this.r2.callj(\"e cfg.debu"\
  "g\");\n }\n setExceptionHandler() {\n \n }\n id() {\n \n return this."\
  "r2.callj(\"dpq\").trim();\n }\n pointerSize() {\n return r2pipe_js"\
  "_1.r2.callj(\"e asm.bits\") / 8;\n }\n}\nexports.ProcessClass = Pr"\
  "ocessClass;\nclass Assembler {\n constructor(myr2) {\n this.prog"\
  "ram = \"\";\n this.labels = {};\n this.endian = false;\n this.pc ="\
  " ptr(0);\n if (myr2 === undefined) {\n this.r2 = (0, r2pipe_js_"\
  "1.newAsyncR2PipeFromSync)(r2pipe_js_1.r2);\n }\n else {\n this.r"\
  "2 = myr2;\n }\n this.program = \"\";\n this.labels = {};\n }\n setPr"\
  "ogramCounter(pc) {\n this.pc = pc;\n }\n setEndian(big) {\n this."\
  "endian = big;\n }\n toString() {\n return this.program;\n }\n appe"\
  "nd(x) {\n \n this.pc = this.pc.add(x.length / 2);\n this.program"\
  " += x;\n }\n \n label(s) {\n const pos = this.pc; \n this.labels[s"\
  "] = this.pc;\n return pos;\n }\n encode(s) {\n const output = thi"\
  "s.r2.call(`pa ${s}`);\n return output.trim();\n }\n decode(s) {\n"\
  " const output = this.r2.call(`pad ${s}`);\n return output.trim"\
  "();\n }\n}\nexports.Assembler = Assembler;\nclass R2PapiSync {\n c"\
  "onstructor(r2) {\n this.r2 = r2;\n }\n toString() {\n return \"[ob"\
  "ject R2Papi]\";\n }\n toJSON() {\n return this.toString();\n }\n ge"\
  "tBaseAddress() {\n return new NativePointer(this.cmd(\"e bin.ba"\
  "ddr\"));\n }\n jsonToTypescript(name, a) {\n let str = `interface"\
  " ${name} {\\n`;\n if (a.length && a.length > 0) {\n a = a[0];\n }"\
  "\n for (const k of Object.keys(a)) {\n const typ = typeof a[k];"\
  "\n const nam = k;\n str += ` ${nam}: ${typ};\\n`;\n }\n return `${"\
  "str}}\\n`;\n }\n getBits() {\n return +this.cmd(\"-b\");\n }\n getArc"\
  "h() {\n return this.cmdTrim(\"-a\");\n }\n callTrim(x) {\n const re"\
  "s = this.call(x);\n return res.trim();\n }\n cmdTrim(x) {\n const"\
  " res = this.cmd(x);\n return res.trim();\n }\n getCpu() {\n \n ret"\
  "urn this.cmdTrim(\"-e asm.cpu\"); \n }\n \n setArch(arch, bits) {\n"\
  " this.cmd(\"-a \" + arch);\n if (bits !== undefined) {\n this.cmd"\
  "(\"-b \" + bits);\n }\n }\n setFlagSpace(name) {\n this.cmd(\"fs \" +"\
  " name);\n }\n demangleSymbol(lang, mangledName) {\n return this."\
  "cmdTrim(\"iD \" + lang + \" \" + mangledName);\n }\n setLogLevel(le"\
  "vel) {\n this.cmd(\"e log.level=\" + level);\n }\n \n newMap(fd, va"\
  "ddr, size, paddr, perm, name = \"\") {\n this.cmd(`om ${fd} ${va"\
  "ddr} ${size} ${paddr} ${perm} ${name}`);\n }\n at(a) {\n return "\
  "new NativePointer(a);\n }\n getShell() {\n return new shell_js_1"\
  ".R2Shell(this);\n }\n \n version() {\n const v = this.r2.cmd(\"?Vq"\
  "\");\n return v.trim();\n }\n \n platform() {\n const output = this"\
  ".r2.cmd(\"uname\");\n return output.trim();\n }\n arch() {\n const "\
  "output = this.r2.cmd(\"uname -a\");\n return output.trim();\n }\n "\
  "bits() {\n const output = this.r2.cmd(\"uname -b\");\n return out"\
  "put.trim();\n }\n id() {\n \n return +this.r2.cmd(\"?vi:$p\");\n }\n "\
  "\n printAt(msg, x, y) {\n \n }\n clearScreen() {\n this.r2.cmd(\"!c"\
  "lear\");\n return this;\n }\n getConfig(key) {\n if (key === \"\") {"\
  "\n return new Error(\"Empty key\");\n }\n const exist = this.r2.cm"\
  "d(`e~^${key} =`);\n if (exist.trim() === \"\") {\n return new Err"\
  "or(\"Config key does not exist\");\n }\n const value = this.r2.ca"\
  "ll(\"e \" + key);\n return value.trim();\n }\n setConfig(key, val)"\
  " {\n this.r2.call(\"e \" + key + \"=\" + val);\n return this;\n }\n g"\
  "etRegisterStateForEsil() {\n const dre = this.cmdj(\"dre\");\n re"\
  "turn this.cmdj(\"dre\");\n }\n getRegisters() {\n \n return this.cm"\
  "dj(\"drj\");\n }\n resizeFile(newSize) {\n this.cmd(`r ${newSize}`"\
  ");\n return this;\n }\n insertNullBytes(newSize, at) {\n if (at ="\
  "== undefined) {\n at = \"$$\";\n }\n this.cmd(`r+${newSize}@${at}`"\
  ");\n return this;\n }\n removeBytes(newSize, at) {\n if (at === u"\
  "ndefined) {\n at = \"$$\";\n }\n this.cmd(`r-${newSize}@${at}`);\n "\
  "return this;\n }\n seek(addr) {\n this.cmd(`s ${addr}`);\n return"\
  " this;\n }\n currentSeek() {\n return new NativePointer(\"$$\");\n "\
  "}\n seekToRelativeOpcode(nth) {\n this.cmd(`so ${nth}`);\n retur"\
  "n this.currentSeek();\n }\n getBlockSize() {\n return +this.cmd("\
  "\"b\");\n }\n setBlockSize(a) {\n this.cmd(`b ${a}`);\n return this"\
  ";\n }\n countFlags() {\n return Number(this.cmd(\"f~?\"));\n }\n cou"\
  "ntFunctions() {\n return Number(this.cmd(\"aflc\"));\n }\n analyze"\
  "FunctionsWithEsil(depth) {\n this.cmd(\"aaef\");\n }\n analyzeProg"\
  "ramWithEsil(depth) {\n this.cmd(\"aae\");\n }\n analyzeProgram(dep"\
  "th) {\n if (depth === undefined) {\n depth = 0;\n }\n switch (dep"\
  "th) {\n case 0:\n this.cmd(\"aa\");\n break;\n case 1:\n this.cmd(\"a"\
  "aa\");\n break;\n case 2:\n this.cmd(\"aaaa\");\n break;\n case 3:\n t"\
  "his.cmd(\"aaaaa\");\n break;\n }\n return this;\n }\n enumerateThrea"\
  "ds() {\n \n const regs0 = this.cmdj(\"drj\");\n const thread0 = {\n"\
  " context: regs0,\n id: 0,\n state: \"waiting\",\n selected: true\n "\
  "};\n return [thread0];\n }\n currentThreadId() {\n if (+this.cmd("\
  "\"e cfg.debug\")) {\n return +this.cmd(\"dpt.\");\n }\n return this."\
  "id();\n }\n setRegisters(obj) {\n for (const r of Object.keys(ob"\
  "j)) {\n const v = obj[r];\n this.r2.cmd(\"dr \" + r + \"=\" + v);\n "\
  "}\n }\n hex(s) {\n const output = this.r2.cmd(\"?v \" + s);\n retur"\
  "n output.trim();\n }\n step() {\n this.r2.cmd(\"ds\");\n return thi"\
  "s;\n }\n stepOver() {\n this.r2.cmd(\"dso\");\n return this;\n }\n ma"\
  "th(expr) {\n return +this.r2.cmd(\"?v \" + expr);\n }\n stepUntil("\
  "dst) {\n this.cmd(`dsu ${dst}`);\n }\n enumerateXrefsTo(s) {\n co"\
  "nst output = this.call(\"axtq \" + s);\n return output.trim().sp"\
  "lit(/\\n/);\n }\n \n findXrefsTo(s, use_esil) {\n if (use_esil) {\n"\
  " this.call(\"/r \" + s);\n }\n else {\n this.call(\"/re \" + s);\n }\n"\
  " }\n analyzeFunctionsFromCalls() {\n this.call(\"aac\");\n return "\
  "this;\n }\n autonameAllFunctions() {\n this.call(\"aan\");\n return"\
  " this;\n }\n analyzeFunctionsWithPreludes() {\n this.call(\"aap\")"\
  ";\n return this;\n }\n analyzeObjCReferences() {\n this.cmd(\"aao\""\
  ");\n return this;\n }\n analyzeImports() {\n this.cmd(\"af @ sym.i"\
  "mp.*\");\n return this;\n }\n searchDisasm(s) {\n const res = this"\
  ".callj(\"/ad \" + s);\n return res;\n }\n searchString(s) {\n const"\
  " res = this.cmdj(\"/j \" + s);\n return res;\n }\n searchBytes(dat"\
  "a) {\n function num2hex(data) {\n return (data & 0xff).toString"\
  "(16);\n }\n const s = data.map(num2hex).join(\"\");\n const res = "\
  "this.cmdj(\"/xj \" + s);\n return res;\n }\n binInfo() {\n try {\n r"\
  "eturn this.cmdj(\"ij~{bin}\");\n }\n catch (e) {\n return {};\n }\n "\
  "}\n \n selectBinary(id) {\n this.call(`ob ${id}`);\n }\n openFile("\
  "name) {\n const ofd = this.call(\"oqq\");\n this.call(`o ${name}`"\
  ");\n const nfd = this.call(\"oqq\");\n if (ofd.trim() === nfd.tri"\
  "m()) {\n return new Error(\"Cannot open file\");\n }\n return pars"\
  "eInt(nfd);\n }\n openFileNomap(name) {\n const ofd = this.call(\""\
  "oqq\");\n this.call(`of ${name}`);\n const nfd = this.call(\"oqq\""\
  ");\n if (ofd.trim() === nfd.trim()) {\n return new Error(\"Canno"\
  "t open file\");\n }\n return parseInt(nfd);\n }\n currentFile(name"\
  ") {\n return (this.call(\"o.\")).trim();\n }\n enumeratePlugins(ty"\
  "pe) {\n switch (type) {\n case \"bin\":\n return this.callj(\"Lij\")"\
  ";\n case \"io\":\n return this.callj(\"Loj\");\n case \"core\":\n retur"\
  "n this.callj(\"Lcj\");\n case \"arch\":\n return this.callj(\"LAj\");"\
  "\n case \"anal\":\n return this.callj(\"Laj\");\n case \"lang\":\n retu"\
  "rn this.callj(\"Llj\");\n }\n return [];\n }\n enumerateModules() {"\
  "\n return this.callj(\"dmmj\");\n }\n enumerateFiles() {\n return t"\
  "his.callj(\"oj\");\n }\n enumerateBinaries() {\n return this.callj"\
  "(\"obj\");\n }\n enumerateMaps() {\n return this.callj(\"omj\");\n }\n"\
  " enumerateClasses() {\n return this.callj(\"icj\");\n }\n enumerat"\
  "eSymbols() {\n return this.callj(\"isj\");\n }\n enumerateExports("\
  ") {\n return this.callj(\"iEj\");\n }\n enumerateImports() {\n retu"\
  "rn this.callj(\"iij\");\n }\n enumerateLibraries() {\n return this"\
  ".callj(\"ilj\");\n }\n enumerateSections() {\n return this.callj(\""\
  "iSj\");\n }\n enumerateSegments() {\n return this.callj(\"iSSj\");\n"\
  " }\n enumerateEntrypoints() {\n return this.callj(\"iej\");\n }\n e"\
  "numerateRelocations() {\n return this.callj(\"irj\");\n }\n enumer"\
  "ateFunctions() {\n return this.cmdj(\"aflj\");\n }\n enumerateFlag"\
  "s() {\n return this.cmdj(\"fj\");\n }\n skip() {\n this.r2.cmd(\"dss"\
  "\");\n }\n ptr(s) {\n return new NativePointer(s, this);\n }\n call"\
  "(s) {\n return this.r2.call(s);\n }\n callj(s) {\n return JSON.pa"\
  "rse(this.call(s));\n }\n cmd(s) {\n return this.r2.cmd(s);\n }\n c"\
  "mdj(s) {\n return JSON.parse(this.cmd(s));\n }\n log(s) {\n retur"\
  "n this.r2.log(s);\n }\n clippy(msg) {\n this.r2.log(this.r2.cmd("\
  "\"?E \" + msg));\n }\n ascii(msg) {\n this.r2.log(this.r2.cmd(\"?ea"\
  " \" + msg));\n }\n}\nexports.R2PapiSync = R2PapiSync;\n\nclass Nati"\
  "veFunction {\n constructor() { }\n}\nexports.NativeFunction = Na"\
  "tiveFunction;\n\nclass NativeCallback {\n constructor() { }\n}\nex"\
  "ports.NativeCallback = NativeCallback;\nclass NativePointer {\n"\
  " constructor(s, api) {\n this.api = api ?? exports.R;\n this.ad"\
  "dr = (\"\" + s).trim();\n }\n filterFlag(name) {\n return this.api"\
  ".call(`fD ${name}`);\n }\n setFlag(name) {\n this.api.call(`f ${"\
  "name}=${this.addr}`);\n }\n unsetFlag() {\n this.api.call(`f-${t"\
  "his.addr}`);\n }\n hexdump(length) {\n const len = length === un"\
  "defined ? \"\" : \"\" + length;\n return this.api.cmd(`x${len}@${t"\
  "his.addr}`);\n }\n functionGraph(format) {\n if (format === \"dot"\
  "\") {\n return this.api.cmd(`agfd@ ${this.addr}`);\n }\n if (form"\
  "at === \"json\") {\n return this.api.cmd(`agfj@${this.addr}`);\n "\
  "}\n if (format === \"mermaid\") {\n return this.api.cmd(`agfm@${t"\
  "his.addr}`);\n }\n return this.api.cmd(`agf@${this.addr}`);\n }\n"\
  " readByteArray(len) {\n return JSON.parse(this.api.cmd(`p8j ${"\
  "len}@${this.addr}`));\n }\n readHexString(len) {\n return (this."\
  "api.cmd(`p8 ${len}@${this.addr}`)).trim();\n }\n and(a) {\n cons"\
  "t addr = this.api.call(`?v ${this.addr} & ${a}`);\n return new"\
  " NativePointer(addr.trim());\n }\n or(a) {\n const addr = this.a"\
  "pi.call(`?v ${this.addr} | ${a}`);\n return new NativePointer("\
  "addr.trim());\n }\n add(a) {\n const addr = this.api.call(`?v ${"\
  "this.addr}+${a}`);\n return new NativePointer(addr);\n }\n sub(a"\
  ") {\n const addr = this.api.call(`?v ${this.addr}-${a}`);\n ret"\
  "urn new NativePointer(addr);\n }\n writeByteArray(data) {\n this"\
  ".api.cmd(\"wx \" + data.join(\"\"));\n return this;\n }\n writeAssem"\
  "bly(instruction) {\n this.api.cmd(`wa ${instruction} @ ${this."\
  "addr}`);\n return this;\n }\n writeCString(s) {\n this.api.call(\""\
  "w \" + s);\n return this;\n }\n writeWideString(s) {\n this.api.ca"\
  "ll(\"ww \" + s);\n return this;\n }\n isNull() {\n return (this.toN"\
  "umber()) == 0;\n }\n compare(a) {\n const bv = typeof a === \"str"\
  "ing\" || typeof a === \"number\"\n ? new NativePointer(a)\n : a;\n "\
  "const dist = r2pipe_js_1.r2.call(`?vi ${this.addr} - ${bv.add"\
  "r}`);\n if (dist[0] === \"-\") {\n return -1;\n }\n if (dist[0] ==="\
  " \"0\") {\n return 0;\n }\n return 1;\n }\n pointsToNull() {\n const "\
  "value = this.readPointer();\n return (value.compare(0)) == 0;\n"\
  " }\n toJSON() {\n const output = this.api.cmd(\"?vi \" + this.add"\
  "r.trim());\n return output.trim();\n }\n toString() {\n return (t"\
  "his.api.cmd(\"?v \" + this.addr.trim())).trim();\n }\n toNumber()"\
  " {\n return parseInt(this.toString());\n }\n writePointer(p) {\n "\
  "}\n readRelativePointer() {\n return this.add(this.readS32());\n"\
  " }\n readPointer() {\n const address = this.api.call(\"pvp@\" + t"\
  "his.addr);\n return new NativePointer(address);\n }\n readS8() {"\
  "\n return parseInt(this.api.cmd(`pv1d@${this.addr}`));\n }\n rea"\
  "dU8() {\n return parseInt(this.api.cmd(`pv1u@${this.addr}`));\n"\
  " }\n readU16() {\n return parseInt(this.api.cmd(`pv2d@${this.ad"\
  "dr}`));\n }\n readU16le() {\n }\n readU16be() {\n }\n readS16() {\n "\
  "}\n readS16le() {\n }\n readS16be() {\n }\n readS32() {\n \n }\n read"\
  "U32() {\n }\n readU32le() {\n }\n readU32be() {\n }\n readU64() {\n "\
  "\n return parseInt(this.api.cmd(`pv8u@${this.addr}`));\n }\n rea"\
  "dU64le() {\n }\n readU64be() {\n }\n writeInt(n) {\n return this.w"\
  "riteU32(n);\n }\n writeU8(n) {\n this.api.cmd(`wv1 ${n}@${this.a"\
  "ddr}`);\n return true;\n }\n writeU16(n) {\n this.api.cmd(`wv2 ${"\
  "n}@${this.addr}`);\n return true;\n }\n writeU16be(n) {\n this.ap"\
  "i.cmd(`wv2 ${n}@${this.addr}@e:cfg.bigendian=true`);\n return "\
  "true;\n }\n writeU16le(n) {\n this.api.cmd(`wv2 ${n}@${this.addr"\
  "}@e:cfg.bigendian=false`);\n return true;\n }\n writeU32(n) {\n t"\
  "his.api.cmd(`wv4 ${n}@${this.addr}`);\n return true;\n }\n write"\
  "U32be(n) {\n this.api.cmd(`wv4 ${n}@${this.addr}@e:cfg.bigendi"\
  "an=true`);\n return true;\n }\n writeU32le(n) {\n this.api.cmd(`w"\
  "v4 ${n}@${this.addr}@e:cfg.bigendian=false`);\n return true;\n "\
  "}\n writeU64(n) {\n this.api.cmd(`wv8 ${n}@${this.addr}`);\n ret"\
  "urn true;\n }\n writeU64be(n) {\n this.api.cmd(`wv8 ${n}@${this."\
  "addr}@e:cfg.bigendian=true`);\n return true;\n }\n writeU64le(n)"\
  " {\n this.api.cmd(`wv8 ${n}@${this.addr}@e:cfg.bigendian=false"\
  "`);\n return true;\n }\n readInt32() {\n return this.readU32();\n "\
  "}\n readCString() {\n const output = this.api.cmd(`pszj@${this."\
  "addr}`);\n return JSON.parse(output).string;\n }\n readWideStrin"\
  "g() {\n const output = this.api.cmd(`pswj@${this.addr}`);\n ret"\
  "urn JSON.parse(output).string;\n }\n readPascalString() {\n cons"\
  "t output = this.api.cmd(`pspj@${this.addr}`);\n return JSON.pa"\
  "rse(output).string;\n }\n instruction() {\n const output = this."\
  "api.cmdj(`aoj@${this.addr}`);\n return output[0];\n }\n disassem"\
  "ble(length) {\n const len = length === undefined ? \"\" : \"\" + l"\
  "ength;\n return this.api.cmd(`pd ${len}@${this.addr}`);\n }\n an"\
  "alyzeFunction() {\n this.api.cmd(\"af@\" + this.addr);\n return t"\
  "his;\n }\n analyzeFunctionRecursively() {\n this.api.cmd(\"afr@\" "\
  "+ this.addr);\n return this;\n }\n name() {\n return (this.api.cm"\
  "d(\"fd \" + this.addr)).trim();\n }\n methodName() {\n \n return (t"\
  "his.api.cmd(\"ic.@\" + this.addr)).trim();\n }\n symbolName() {\n "\
  "\n const name = this.api.cmd(\"isj.@\" + this.addr);\n return nam"\
  "e.trim();\n }\n getFunction() {\n return this.api.cmdj(\"afij@\" +"\
  " this.addr);\n }\n basicBlock() {\n return this.api.cmdj(\"abj@\" "\
  "+ this.addr);\n }\n functionBasicBlocks() {\n return this.api.cm"\
  "dj(\"afbj@\" + this.addr);\n }\n xrefs() {\n return this.api.cmdj("\
  "\"axtj@\" + this.addr);\n }\n}\nexports.NativePointer = NativePoin"\
  "ter;\nvar R2Papi=R2PapiSync;\n";
