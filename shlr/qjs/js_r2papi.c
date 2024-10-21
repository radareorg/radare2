static const char *const js_r2papi_qjs = "" \
  "\"use strict\";\n// shell utilities on top of r2pipe\nObject.defi"\
  "neProperty(exports, \"__esModule\", { value: true });\nexports.R"\
  "2Shell = void 0;\n/**\n * Provides a way to script the interact"\
  "ions with different language models using javascript from ins"\
  "ide radare2.\n *\n * @typedef R2Shell\n */\nclass R2Shell {\n /**\n"\
  " * Create a new instance of the R2Shell\n *\n * @param {R2Papi}"\
  " take the R2Papi intance to used as backend to run the comman"\
  "ds\n * @returns {R2Shell} instance of the shell api\n */\n const"\
  "ructor(papi) {\n this.rp = papi;\n }\n /**\n * Create a new direc"\
  "tory in the host system, if the opational recursive argument "\
  "is set to\n * true it will create all the necessary subdirecto"\
  "ries instead of just the specified one.\n *\n * @param {string}"\
  " text path to the new directory to be created\n * @param {bool"\
  "ean?} disabled by default, but if it's true, it will create s"\
  "ubdirectories recursively if necessary\n * @returns {boolean} "\
  "true if successful\n */\n mkdir(file, recursive) {\n if (recursi"\
  "ve === true) {\n this.rp.call(`mkdir -p ${file}`);\n }\n else {\n"\
  " this.rp.call(`mkdir ${file}`);\n }\n return true;\n }\n /**\n * D"\
  "eletes a file\n *\n * @param {string} path to the file to remov"\
  "e\n * @returns {boolean} true if successful\n */\n unlink(file) "\
  "{\n this.rp.call(`rm ${file}`);\n return true;\n }\n /**\n * Chang"\
  "e current directory\n *\n * @param {string} path to the directo"\
  "ry\n * @returns {boolean} true if successful\n */\n chdir(path) "\
  "{\n this.rp.call(`cd ${path}`);\n return true;\n }\n /**\n * List "\
  "files in the current directory\n *\n * @returns {string[]} arra"\
  "y of file names\n */\n ls() {\n const files = this.rp.call(`ls -"\
  "q`);\n return files.trim().split(\"\\n\");\n }\n /**\n * TODO: Check"\
  "s if a file exists (not implemented)\n *\n * @returns {boolean}"\
  " true if the file exists, false if it does not\n */\n fileExist"\
  "s(path) {\n // TODO\n return false;\n }\n /**\n * Opens an URL or "\
  "application\n * Execute `xdg-open` on linux, `start` on window"\
  "s, `open` on Mac\n *\n * @param {string} URI or file to open by"\
  " the system\n */\n open(arg) {\n this.rp.call(`open ${arg}`);\n }"\
  "\n /**\n * Run a system command and get the return code\n *\n * @"\
  "param {string} system command to be executed\n * @returns {num"\
  "ber} return code (0 is success)\n */\n system(cmd) {\n this.rp.c"\
  "all(`!${cmd}`);\n return 0;\n }\n /**\n * Mount the given offset "\
  "on the specified path using the filesytem.\n * This is not a s"\
  "ystem-level mountpoint, it's using the internal filesystem ab"\
  "straction of radare2.\n *\n * @param {string} filesystem type n"\
  "ame (see .\n * @param {string} system command to be executed\n "\
  "* @param {string|number}\n * @returns {number} return code (0 "\
  "is success)\n */\n mount(fstype, path, offset) {\n if (!offset) "\
  "{\n offset = 0;\n }\n this.rp.call(`m ${fstype} ${path} ${offset"\
  "}`);\n return true;\n }\n /**\n * Unmount the mountpoint associat"\
  "ed with the given path.\n *\n * @param {string} path to the mou"\
  "nted filesystem\n * @returns {void} TODO: should return boolea"\
  "n\n */\n umount(path) {\n this.rp.call(`m-${path}`);\n }\n /**\n * "\
  "Change current directory on the internal radare2 filesystem\n "\
  "*\n * @param {string} path name to change to\n * @returns {void"\
  "} TODO: should return boolean\n */\n chdir2(path) {\n this.rp.ca"\
  "ll(`mdq ${path}`);\n }\n /**\n * List the files contained in the"\
  " given path within the virtual radare2 filesystem.\n *\n * @par"\
  "am {string} path name to change to\n * @returns {void} TODO: s"\
  "hould return boolean\n */\n ls2(path) {\n const files = this.rp."\
  "call(`mdq ${path}`);\n return files.trim().split(\"\\n\");\n }\n /*"\
  "*\n * Enumerate all the mountpoints set in the internal virtua"\
  "l filesystem of radare2\n * @returns {any[]} array of mount\n *"\
  "/\n enumerateFilesystemTypes() {\n return this.rp.cmdj(\"mLj\");\n"\
  " }\n /**\n * Enumerate all the mountpoints set in the internal "\
  "virtual filesystem of radare2\n * @returns {any[]} array of mo"\
  "unt\n */\n enumerateMountpoints() {\n const output = this.rp.cmd"\
  "j(\"mj\");\n return output[\"mountpoints\"];\n }\n /**\n * TODO: not "\
  "implemented\n */\n isSymlink(file) {\n return false;\n }\n /**\n * "\
  "TODO: not implemented\n */\n isDirectory(file) {\n return false;"\
  "\n }\n}\nexports.R2Shell = R2Shell;\n\"use strict\";\nObject.defineP"\
  "roperty(exports, \"__esModule\", { value: true });\nexports.Esil"\
  "Parser = exports.EsilNode = exports.EsilToken = void 0;\n// (\""\
  "this is just a comment\"), -- comments are also part of the ru"\
  "ntime\n/*\n=(\"//\", {\n =(obj, {}())\n =([obj, comment], 32)\n if(e"\
  "q([obj,comment], 32),\n ret()\n )\n ret(obj)\n})\n*/\nclass EsilTok"\
  "en {\n constructor(text = \"\", position = 0) {\n this.label = \"\""\
  ";\n this.comment = \"\";\n this.text = \"\";\n this.addr = \"0\"; // f"\
  "or ut64 we use strings for numbers :<\n this.position = 0;\n th"\
  "is.text = text;\n this.position = position;\n }\n toString() {\n "\
  "return this.text;\n }\n}\nexports.EsilToken = EsilToken;\nclass E"\
  "silNode {\n constructor(token = new EsilToken(), type = \"none\""\
  ") {\n this.type = \"none\";\n this.token = token;\n this.children "\
  "= [];\n }\n setSides(lhs, rhs) {\n this.lhs = lhs;\n this.rhs = r"\
  "hs;\n }\n addChildren(ths, fhs) {\n if (ths !== undefined) {\n th"\
  "is.children.push(ths);\n }\n if (fhs !== undefined) {\n this.chi"\
  "ldren.push(fhs);\n }\n }\n toEsil() {\n if (this.lhs !== undefine"\
  "d && this.rhs !== undefined) {\n // XXX handle ?{ }{ }\n let le"\
  "ft = this.lhs.toEsil();\n if (left !== \"\") {\n left += \",\";\n }\n"\
  " const right = this.rhs.toEsil();\n return `${right},${left}${"\
  "this.token}`;\n }\n return \"\"; // this.token.text;\n }\n toString"\
  "() {\n let str = \"\";\n if (this.token.label !== \"\") {\n str += t"\
  "his.token.label + \":\\n\";\n }\n if (this.token.addr !== \"0\") {\n "\
  "// str += \"// @ \" + this.token.addr + \"\\n\";\n }\n if (this.toke"\
  "n.comment !== \"\") {\n str += \"/*\" + this.token.comment + \"*/\\n"\
  "\";\n }\n if (this.token.toString() === \"GOTO\") {\n if (this.chil"\
  "dren.length > 0) {\n const children = this.children[0];\n str +"\
  "= \"goto label_\" + children.token.position + \";\\n\";\n }\n else {"\
  "\n // console.log(JSON.stringify(this,null, 2));\n const pos = "\
  "0;\n str += `goto label_${pos};\\n`;\n }\n }\n if (this.children.l"\
  "ength > 0) {\n str += ` (if (${this.rhs})\\n`;\n for (const chil"\
  "dren of this.children) {\n if (children !== null) {\n const x ="\
  " children.toString();\n if (x != \"\") {\n str += ` ${x}\\n`;\n }\n "\
  "}\n }\n str += \" )\\n\";\n }\n if (this.lhs !== undefined && this.r"\
  "hs !== undefined) {\n return str + ` ( ${this.lhs} ${this.toke"\
  "n} ${this.rhs} )`;\n // return str + `${this.lhs} ${this.token"\
  "} ${this.rhs}`;\n }\n return str + this.token.toString();\n }\n}\n"\
  "exports.EsilNode = EsilNode;\nclass EsilParser {\n constructor("\
  "r2) {\n this.cur = 0;\n this.r2 = r2;\n this.cur = 0;\n this.stac"\
  "k = [];\n this.nodes = [];\n this.tokens = [];\n this.root = new"\
  " EsilNode(new EsilToken(\"function\", 0), \"block\");\n }\n toJSON("\
  ") {\n if (this.stack.length > 0) {\n // return JSON.stringify ("\
  "this.stack, null, 2);\n throw new Error(\"The ESIL stack is not"\
  " empty\");\n }\n return JSON.stringify(this.root, null, 2);\n }\n "\
  "toEsil() {\n return this.nodes.map((x) => x.toEsil()).join(\",\""\
  ");\n }\n optimizeFlags(node) {\n if (node.rhs !== undefined) {\n "\
  "this.optimizeFlags(node.rhs);\n }\n if (node.lhs !== undefined)"\
  " {\n this.optimizeFlags(node.lhs);\n }\n for (let i = 0; i < nod"\
  "e.children.length; i++) {\n this.optimizeFlags(node.children[i"\
  "]);\n }\n const addr = node.toString();\n if (+addr > 4096) {\n c"\
  "onst cname = r2.cmd(`fd.@ ${addr}`);\n const fname = cname.tri"\
  "m().split(\"\\n\")[0].trim();\n if (fname != \"\" && fname.indexOf("\
  "\"+\") === -1) {\n node.token.text = fname;\n }\n }\n }\n optimize(o"\
  "ptions) {\n if (options.indexOf(\"flag\") != -1) {\n this.optimiz"\
  "eFlags(this.root);\n }\n }\n toString() {\n return this.root.chil"\
  "dren.map((x) => x.toString()).join(\";\\n\");\n }\n reset() {\n thi"\
  "s.nodes = [];\n this.stack = [];\n this.tokens = [];\n this.cur "\
  "= 0;\n this.root = new EsilNode(new EsilToken(\"function\", 0), "\
  "\"block\");\n }\n parseRange(from, to) {\n let pos = from;\n while "\
  "(pos < this.tokens.length && pos < to) {\n const token = this."\
  "peek(pos);\n if (!token) {\n // console.log(\"BREAK\");\n break;\n "\
  "}\n // console.log(pos, token);\n this.cur = pos;\n this.pushTok"\
  "en(token);\n pos = this.cur;\n pos++;\n }\n // console.log(\"done\""\
  ");\n }\n parseFunction(addr) {\n const ep = this;\n function pars"\
  "eAmount(n) {\n // console.log(\"PDQ \"+n);\n const output = r2.cm"\
  "d(\"pie \" + n + \" @e:scr.color=0\");\n const lines = output.trim"\
  "().split(\"\\n\");\n for (const line of lines) {\n if (line.length"\
  " === 0) {\n console.log(\"Empty\");\n continue;\n }\n // console.lo"\
  "g(\"parse\", r2.cmd(\"?v:$$\"));\n const kv = line.split(\" \");\n if"\
  " (kv.length > 1) {\n // line != \"\") {\n // console.log(\"// @ \" "\
  "+ kv[0]);\n //ep.reset ();\n r2.cmd(`s ${kv[0]}`);\n ep.parse(kv"\
  "[1], kv[0]);\n ep.optimize(\"flags,labels\");\n //console.log(ep."\
  "toString());\n }\n }\n // console.log(ep.toString());\n }\n const "\
  "oaddr = (r2.cmd(\"?v $$\")).trim();\n // const func = r2.cmdj(\"p"\
  "drj\"); // XXX this command changes the current seek\n if (addr"\
  " === undefined) {\n addr = oaddr;\n }\n const bbs = r2.cmdj(`afb"\
  "j@${addr}`); // XXX this command changes the current seek\n fo"\
  "r (const bb of bbs) {\n // console.log(\"bb_\" + bb.addr + \":\");"\
  "\n r2.cmd(`s ${bb.addr}`);\n parseAmount(bb.ninstr);\n }\n r2.cmd"\
  "(`s ${oaddr}`);\n }\n parse(expr, addr) {\n const tokens = expr\n"\
  " .trim()\n .split(\",\")\n .map((x) => x.trim());\n const from = t"\
  "his.tokens.length;\n for (const tok of tokens) {\n const token "\
  "= new EsilToken(tok, this.tokens.length);\n if (addr !== undef"\
  "ined) {\n token.addr = addr;\n }\n this.tokens.push(token);\n }\n "\
  "const to = this.tokens.length;\n this.parseRange(from, to);\n }"\
  "\n peek(a) {\n return this.tokens[a];\n }\n pushToken(tok) {\n if "\
  "(this.isNumber(tok)) {\n const node = new EsilNode(tok, \"numbe"\
  "r\");\n this.stack.push(node);\n this.nodes.push(node);\n }\n else"\
  " if (this.isInternal(tok)) {\n const node = new EsilNode(tok, "\
  "\"flag\");\n this.stack.push(node);\n this.nodes.push(node);\n }\n "\
  "else if (this.isOperation(tok)) {\n // run the operation login"\
  "\n }\n else {\n // assume it's a register, so just push the stri"\
  "ng\n const node = new EsilNode(tok, \"register\");\n this.stack.p"\
  "ush(node);\n this.nodes.push(node);\n }\n // we need a list of r"\
  "egister names to do this check properly\n // throw new Error ("\
  "\"Unknown token\");\n }\n isNumber(expr) {\n if (expr.toString().s"\
  "tartsWith(\"0\")) {\n return true;\n }\n return +expr > 0;\n }\n isI"\
  "nternal(expr) {\n const text = expr.toString();\n return text.s"\
  "tartsWith(\"$\") && text.length > 1;\n }\n parseUntil(start) {\n c"\
  "onst from = start + 1;\n let pos = from;\n const origStack = []"\
  ";\n const this_nodes_length = this.nodes.length;\n this.stack.f"\
  "orEach((x) => origStack.push(x));\n while (pos < this.tokens.l"\
  "ength) {\n const token = this.peek(pos);\n if (!token) {\n break"\
  ";\n }\n if (token.toString() === \"}\") {\n break;\n }\n if (token.t"\
  "oString() === \"}{\") {\n // return token;\n break;\n }\n // consol"\
  "e.log(\"peek \", this.tokens[pos]);\n pos++;\n }\n this.stack = or"\
  "igStack;\n const to = pos;\n this.parseRange(from, to);\n const "\
  "same = this.nodes.length == this_nodes_length;\n // console.lo"\
  "g(\"BLOCK (\"+ ep.toString());\n if (same) {\n return null;\n }\n r"\
  "eturn this.nodes[this.nodes.length - 1]; // this.tokens.lengt"\
  "h - 1];\n }\n getNodeFor(index) {\n const tok = this.peek(index)"\
  ";\n if (tok === undefined) {\n return null;\n }\n for (const node"\
  " of this.nodes) {\n if (node.token.position === index) {\n retu"\
  "rn node;\n }\n }\n this.nodes.push(new EsilNode(new EsilToken(\"l"\
  "abel\", index), \"label\"));\n return null;\n }\n findNodeFor(index"\
  ") {\n for (const node of this.nodes) {\n if (node.token.positio"\
  "n === index) {\n return node;\n }\n }\n return null;\n }\n isOperat"\
  "ion(expr) {\n switch (expr.toString()) {\n // 1pop1push\n case \""\
  "[1]\":\n case \"[2]\":\n case \"[4]\":\n case \"[8]\":\n if (this.stack."\
  "length >= 1) {\n const i1 = this.stack.pop();\n // TODO: Memory"\
  "ReferenceNode(i1));\n const mn = new EsilNode(i1.token, \"opera"\
  "tion\"); // expr.toString());\n this.stack.push(i1); // mn);\n }"\
  "\n else {\n throw new Error(\"Stack needs more items\");\n }\n retu"\
  "rn true;\n // 1pop1push\n case \"!\":\n if (this.stack.length >= 1"\
  ") {\n const i0 = new EsilNode(new EsilToken(\"\", expr.position)"\
  ", \"none\");\n const i1 = this.stack.pop();\n const nn = new Esil"\
  "Node(expr, \"operation\");\n nn.setSides(i0, i1);\n this.stack.pu"\
  "sh(nn);\n }\n else {\n throw new Error(\"Stack needs more items\")"\
  ";\n }\n return true;\n case \"\":\n case \"}\":\n case \"}{\":\n // no po"\
  "ps or nothing, just does nothing\n return true;\n case \"DUP\":\n "\
  "if (this.stack.length < 1) {\n throw new Error(\"goto cant pop\""\
  ");\n }\n else {\n const destNode = this.stack.pop();\n this.stack"\
  ".push(destNode);\n this.stack.push(destNode);\n }\n return true;"\
  "\n case \"GOTO\":\n // take previous statement which should be co"\
  "nst and add a label\n {\n const prev = this.peek(expr.position "\
  "- 1);\n if (prev !== null) {\n // TODO: check stack\n if (this.s"\
  "tack.length < 1) {\n throw new Error(\"goto cant pop\");\n }\n con"\
  "st destNode = this.stack.pop();\n if (destNode !== null) {\n co"\
  "nst value = 0 | +destNode.toString();\n if (value > 0) {\n cons"\
  "t destToken = this.peek(value);\n if (destToken !== undefined)"\
  " {\n destToken.label = \"label_\" + value;\n destToken.comment = "\
  "\"hehe\";\n const nn = new EsilNode(expr, \"goto\");\n const gn = t"\
  "his.getNodeFor(destToken.position);\n if (gn != null) {\n nn.ch"\
  "ildren.push(gn);\n }\n this.root.children.push(nn);\n }\n else {\n"\
  " console.error(\"Cannot find goto node\");\n }\n }\n else {\n conso"\
  "le.error(\"Cannot find dest node for goto\");\n }\n }\n }\n }\n retu"\
  "rn true;\n // controlflow\n case \"?{\": // ESIL_TOKEN_IF\n if (th"\
  "is.stack.length >= 1) {\n const i0 = new EsilNode(new EsilToke"\
  "n(\"if\", expr.position), \"none\");\n const i1 = this.stack.pop()"\
  ";\n const nn = new EsilNode(expr, \"operation\");\n nn.setSides(i"\
  "0, i1); // left side can be ignored for now.. but we can expr"\
  "ess this somehow\n const trueBlock = this.parseUntil(expr.posi"\
  "tion);\n let falseBlock = null;\n // nn.addChildren(trueBlock, "\
  "falseBlock);\n if (trueBlock !== null) {\n nn.children.push(tru"\
  "eBlock);\n this.nodes.push(trueBlock);\n falseBlock = this.pars"\
  "eUntil(trueBlock.token.position + 1);\n if (falseBlock !== nul"\
  "l) {\n nn.children.push(falseBlock);\n this.nodes.push(falseBlo"\
  "ck);\n }\n }\n // console.log(\"true\", trueBlock);\n // console.lo"\
  "g(\"false\", falseBlock);\n // this.stack.push(nn);\n this.nodes."\
  "push(nn);\n this.root.children.push(nn);\n if (falseBlock !== n"\
  "ull) {\n this.cur = falseBlock.token.position;\n }\n }\n else {\n "\
  "throw new Error(\"Stack needs more items\");\n }\n return true;\n "\
  "case \"-\":\n if (this.stack.length >= 2) {\n const i0 = this.sta"\
  "ck.pop();\n const i1 = this.stack.pop();\n const nn = new EsilN"\
  "ode(expr, \"operation\");\n nn.setSides(i0, i1);\n if (this.stack"\
  ".length === 0) {\n //\tthis.root.children.push(nn);\n }\n this.st"\
  "ack.push(nn);\n this.nodes.push(nn);\n }\n else {\n throw new Err"\
  "or(\"Stack needs more items\");\n }\n return true;\n // 2pop1push\n"\
  " case \"<\":\n case \">\":\n case \"^\":\n case \"&\":\n case \"|\":\n case "\
  "\"+\":\n case \"*\":\n case \"/\":\n case \">>=\":\n case \"<<=\":\n case \">"\
  ">>=\":\n case \"<<<=\":\n case \">>>>=\":\n case \"<<<<=\":\n if (this.s"\
  "tack.length >= 2) {\n const i0 = this.stack.pop();\n const i1 ="\
  " this.stack.pop();\n const nn = new EsilNode(expr, \"operation\""\
  ");\n nn.setSides(i0, i1);\n if (this.stack.length === 0) {\n //\t"\
  "this.root.children.push(nn);\n }\n this.stack.push(nn);\n this.n"\
  "odes.push(nn);\n }\n else {\n throw new Error(\"Stack needs more "\
  "items\");\n }\n return true;\n // 2pop0push\n case \"=\":\n case \":=\""\
  ":\n case \"-=\":\n case \"+=\":\n case \"==\":\n case \"=[1]\":\n case \"=["\
  "2]\":\n case \"=[4]\":\n case \"=[8]\":\n if (this.stack.length >= 2)"\
  " {\n const i0 = this.stack.pop();\n const i1 = this.stack.pop()"\
  ";\n const nn = new EsilNode(expr, \"operation\");\n nn.setSides(i"\
  "0, i1);\n if (this.stack.length === 0) {\n this.root.children.p"\
  "ush(nn);\n }\n this.nodes.push(nn);\n }\n else {\n throw new Error"\
  "(\"Stack needs more items\");\n }\n return true;\n }\n return false"\
  ";\n }\n}\nexports.EsilParser = EsilParser;\n\"use strict\";\nObject."\
  "defineProperty(exports, \"__esModule\", { value: true });\nexpor"\
  "ts.Base64 = void 0;\nclass Base64 {\n /**\n * Encode the given i"\
  "nput string using base64\n *\n * @param {string} input string t"\
  "o encode\n * @returns {string} base64 encoded string\n */\n stat"\
  "ic encode(input) {\n return (0, exports.b64)(input);\n }\n /**\n "\
  "* Decode the given base64 string into plain text\n *\n * @param"\
  " {string} input string encoded in base64 format\n * @returns {"\
  "string} base64 decoded string\n */\n static decode(input) {\n re"\
  "turn (0, exports.b64)(input, true);\n }\n}\nexports.Base64 = Bas"\
  "e64;\n\"use strict\";\nObject.defineProperty(exports, \"__esModule"\
  "\", { value: true });\nexports.newAsyncR2PipeFromSync = exports"\
  ".R2PipeSyncFromSync = void 0;\nclass R2PipeSyncFromSync {\n con"\
  "structor(r2p) {\n this.r2p = r2p;\n }\n /**\n * Run a command in "\
  "the associated instance of radare2 and return the output as a"\
  " string\n *\n * @param {string} command to be executed inside r"\
  "adare2.\n * @returns {string} The output of the command execut"\
  "ion\n */\n cmd(command) {\n return this.r2p.cmd(command);\n }\n cm"\
  "dAt(command, address) {\n return this.r2p.cmdAt(command, addre"\
  "ss);\n }\n cmdj(cmd) {\n return this.r2p.cmdj(cmd);\n }\n call(com"\
  "mand) {\n return this.r2p.call(command);\n }\n callj(cmd) {\n ret"\
  "urn this.r2p.cmdj(cmd);\n }\n callAt(command, address) {\n retur"\
  "n this.r2p.cmdAt(command, address);\n }\n log(msg) {\n return th"\
  "is.r2p.log(msg);\n }\n plugin(type, maker) {\n return this.r2p.p"\
  "lugin(type, maker);\n }\n unload(type, name) {\n return this.r2p"\
  ".unload(type, name);\n }\n}\nexports.R2PipeSyncFromSync = R2Pipe"\
  "SyncFromSync;\nfunction newAsyncR2PipeFromSync(r2p) {\n const a"\
  "syncR2Pipe = new R2PipeSyncFromSync(r2p);\n return asyncR2Pipe"\
  ";\n}\nexports.newAsyncR2PipeFromSync = newAsyncR2PipeFromSync;\n"\
  "\"use strict\";\nObject.defineProperty(exports, \"__esModule\", { "\
  "value: true });\nexports.R2AI = void 0;\n/**\n * Provides a way "\
  "to script the interactions with different language models usi"\
  "ng javascript from inside radare2.\n *\n * @typedef R2AI\n */\ncl"\
  "ass R2AI {\n constructor(r2, num, model) {\n /**\n * Instance va"\
  "riable that informs if the `r2ai` plugin is loaded, must be t"\
  "rue in order to use the rest of the methods of this class.\n *"\
  "\n * @type {boolean}\n */\n this.available = false;\n /**\n * Name"\
  " of the model instantiated to be used for the subsequent call"\
  "s.\n *\n * @type {string}\n */\n this.model = \"\";\n this.r2 = r2;\n"\
  " this.available = false;\n }\n checkAvailability() {\n if (this."\
  "available) {\n return true;\n }\n this.available = r2pipe_js_1.r"\
  "2.cmd(\"r2ai -h\").trim() !== \"\";\n /*\n if (this.available) {\n i"\
  "f (num) {\n r2.call(`r2ai -n ${num}`)\n }\n // r2.call('r2ai -e "\
  "DEBUG=1')\n if (model) {\n this.model = model;\n }\n }\n */\n retur"\
  "n this.available;\n }\n /**\n * Reset conversation messages\n */\n"\
  " reset() {\n this.checkAvailability();\n if (this.available) {\n"\
  " r2pipe_js_1.r2.call(\"r2ai -R\");\n }\n }\n /**\n * Set the role ("\
  "system prompt) message for the language model to obey.\n *\n * "\
  "@param {string} text containing the system prompt\n * @returns"\
  " {boolean} true if successful\n */\n setRole(msg) {\n if (this.a"\
  "vailable) {\n r2pipe_js_1.r2.call(`r2ai -r ${msg}`);\n return t"\
  "rue;\n }\n return false;\n }\n /**\n * Set the Model name or path "\
  "to the GGUF file to use.\n *\n * @param {string} model name or "\
  "path to GGUF file\n * @returns {boolean} true if successful\n *"\
  "/\n setModel(modelName) {\n if (this.available) {\n r2pipe_js_1."\
  "r2.call(`r2ai -m ${this.model}`);\n return true;\n }\n return fa"\
  "lse;\n }\n /**\n * Get the current selected model name.\n *\n * @r"\
  "eturns {boolean} model name\n */\n getModel() {\n if (this.avail"\
  "able) {\n this.model = r2pipe_js_1.r2.call(\"r2ai -m\").trim();\n"\
  " }\n return this.model;\n }\n /**\n * Get a list of suggestions f"\
  "or model names to use.\n *\n * @returns {string[]} array of str"\
  "ings containing the model names known to work\n */\n listModels"\
  "() {\n if (this.available) {\n const models = r2pipe_js_1.r2.ca"\
  "ll(\"r2ai -M\");\n return models\n .replace(/-m /, \"\")\n .trim()\n "\
  ".split(/\\n/g)\n .filter((x) => x.indexOf(\":\") !== -1);\n }\n ret"\
  "urn [];\n }\n /**\n * Send message to the language model to be a"\
  "ppended to the current conversation (see `.reset()`)\n *\n * @p"\
  "aram {string} text sent from the user to the language model\n "\
  "* @returns {string} response from the language model\n */\n que"\
  "ry(msg) {\n if (!this.available || msg == \"\") {\n return \"\";\n }"\
  "\n const fmsg = msg.trim().replace(/\\n/g, \".\");\n const respons"\
  "e = r2pipe_js_1.r2.call(`r2ai ${fmsg}`);\n return response.tri"\
  "m();\n }\n}\nexports.R2AI = R2AI;\n\"use strict\";\n// main r2papi f"\
  "ile\nObject.defineProperty(exports, \"__esModule\", { value: tru"\
  "e });\nexports.NativePointer = exports.NativeCallback = export"\
  "s.NativeFunction = exports.R2PapiSync = exports.Assembler = e"\
  "xports.ProcessClass = exports.ModuleClass = exports.ThreadCla"\
  "ss = void 0;\nclass ThreadClass {\n constructor(r2) {\n this.api"\
  " = null;\n this.api = r2;\n }\n backtrace() {\n return r2pipe_js_"\
  "1.r2.call(\"dbtj\");\n }\n sleep(seconds) {\n return r2pipe_js_1.r"\
  "2.call(\"sleep \" + seconds);\n }\n}\nexports.ThreadClass = Thread"\
  "Class;\nclass ModuleClass {\n constructor(r2) {\n this.api = nul"\
  "l;\n this.api = r2;\n }\n fileName() {\n return this.api.call(\"dp"\
  "e\").trim();\n }\n name() {\n return \"Module\";\n }\n findBaseAddres"\
  "s() {\n return \"TODO\";\n }\n getBaseAddress(name) {\n return \"TOD"\
  "O\";\n }\n getExportByName(name) {\n const res = r2pipe_js_1.r2.c"\
  "all(\"iE,name/eq/\" + name + \",vaddr/cols,:quiet\");\n return ptr"\
  "(res);\n }\n findExportByName(name) {\n return this.getExportByN"\
  "ame(name);\n }\n enumerateExports() {\n // TODO: adjust to be th"\
  "e same output as Frida\n return r2pipe_js_1.r2.callj(\"iEj\");\n "\
  "}\n enumerateImports() {\n // TODO: adjust to be the same outpu"\
  "t as Frida\n return r2pipe_js_1.r2.callj(\"iij\");\n }\n enumerate"\
  "Symbols() {\n // TODO: adjust to be the same output as Frida\n "\
  "return r2pipe_js_1.r2.callj(\"isj\");\n }\n enumerateEntrypoints("\
  ") {\n // TODO: adjust to be the same output as Frida\n return r"\
  "2pipe_js_1.r2.callj(\"iej\");\n }\n enumerateRanges() {\n // TODO:"\
  " adjust to be the same output as Frida\n return r2pipe_js_1.r2"\
  ".callj(\"omj\");\n }\n}\nexports.ModuleClass = ModuleClass;\nclass "\
  "ProcessClass {\n constructor(r2) {\n this.r2 = null;\n this.r2 ="\
  " r2;\n }\n enumerateMallocRanges() { }\n enumerateSystemRanges()"\
  " { }\n enumerateRanges() { }\n enumerateThreads() {\n return r2p"\
  "ipe_js_1.r2.callj(\"dptj\");\n }\n enumerateModules() {\n r2pipe_j"\
  "s_1.r2.call(\"cfg.json.num=string\"); // to handle 64bit values"\
  " properly\n if (r2pipe_js_1.r2.callj(\"e cfg.debug\")) {\n const "\
  "modules = r2pipe_js_1.r2.callj(\"dmmj\");\n const res = [];\n for"\
  " (const mod of modules) {\n const entry = {\n base: new NativeP"\
  "ointer(mod.addr),\n size: new NativePointer(mod.addr_end).sub("\
  "mod.addr),\n path: mod.file,\n name: mod.name\n };\n res.push(ent"\
  "ry);\n }\n return res;\n }\n else {\n const fname = (x) => {\n cons"\
  "t y = x.split(\"/\");\n return y[y.length - 1];\n };\n const bobjs"\
  " = r2pipe_js_1.r2.callj(\"obj\");\n const res = [];\n for (const "\
  "obj of bobjs) {\n const entry = {\n base: new NativePointer(obj"\
  ".addr),\n size: obj.size,\n path: obj.file,\n name: fname(obj.fi"\
  "le)\n };\n res.push(entry);\n }\n const libs = r2pipe_js_1.r2.cal"\
  "lj(\"ilj\");\n for (const lib of libs) {\n const entry = {\n base:"\
  " 0,\n size: 0,\n path: lib,\n name: fname(lib)\n };\n res.push(ent"\
  "ry);\n }\n return res;\n }\n }\n getModuleByAddress(addr) { }\n get"\
  "ModuleByName(moduleName) { }\n codeSigningPolicy() {\n return \""\
  "optional\";\n }\n getTmpDir() {\n return this.r2.call(\"e dir.tmp\""\
  ").trim();\n }\n getHomeDir() {\n return this.r2.call(\"e dir.home"\
  "\").trim();\n }\n platform() {\n return this.r2.call(\"e asm.os\")."\
  "trim();\n }\n getCurrentDir() {\n return this.r2.call(\"pwd\").tri"\
  "m();\n }\n getCurrentThreadId() {\n return +this.r2.call(\"dpq\");"\
  "\n }\n pageSize() {\n if (this.r2.callj(\"e asm.bits\") === 64 &&\n"\
  " this.r2.call(\"e asm.arch\").startsWith(\"arm\")) {\n return 1638"\
  "4;\n }\n return 4096;\n }\n isDebuggerAttached() {\n return this.r"\
  "2.callj(\"e cfg.debug\");\n }\n setExceptionHandler() {\n // do no"\
  "thing\n }\n id() {\n //\n return this.r2.callj(\"dpq\").trim();\n }\n"\
  " pointerSize() {\n return r2pipe_js_1.r2.callj(\"e asm.bits\") /"\
  " 8;\n }\n}\nexports.ProcessClass = ProcessClass;\n/**\n * Assemble"\
  "r and disassembler facilities to decode and encode instructio"\
  "ns\n *\n * @typedef Assembler\n */\nclass Assembler {\n constructo"\
  "r(myr2) {\n this.program = \"\";\n this.labels = {};\n this.endian"\
  " = false;\n this.pc = ptr(0);\n if (myr2 === undefined) {\n this"\
  ".r2 = (0, r2pipe_js_1.newAsyncR2PipeFromSync)(r2pipe_js_1.r2)"\
  ";\n }\n else {\n this.r2 = myr2;\n }\n this.program = \"\";\n this.la"\
  "bels = {};\n }\n /**\n * Change the address of the program count"\
  "er, some instructions need to know where\n * are they located "\
  "before being encoded or decoded.\n *\n * @param {NativePointerV"\
  "alue}\n */\n setProgramCounter(pc) {\n this.pc = pc;\n }\n setEndi"\
  "an(big) {\n this.endian = big;\n }\n toString() {\n return this.p"\
  "rogram;\n }\n append(x) {\n // append text\n this.pc = this.pc.ad"\
  "d(x.length / 2);\n this.program += x;\n }\n // api\n label(s) {\n "\
  "const pos = this.pc; // this.#program.length / 4;\n this.label"\
  "s[s] = this.pc;\n return pos;\n }\n /**\n * Encode (assemble) an "\
  "instruction by taking the string representation.\n *\n * @param"\
  " {string} the string representation of the instruction to ass"\
  "emble\n * @returns {string} the hexpairs that represent the as"\
  "sembled instruciton\n */\n encode(s) {\n const output = this.r2."\
  "call(`pa ${s}`);\n return output.trim();\n }\n /**\n * Decode (di"\
  "sassemble) an instruction by taking the hexpairs string as in"\
  "put.\n * TODO: should take an array of bytes too\n *\n * @param "\
  "{string} the hexadecimal pairs of bytes to decode as an instr"\
  "uction\n * @returns {string} the mnemonic and operands of the "\
  "resulting decoding\n */\n decode(s) {\n const output = this.r2.c"\
  "all(`pad ${s}`);\n return output.trim();\n }\n}\nexports.Assemble"\
  "r = Assembler;\n/**\n * High level abstraction on top of the r2"\
  " command interface provided by r2pipe.\n *\n * @typedef R2Papi\n"\
  " */\nclass R2PapiSync {\n /**\n * Create a new instance of the R"\
  "2Papi class, taking an r2pipe interface as reference.\n *\n * @"\
  "param {R2PipeSync} the r2pipe instance to use as backend.\n * "\
  "@returns {R2Papi} instance\n */\n constructor(r2) {\n this.r2 = "\
  "r2;\n }\n toString() {\n return \"[object R2Papi]\";\n }\n toJSON() "\
  "{\n return this.toString();\n }\n /**\n * Get the base address us"\
  "ed by the current loaded binary\n *\n * @returns {NativePointer"\
  "} address of the base of the binary\n */\n getBaseAddress() {\n "\
  "const v = this.cmd(\"e bin.baddr\");\n return new NativePointer("\
  "v);\n }\n jsonToTypescript(name, a) {\n let str = `interface ${n"\
  "ame} {\\n`;\n if (a.length && a.length > 0) {\n a = a[0];\n }\n fo"\
  "r (const k of Object.keys(a)) {\n const typ = typeof a[k];\n co"\
  "nst nam = k;\n str += ` ${nam}: ${typ};\\n`;\n }\n return `${str}"\
  "}\\n`;\n }\n /**\n * Get the general purpose register size of the"\
  " targize architecture in bits\n *\n * @returns {number} the reg"\
  "size\n */\n getBits() {\n return +this.cmd(\"-b\");\n }\n /**\n * Get"\
  " the name of the arch plugin selected, which tends to be the "\
  "same target architecture.\n * Note that on some situations, th"\
  "is info will be stored protected bby the AirForce.\n * When us"\
  "ing the r2ghidra arch plugin the underlying arch is in `asm.c"\
  "pu`:\n *\n * @returns {string} the name of the target architect"\
  "ure.\n */\n getArch() {\n return this.cmdTrim(\"-a\");\n }\n callTri"\
  "m(x) {\n const res = this.call(x);\n return res.trim();\n }\n cmd"\
  "Trim(x) {\n const res = this.cmd(x);\n return res.trim();\n }\n /"\
  "**\n * Get the name of the selected CPU for the current select"\
  "ed architecture.\n *\n * @returns {string} the value of asm.cpu"\
  "\n */\n getCpu() {\n // return this.cmd('-c');\n return this.cmdT"\
  "rim(\"-e asm.cpu\"); // use arch.cpu\n }\n // TODO: setEndian, se"\
  "tCpu, ...\n setArch(arch, bits) {\n this.cmd(\"-a \" + arch);\n if"\
  " (bits !== undefined) {\n this.cmd(\"-b \" + bits);\n }\n }\n setFl"\
  "agSpace(name) {\n this.cmd(\"fs \" + name);\n }\n demangleSymbol(l"\
  "ang, mangledName) {\n return this.cmdTrim(\"iD \" + lang + \" \" +"\
  " mangledName);\n }\n setLogLevel(level) {\n this.cmd(\"e log.leve"\
  "l=\" + level);\n }\n /**\n * should return the id for the new map"\
  " using the given file descriptor\n */\n // rename to createMap "\
  "or mapFile?\n newMap(fd, vaddr, size, paddr, perm, name = \"\") "\
  "{\n this.cmd(`om ${fd} ${vaddr} ${size} ${paddr} ${perm} ${nam"\
  "e}`);\n }\n at(a) {\n return new NativePointer(a);\n }\n getShell("\
  ") {\n return new shell_js_1.R2Shell(this);\n }\n // Radare/Frida"\
  "\n version() {\n const v = this.r2.cmd(\"?Vq\");\n return v.trim()"\
  ";\n }\n // Process\n platform() {\n const output = this.r2.cmd(\"u"\
  "name\");\n return output.trim();\n }\n arch() {\n const output = t"\
  "his.r2.cmd(\"uname -a\");\n return output.trim();\n }\n bits() {\n "\
  "const output = this.r2.cmd(\"uname -b\");\n return output.trim()"\
  ";\n }\n id() {\n // getpid();\n return +this.r2.cmd(\"?vi:$p\");\n }"\
  "\n // Other stuff\n printAt(msg, x, y) {\n // see pg, but pg is "\
  "obrken :D\n }\n clearScreen() {\n this.r2.cmd(\"!clear\");\n return"\
  " this;\n }\n getConfig(key) {\n if (key === \"\") {\n return new Er"\
  "ror(\"Empty key\");\n }\n const exist = this.r2.cmd(`e~^${key} =`"\
  ");\n if (exist.trim() === \"\") {\n return new Error(\"Config key "\
  "does not exist\");\n }\n const value = this.r2.call(\"e \" + key);"\
  "\n return value.trim();\n }\n setConfig(key, val) {\n this.r2.cal"\
  "l(\"e \" + key + \"=\" + val);\n return this;\n }\n getRegisterState"\
  "ForEsil() {\n const dre = this.cmdj(\"dre\");\n return this.cmdj("\
  "\"dre\");\n }\n getRegisters() {\n // this.r2.log(\"winrar\" + JSON."\
  "stringify(JSON.parse(this.r2.cmd(\"drj\")),null, 2) );\n return "\
  "this.cmdj(\"drj\");\n }\n resizeFile(newSize) {\n this.cmd(`r ${ne"\
  "wSize}`);\n return this;\n }\n insertNullBytes(newSize, at) {\n i"\
  "f (at === undefined) {\n at = \"$$\";\n }\n this.cmd(`r+${newSize}"\
  "@${at}`);\n return this;\n }\n removeBytes(newSize, at) {\n if (a"\
  "t === undefined) {\n at = \"$$\";\n }\n this.cmd(`r-${newSize}@${a"\
  "t}`);\n return this;\n }\n seek(addr) {\n this.cmd(`s ${addr}`);\n"\
  " return this;\n }\n currentSeek() {\n return new NativePointer(\""\
  "$$\");\n }\n seekToRelativeOpcode(nth) {\n this.cmd(`so ${nth}`);"\
  "\n return this.currentSeek();\n }\n getBlockSize() {\n return +th"\
  "is.cmd(\"b\");\n }\n setBlockSize(a) {\n this.cmd(`b ${a}`);\n retu"\
  "rn this;\n }\n countFlags() {\n return Number(this.cmd(\"f~?\"));\n"\
  " }\n countFunctions() {\n return Number(this.cmd(\"aflc\"));\n }\n "\
  "analyzeFunctionsWithEsil(depth) {\n this.cmd(\"aaef\");\n }\n anal"\
  "yzeProgramWithEsil(depth) {\n this.cmd(\"aae\");\n }\n analyzeProg"\
  "ram(depth) {\n if (depth === undefined) {\n depth = 0;\n }\n swit"\
  "ch (depth) {\n case 0:\n this.cmd(\"aa\");\n break;\n case 1:\n this"\
  ".cmd(\"aaa\");\n break;\n case 2:\n this.cmd(\"aaaa\");\n break;\n cas"\
  "e 3:\n this.cmd(\"aaaaa\");\n break;\n }\n return this;\n }\n enumera"\
  "teThreads() {\n // TODO: use apt/dpt to list threads at iterat"\
  "e over them to get the registers\n const regs0 = this.cmdj(\"dr"\
  "j\");\n const thread0 = {\n context: regs0,\n id: 0,\n state: \"wai"\
  "ting\",\n selected: true\n };\n return [thread0];\n }\n currentThre"\
  "adId() {\n if (+this.cmd(\"e cfg.debug\")) {\n return +this.cmd(\""\
  "dpt.\");\n }\n return this.id();\n }\n setRegisters(obj) {\n for (c"\
  "onst r of Object.keys(obj)) {\n const v = obj[r];\n this.r2.cmd"\
  "(\"dr \" + r + \"=\" + v);\n }\n }\n hex(s) {\n const output = this.r"\
  "2.cmd(\"?v \" + s);\n return output.trim();\n }\n step() {\n this.r"\
  "2.cmd(\"ds\");\n return this;\n }\n stepOver() {\n this.r2.cmd(\"dso"\
  "\");\n return this;\n }\n math(expr) {\n return +this.r2.cmd(\"?v \""\
  " + expr);\n }\n stepUntil(dst) {\n this.cmd(`dsu ${dst}`);\n }\n e"\
  "numerateXrefsTo(s) {\n const output = this.call(\"axtq \" + s);\n"\
  " return output.trim().split(/\\n/);\n }\n // TODO: rename to sea"\
  "rchXrefsTo ?\n findXrefsTo(s, use_esil) {\n if (use_esil) {\n th"\
  "is.call(\"/r \" + s);\n }\n else {\n this.call(\"/re \" + s);\n }\n }\n"\
  " analyzeFunctionsFromCalls() {\n this.call(\"aac\");\n return thi"\
  "s;\n }\n autonameAllFunctions() {\n this.call(\"aan\");\n return th"\
  "is;\n }\n analyzeFunctionsWithPreludes() {\n this.call(\"aap\");\n "\
  "return this;\n }\n analyzeObjCReferences() {\n this.cmd(\"aao\");\n"\
  " return this;\n }\n analyzeImports() {\n this.cmd(\"af @ sym.imp."\
  "*\");\n return this;\n }\n searchDisasm(s) {\n const res = this.ca"\
  "llj(\"/ad \" + s);\n return res;\n }\n searchString(s) {\n const re"\
  "s = this.cmdj(\"/j \" + s);\n return res;\n }\n searchBytes(data) "\
  "{\n function num2hex(data) {\n return (data & 0xff).toString(16"\
  ");\n }\n const s = data.map(num2hex).join(\"\");\n const res = thi"\
  "s.cmdj(\"/xj \" + s);\n return res;\n }\n binInfo() {\n try {\n retu"\
  "rn this.cmdj(\"ij~{bin}\");\n }\n catch (e) {\n return {};\n }\n }\n "\
  "// TODO: take a BinFile as argument instead of number\n select"\
  "Binary(id) {\n this.call(`ob ${id}`);\n }\n openFile(name) {\n co"\
  "nst ofd = this.call(\"oqq\");\n this.call(`o ${name}`);\n const n"\
  "fd = this.call(\"oqq\");\n if (ofd.trim() === nfd.trim()) {\n ret"\
  "urn new Error(\"Cannot open file\");\n }\n return parseInt(nfd);\n"\
  " }\n openFileNomap(name) {\n const ofd = this.call(\"oqq\");\n thi"\
  "s.call(`of ${name}`);\n const nfd = this.call(\"oqq\");\n if (ofd"\
  ".trim() === nfd.trim()) {\n return new Error(\"Cannot open file"\
  "\");\n }\n return parseInt(nfd);\n }\n currentFile(name) {\n const "\
  "v = this.call(\"o.\");\n return v.trim();\n }\n enumeratePlugins(t"\
  "ype) {\n switch (type) {\n case \"bin\":\n return this.callj(\"Lij\""\
  ");\n case \"io\":\n return this.callj(\"Loj\");\n case \"core\":\n retu"\
  "rn this.callj(\"Lcj\");\n case \"arch\":\n return this.callj(\"LAj\")"\
  ";\n case \"anal\":\n return this.callj(\"Laj\");\n case \"lang\":\n ret"\
  "urn this.callj(\"Llj\");\n }\n return [];\n }\n enumerateModules() "\
  "{\n return this.callj(\"dmmj\");\n }\n enumerateFiles() {\n return "\
  "this.callj(\"oj\");\n }\n enumerateBinaries() {\n return this.call"\
  "j(\"obj\");\n }\n enumerateMaps() {\n return this.callj(\"omj\");\n }"\
  "\n enumerateClasses() {\n return this.callj(\"icj\");\n }\n enumera"\
  "teSymbols() {\n return this.callj(\"isj\");\n }\n enumerateExports"\
  "() {\n return this.callj(\"iEj\");\n }\n enumerateImports() {\n ret"\
  "urn this.callj(\"iij\");\n }\n enumerateLibraries() {\n return thi"\
  "s.callj(\"ilj\");\n }\n enumerateSections() {\n return this.callj("\
  "\"iSj\");\n }\n enumerateSegments() {\n return this.callj(\"iSSj\");"\
  "\n }\n enumerateEntrypoints() {\n return this.callj(\"iej\");\n }\n "\
  "enumerateRelocations() {\n return this.callj(\"irj\");\n }\n enume"\
  "rateFunctions() {\n return this.cmdj(\"aflj\");\n }\n enumerateFla"\
  "gs() {\n return this.cmdj(\"fj\");\n }\n skip() {\n this.r2.cmd(\"ds"\
  "s\");\n }\n ptr(s) {\n return new NativePointer(s, this);\n }\n cal"\
  "l(s) {\n return this.r2.call(s);\n }\n callj(s) {\n const v = thi"\
  "s.call(s);\n return JSON.parse(v);\n }\n cmd(s) {\n return this.r"\
  "2.cmd(s);\n }\n cmdj(s) {\n const v = this.cmd(s);\n return JSON."\
  "parse(v);\n }\n log(s) {\n return this.r2.log(s);\n }\n clippy(msg"\
  ") {\n const v = this.r2.cmd(\"?E \" + msg);\n this.r2.log(v);\n }\n"\
  " ascii(msg) {\n const v = this.r2.cmd(\"?ea \" + msg);\n this.r2."\
  "log(v);\n }\n}\nexports.R2PapiSync = R2PapiSync;\n// useful to ca"\
  "ll functions via dxc and to define and describe function sign"\
  "atures\nclass NativeFunction {\n constructor() { }\n}\nexports.Na"\
  "tiveFunction = NativeFunction;\n// uhm not sure how to map thi"\
  "s into r2 yet\nclass NativeCallback {\n constructor() { }\n}\nexp"\
  "orts.NativeCallback = NativeCallback;\n/**\n * Class providing "\
  "a way to work with 64bit pointers from Javascript, this API m"\
  "imics the same\n * well-known promitive available in Frida, bu"\
  "t it's baked by the current session of r2.\n *\n * It is also p"\
  "ossible to use this class via the global `ptr` function.\n *\n "\
  "* @typedef NativePointer\n */\nclass NativePointer {\n construct"\
  "or(s, api) {\n this.api = api ?? exports.R;\n this.addr = (s =="\
  " undefined) ? \"$$\" : (\"\" + s).trim();\n }\n /**\n * Copy N bytes"\
  " from current pointer to the destination\n *\n * @param {string"\
  "|NativePointer|number} destination address\n * @param {string|"\
  "number} amount of bytes\n */\n copyTo(addr, size) {\n this.api.c"\
  "all(`wf ${this.addr} ${size} @ ${addr}`);\n }\n /**\n * Copy N b"\
  "ytes from given address to the current destination\n *\n * @par"\
  "am {string|NativePointer|number} source address\n * @param {st"\
  "ring|number} amount of bytes\n */\n copyFrom(addr, size) {\n thi"\
  "s.api.call(`wf ${addr} ${size} @ ${this.addr}`);\n }\n /**\n * F"\
  "ill N bytes in this address with zero\n *\n * @param {string|nu"\
  "mber} amount of bytes\n */\n zeroFill(size) {\n this.api.call(`w"\
  "0 ${size} @ ${this.addr}`);\n }\n /**\n * Filter a string to be "\
  "used as a valid flag name\n *\n * @param {string} name of the s"\
  "ymbol name\n * @returns {string} filtered name to be used as a"\
  " flag\n */\n filterFlag(name) {\n return this.api.call(`fD ${nam"\
  "e}`);\n }\n /**\n * Set a flag (name) at the offset pointed\n *\n "\
  "* @param {string} name of the flag to set\n * @returns {string"\
  "} base64 decoded string\n */\n setFlag(name) {\n this.api.call(`"\
  "f ${name}=${this.addr}`);\n }\n /**\n * Remove the flag in the c"\
  "urrent offset\n *\n */\n unsetFlag() {\n this.api.call(`f-${this."\
  "addr}`);\n }\n /**\n * Render an hexadecimal dump of the bytes c"\
  "ontained in the range starting\n * in the current pointer and "\
  "given length.\n *\n * @param {number} length optional amount of"\
  " bytes to dump, using blocksize\n * @returns {string} string c"\
  "ontaining the hexadecimal dump of memory\n */\n hexdump(length)"\
  " {\n const len = length === undefined ? \"\" : \"\" + length;\n ret"\
  "urn this.api.cmd(`x${len}@${this.addr}`);\n }\n functionGraph(f"\
  "ormat) {\n if (format === \"dot\") {\n return this.api.cmd(`agfd@"\
  " ${this.addr}`);\n }\n if (format === \"json\") {\n return this.ap"\
  "i.cmd(`agfj@${this.addr}`);\n }\n if (format === \"mermaid\") {\n "\
  "return this.api.cmd(`agfm@${this.addr}`);\n }\n return this.api"\
  ".cmd(`agf@${this.addr}`);\n }\n readByteArray(len) {\n const v ="\
  " this.api.cmd(`p8j ${len}@${this.addr}`);\n return JSON.parse("\
  "v);\n }\n readHexString(len) {\n const v = this.api.cmd(`p8 ${le"\
  "n}@${this.addr}`);\n return v.trim();\n }\n and(a) {\n const addr"\
  " = this.api.call(`?v ${this.addr} & ${a}`);\n return new Nativ"\
  "ePointer(addr.trim());\n }\n or(a) {\n const addr = this.api.cal"\
  "l(`?v ${this.addr} | ${a}`);\n return new NativePointer(addr.t"\
  "rim());\n }\n add(a) {\n const addr = this.api.call(`?v ${this.a"\
  "ddr}+${a}`);\n return new NativePointer(addr);\n }\n sub(a) {\n c"\
  "onst addr = this.api.call(`?v ${this.addr}-${a}`);\n return ne"\
  "w NativePointer(addr);\n }\n writeByteArray(data) {\n this.api.c"\
  "md(\"wx \" + data.join(\"\"));\n return this;\n }\n writeAssembly(in"\
  "struction) {\n this.api.cmd(`wa ${instruction} @ ${this.addr}`"\
  ");\n return this;\n }\n writeCString(s) {\n this.api.call(\"w \" + "\
  "s);\n return this;\n }\n writeWideString(s) {\n this.api.call(\"ww"\
  " \" + s);\n return this;\n }\n /**\n * Check if it's a pointer to "\
  "the address zero. Also known as null pointer.\n *\n * @returns "\
  "{boolean} true if null\n */\n isNull() {\n const v = this.toNumb"\
  "er();\n return v === 0;\n }\n /**\n * Compare current pointer wit"\
  "h the passed one, and return -1, 0 or 1.\n *\n * * if (this < a"\
  "rg) return -1;\n * * if (this > arg) return 1;\n * * if (this ="\
  "= arg) return 0;\n *\n * @returns {number} returns -1, 0 or 1 d"\
  "epending on the comparison of the pointers\n */\n compare(a) {\n"\
  " const bv = typeof a === \"string\" || typeof a === \"number\"\n ?"\
  " new NativePointer(a)\n : a;\n const dist = r2pipe_js_1.r2.call"\
  "(`?vi ${this.addr} - ${bv.addr}`);\n if (dist[0] === \"-\") {\n r"\
  "eturn -1;\n }\n if (dist[0] === \"0\") {\n return 0;\n }\n return 1;"\
  "\n }\n /**\n * Check if it's a pointer to the address zero. Also"\
  " known as null pointer.\n *\n * @returns {boolean} true if null"\
  "\n */\n pointsToNull() {\n const value = this.readPointer();\n co"\
  "nst v = value.compare(0);\n return v == 0;\n }\n toJSON() {\n con"\
  "st output = this.api.cmd(\"?vi \" + this.addr.trim());\n return "\
  "output.trim();\n }\n toString() {\n const v = this.api.cmd(\"?v \""\
  " + this.addr.trim());\n return v.trim();\n }\n toNumber() {\n con"\
  "st v = this.toString();\n return parseInt(v);\n }\n writePointer"\
  "(p) {\n }\n readRelativePointer() {\n const v = this.readS32();\n"\
  " return this.add(v);\n }\n readPointer() {\n const address = thi"\
  "s.api.call(\"pvp@\" + this.addr);\n return new NativePointer(add"\
  "ress);\n }\n readS8() {\n const v = this.api.cmd(`pv1d@${this.ad"\
  "dr}`);\n return parseInt(v);\n }\n readU8() {\n const v = this.ap"\
  "i.cmd(`pv1u@${this.addr}`);\n return parseInt(v);\n }\n readU16("\
  ") {\n const v = this.api.cmd(`pv2d@${this.addr}`);\n return par"\
  "seInt(v);\n }\n readU16le() {\n const v = this.api.cmd(`pv2d@${t"\
  "his.addr}@e:cfg.bigendian=false`);\n }\n readU16be() {\n const v"\
  " = this.api.cmd(`pv2d@${this.addr}@e:cfg.bigendian=true`);\n }"\
  "\n readS16() {\n return parseInt(v);\n }\n readS16le() {\n const v"\
  " = this.api.cmd(`pv2d@${this.addr}@e:cfg.bigendian=false`);\n "\
  "}\n readS16be() {\n const v = this.api.cmd(`pv2d@${this.addr}@e"\
  ":cfg.bigendian=true`);\n }\n readS32() {\n const v = this.api.cm"\
  "d(`pv4d@${this.addr}`);\n return parseInt(v);\n }\n readU32() {\n"\
  " const v = this.api.cmd(`pv4u@${this.addr}`);\n return parseIn"\
  "t(v);\n }\n readU32le() {\n const v = this.api.cmd(`pv4u@${this."\
  "addr}@e:cfg.bigendian=false`);\n }\n readU32be() {\n const v = t"\
  "his.api.cmd(`pv4u@${this.addr}@e:cfg.bigendian=true`);\n }\n re"\
  "adU64() {\n // XXX: use bignum or string here\n const v = this."\
  "api.cmd(`pv8u@${this.addr}`);\n return parseInt(v);\n }\n readU6"\
  "4le() {\n const v = this.api.cmd(`pv8u@${this.addr}@e:cfg.bige"\
  "ndian=false`);\n }\n readU64be() {\n const v = this.api.cmd(`pv8"\
  "u@${this.addr}@e:cfg.bigendian=true`);\n }\n writeInt(n) {\n ret"\
  "urn this.writeU32(n);\n }\n /**\n * Write a byte in the current "\
  "offset, the value must be between 0 and 255\n *\n * @param {str"\
  "ing} n number to write in the pointed byte in the current add"\
  "ress\n * @returns {boolean} false if the operation failed\n */\n"\
  " writeU8(n) {\n this.api.cmd(`wv1 ${n}@${this.addr}`);\n return"\
  " true;\n }\n writeU16(n) {\n this.api.cmd(`wv2 ${n}@${this.addr}"\
  "`);\n return true;\n }\n writeU16be(n) {\n this.api.cmd(`wv2 ${n}"\
  "@${this.addr}@e:cfg.bigendian=true`);\n return true;\n }\n write"\
  "U16le(n) {\n this.api.cmd(`wv2 ${n}@${this.addr}@e:cfg.bigendi"\
  "an=false`);\n return true;\n }\n writeU32(n) {\n this.api.cmd(`wv"\
  "4 ${n}@${this.addr}`);\n return true;\n }\n writeU32be(n) {\n thi"\
  "s.api.cmd(`wv4 ${n}@${this.addr}@e:cfg.bigendian=true`);\n ret"\
  "urn true;\n }\n writeU32le(n) {\n this.api.cmd(`wv4 ${n}@${this."\
  "addr}@e:cfg.bigendian=false`);\n return true;\n }\n writeU64(n) "\
  "{\n this.api.cmd(`wv8 ${n}@${this.addr}`);\n return true;\n }\n w"\
  "riteU64be(n) {\n this.api.cmd(`wv8 ${n}@${this.addr}@e:cfg.big"\
  "endian=true`);\n return true;\n }\n writeU64le(n) {\n this.api.cm"\
  "d(`wv8 ${n}@${this.addr}@e:cfg.bigendian=false`);\n return tru"\
  "e;\n }\n readInt32() {\n return this.readU32();\n }\n readCString("\
  ") {\n const output = this.api.cmd(`pszj@${this.addr}`);\n retur"\
  "n JSON.parse(output).string;\n }\n readWideString() {\n const ou"\
  "tput = this.api.cmd(`pswj@${this.addr}`);\n return JSON.parse("\
  "output).string;\n }\n readPascalString() {\n const output = this"\
  ".api.cmd(`pspj@${this.addr}`);\n return JSON.parse(output).str"\
  "ing;\n }\n instruction() {\n const output = this.api.cmdj(`aoj@$"\
  "{this.addr}`);\n return output[0];\n }\n disassemble(length) {\n "\
  "const len = length === undefined ? \"\" : \"\" + length;\n return "\
  "this.api.cmd(`pd ${len}@${this.addr}`);\n }\n analyzeFunction()"\
  " {\n this.api.cmd(\"af@\" + this.addr);\n return this;\n }\n analyz"\
  "eFunctionRecursively() {\n this.api.cmd(\"afr@\" + this.addr);\n "\
  "return this;\n }\n name() {\n const v = this.api.cmd(\"fd \" + thi"\
  "s.addr);\n return v.trim();\n }\n methodName() {\n // TODO: @ sho"\
  "uld be optional here, as addr should be passable as argument "\
  "imho\n const v = this.api.cmd(\"ic.@\" + this.addr);\n return v.t"\
  "rim();\n }\n symbolName() {\n // TODO: @ should be optional here"\
  ", as addr should be passable as argument imho\n const name = t"\
  "his.api.cmd(\"isj.@\" + this.addr);\n return name.trim();\n }\n ge"\
  "tFunction() {\n return this.api.cmdj(\"afij@\" + this.addr);\n }\n"\
  " basicBlock() {\n return this.api.cmdj(\"abj@\" + this.addr);\n }"\
  "\n functionBasicBlocks() {\n return this.api.cmdj(\"afbj@\" + thi"\
  "s.addr);\n }\n xrefs() {\n return this.api.cmdj(\"axtj@\" + this.a"\
  "ddr);\n }\n}\nexports.NativePointer = NativePointer;\nvar R2Papi="\
  "R2PapiSync;\n";
