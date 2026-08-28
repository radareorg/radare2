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
  "is success)\n */\n mount(fstype, path, addr) {\n if (!addr) {\n a"\
  "ddr = 0;\n }\n this.rp.call(`m ${fstype} ${path} ${addr}`);\n re"\
  "turn true;\n }\n /**\n * Unmount the mountpoint associated with "\
  "the given path.\n *\n * @param {string} path to the mounted fil"\
  "esystem\n * @returns {void} TODO: should return boolean\n */\n u"\
  "mount(path) {\n this.rp.call(`m-${path}`);\n }\n /**\n * Change c"\
  "urrent directory on the internal radare2 filesystem\n *\n * @pa"\
  "ram {string} path name to change to\n * @returns {void} TODO: "\
  "should return boolean\n */\n chdir2(path) {\n this.rp.call(`mdq "\
  "${path}`);\n }\n /**\n * List the files contained in the given p"\
  "ath within the virtual radare2 filesystem.\n *\n * @param {stri"\
  "ng} path name to change to\n * @returns {void} TODO: should re"\
  "turn boolean\n */\n ls2(path) {\n const files = this.rp.call(`md"\
  "q ${path}`);\n return files.trim().split(\"\\n\");\n }\n /**\n * Enu"\
  "merate all the mountpoints set in the internal virtual filesy"\
  "stem of radare2\n * @returns {any[]} array of mount\n */\n enume"\
  "rateFilesystemTypes() {\n return this.rp.cmdj(\"mLj\");\n }\n /**\n"\
  " * Enumerate all the mountpoints set in the internal virtual "\
  "filesystem of radare2\n * @returns {any[]} array of mount\n */\n"\
  " enumerateMountpoints() {\n const output = this.rp.cmdj(\"mj\");"\
  "\n return output[\"mountpoints\"];\n }\n /**\n * TODO: not implemen"\
  "ted\n */\n isSymlink(file) {\n return false;\n }\n /**\n * TODO: no"\
  "t implemented\n */\n isDirectory(file) {\n return false;\n }\n}\nex"\
  "ports.R2Shell = R2Shell;\n\"use strict\";\nObject.defineProperty("\
  "exports, \"__esModule\", { value: true });\nexports.EsilParser ="\
  " exports.EsilNode = exports.EsilToken = void 0;\n// (\"this is "\
  "just a comment\"), -- comments are also part of the runtime\n/*"\
  "\n=(\"//\", {\n =(obj, {}())\n =([obj, comment], 32)\n if(eq([obj,c"\
  "omment], 32),\n ret()\n )\n ret(obj)\n})\n*/\nclass EsilToken {\n co"\
  "nstructor(text = \"\", position = 0) {\n this.label = \"\";\n this."\
  "comment = \"\";\n this.text = \"\";\n this.addr = \"0\"; // for ut64 "\
  "we use strings for numbers :<\n this.position = 0;\n this.text "\
  "= text;\n this.position = position;\n }\n toString() {\n return t"\
  "his.text;\n }\n}\nexports.EsilToken = EsilToken;\nclass EsilNode "\
  "{\n constructor(token = new EsilToken(), type = \"none\") {\n thi"\
  "s.type = \"none\";\n this.token = token;\n this.children = [];\n }"\
  "\n setSides(lhs, rhs) {\n this.lhs = lhs;\n this.rhs = rhs;\n }\n "\
  "addChildren(ths, fhs) {\n if (ths !== undefined) {\n this.child"\
  "ren.push(ths);\n }\n if (fhs !== undefined) {\n this.children.pu"\
  "sh(fhs);\n }\n }\n toEsil() {\n if (this.lhs !== undefined && thi"\
  "s.rhs !== undefined) {\n // XXX handle ?{ }{ }\n let left = thi"\
  "s.lhs.toEsil();\n if (left !== \"\") {\n left += \",\";\n }\n const r"\
  "ight = this.rhs.toEsil();\n return `${right},${left}${this.tok"\
  "en}`;\n }\n return \"\"; // this.token.text;\n }\n toString() {\n le"\
  "t str = \"\";\n if (this.token.label !== \"\") {\n str += this.toke"\
  "n.label + \":\\n\";\n }\n if (this.token.addr !== \"0\") {\n // str +"\
  "= \"// @ \" + this.token.addr + \"\\n\";\n }\n if (this.token.commen"\
  "t !== \"\") {\n str += \"/*\" + this.token.comment + \"*/\\n\";\n }\n i"\
  "f (this.token.toString() === \"GOTO\") {\n if (this.children.len"\
  "gth > 0) {\n const children = this.children[0];\n str += \"goto "\
  "label_\" + children.token.position + \";\\n\";\n }\n else {\n // con"\
  "sole.log(JSON.stringify(this,null, 2));\n const pos = 0;\n str "\
  "+= `goto label_${pos};\\n`;\n }\n }\n if (this.children.length > "\
  "0) {\n str += ` (if (${this.rhs})\\n`;\n for (const children of "\
  "this.children) {\n if (children !== null) {\n const x = childre"\
  "n.toString();\n if (x != \"\") {\n str += ` ${x}\\n`;\n }\n }\n }\n st"\
  "r += \" )\\n\";\n }\n if (this.lhs !== undefined && this.rhs !== u"\
  "ndefined) {\n return str + ` ( ${this.lhs} ${this.token} ${thi"\
  "s.rhs} )`;\n // return str + `${this.lhs} ${this.token} ${this"\
  ".rhs}`;\n }\n return str + this.token.toString();\n }\n}\nexports."\
  "EsilNode = EsilNode;\nclass EsilParser {\n constructor(r2) {\n t"\
  "his.cur = 0;\n this.r2 = r2;\n this.cur = 0;\n this.stack = [];\n"\
  " this.nodes = [];\n this.tokens = [];\n this.root = new EsilNod"\
  "e(new EsilToken(\"function\", 0), \"block\");\n }\n toJSON() {\n if "\
  "(this.stack.length > 0) {\n // return JSON.stringify (this.sta"\
  "ck, null, 2);\n throw new Error(\"The ESIL stack is not empty\")"\
  ";\n }\n return JSON.stringify(this.root, null, 2);\n }\n toEsil()"\
  " {\n return this.nodes.map((x) => x.toEsil()).join(\",\");\n }\n o"\
  "ptimizeFlags(node) {\n if (node.rhs !== undefined) {\n this.opt"\
  "imizeFlags(node.rhs);\n }\n if (node.lhs !== undefined) {\n this"\
  ".optimizeFlags(node.lhs);\n }\n for (let i = 0; i < node.childr"\
  "en.length; i++) {\n this.optimizeFlags(node.children[i]);\n }\n "\
  "const addr = node.toString();\n if (+addr > 4096) {\n const cna"\
  "me = r2.cmd(`fd.@ ${addr}`);\n const fname = cname.trim().spli"\
  "t(\"\\n\")[0].trim();\n if (fname != \"\" && fname.indexOf(\"+\") ==="\
  " -1) {\n node.token.text = fname;\n }\n }\n }\n optimize(options) "\
  "{\n if (options.indexOf(\"flag\") != -1) {\n this.optimizeFlags(t"\
  "his.root);\n }\n }\n toString() {\n return this.root.children.map"\
  "((x) => x.toString()).join(\";\\n\");\n }\n reset() {\n this.nodes "\
  "= [];\n this.stack = [];\n this.tokens = [];\n this.cur = 0;\n th"\
  "is.root = new EsilNode(new EsilToken(\"function\", 0), \"block\")"\
  ";\n }\n parseRange(from, to) {\n let pos = from;\n while (pos < t"\
  "his.tokens.length && pos < to) {\n const token = this.peek(pos"\
  ");\n if (!token) {\n // console.log(\"BREAK\");\n break;\n }\n // co"\
  "nsole.log(pos, token);\n this.cur = pos;\n this.pushToken(token"\
  ");\n pos = this.cur;\n pos++;\n }\n // console.log(\"done\");\n }\n p"\
  "arseFunction(addr) {\n const ep = this;\n function parseAmount("\
  "n) {\n // console.log(\"PDQ \"+n);\n const output = r2.cmd(\"pie \""\
  " + n + \" @e:scr.color=0\");\n const lines = output.trim().split"\
  "(\"\\n\");\n for (const line of lines) {\n if (line.length === 0) "\
  "{\n console.log(\"Empty\");\n continue;\n }\n // console.log(\"parse"\
  "\", r2.cmd(\"?v:$$\"));\n const kv = line.split(\" \");\n if (kv.len"\
  "gth > 1) {\n // line != \"\") {\n // console.log(\"// @ \" + kv[0])"\
  ";\n //ep.reset ();\n r2.cmd(`s ${kv[0]}`);\n ep.parse(kv[1], kv["\
  "0]);\n ep.optimize(\"flags,labels\");\n //console.log(ep.toString"\
  "());\n }\n }\n // console.log(ep.toString());\n }\n const oaddr = "\
  "(r2.cmd(\"?v $$\")).trim();\n // const func = r2.cmdj(\"pdrj\"); /"\
  "/ XXX this command changes the current seek\n if (addr === und"\
  "efined) {\n addr = oaddr;\n }\n const bbs = r2.cmdj(`afbj@${addr"\
  "}`); // XXX this command changes the current seek\n for (const"\
  " bb of bbs) {\n // console.log(\"bb_\" + bb.addr + \":\");\n r2.cmd"\
  "(`s ${bb.addr}`);\n parseAmount(bb.ninstr);\n }\n r2.cmd(`s ${oa"\
  "ddr}`);\n }\n parse(expr, addr) {\n const tokens = expr\n .trim()"\
  "\n .split(\",\")\n .map((x) => x.trim());\n const from = this.toke"\
  "ns.length;\n for (const tok of tokens) {\n const token = new Es"\
  "ilToken(tok, this.tokens.length);\n if (addr !== undefined) {\n"\
  " token.addr = addr;\n }\n this.tokens.push(token);\n }\n const to"\
  " = this.tokens.length;\n this.parseRange(from, to);\n }\n peek(a"\
  ") {\n return this.tokens[a];\n }\n pushToken(tok) {\n if (this.is"\
  "Number(tok)) {\n const node = new EsilNode(tok, \"number\");\n th"\
  "is.stack.push(node);\n this.nodes.push(node);\n }\n else if (thi"\
  "s.isInternal(tok)) {\n const node = new EsilNode(tok, \"flag\");"\
  "\n this.stack.push(node);\n this.nodes.push(node);\n }\n else if "\
  "(this.isOperation(tok)) {\n // run the operation login\n }\n els"\
  "e {\n // assume it's a register, so just push the string\n cons"\
  "t node = new EsilNode(tok, \"register\");\n this.stack.push(node"\
  ");\n this.nodes.push(node);\n }\n // we need a list of register "\
  "names to do this check properly\n // throw new Error (\"Unknown"\
  " token\");\n }\n isNumber(expr) {\n if (expr.toString().startsWit"\
  "h(\"0\")) {\n return true;\n }\n return +expr > 0;\n }\n isInternal("\
  "expr) {\n const text = expr.toString();\n return text.startsWit"\
  "h(\"$\") && text.length > 1;\n }\n parseUntil(start) {\n const fro"\
  "m = start + 1;\n let pos = from;\n const origStack = [];\n const"\
  " this_nodes_length = this.nodes.length;\n this.stack.forEach(("\
  "x) => origStack.push(x));\n while (pos < this.tokens.length) {"\
  "\n const token = this.peek(pos);\n if (!token) {\n break;\n }\n if"\
  " (token.toString() === \"}\") {\n break;\n }\n if (token.toString("\
  ") === \"}{\") {\n // return token;\n break;\n }\n // console.log(\"p"\
  "eek \", this.tokens[pos]);\n pos++;\n }\n this.stack = origStack;"\
  "\n const to = pos;\n this.parseRange(from, to);\n const same = t"\
  "his.nodes.length == this_nodes_length;\n // console.log(\"BLOCK"\
  " (\"+ ep.toString());\n if (same) {\n return null;\n }\n return th"\
  "is.nodes[this.nodes.length - 1]; // this.tokens.length - 1];\n"\
  " }\n getNodeFor(index) {\n const tok = this.peek(index);\n if (t"\
  "ok === undefined) {\n return null;\n }\n for (const node of this"\
  ".nodes) {\n if (node.token.position === index) {\n return node;"\
  "\n }\n }\n this.nodes.push(new EsilNode(new EsilToken(\"label\", i"\
  "ndex), \"label\"));\n return null;\n }\n findNodeFor(index) {\n for"\
  " (const node of this.nodes) {\n if (node.token.position === in"\
  "dex) {\n return node;\n }\n }\n return null;\n }\n isOperation(expr"\
  ") {\n switch (expr.toString()) {\n // 1pop1push\n case \"[1]\":\n c"\
  "ase \"[2]\":\n case \"[4]\":\n case \"[8]\":\n if (this.stack.length >"\
  "= 1) {\n const i1 = this.stack.pop();\n // TODO: MemoryReferenc"\
  "eNode(i1));\n const mn = new EsilNode(i1.token, \"operation\"); "\
  "// expr.toString());\n this.stack.push(i1); // mn);\n }\n else {"\
  "\n throw new Error(\"Stack needs more items\");\n }\n return true;"\
  "\n // 1pop1push\n case \"!\":\n if (this.stack.length >= 1) {\n con"\
  "st i0 = new EsilNode(new EsilToken(\"\", expr.position), \"none\""\
  ");\n const i1 = this.stack.pop();\n const nn = new EsilNode(exp"\
  "r, \"operation\");\n nn.setSides(i0, i1);\n this.stack.push(nn);\n"\
  " }\n else {\n throw new Error(\"Stack needs more items\");\n }\n re"\
  "turn true;\n case \"\":\n case \"}\":\n case \"}{\":\n // no pops or no"\
  "thing, just does nothing\n return true;\n case \"DUP\":\n if (this"\
  ".stack.length < 1) {\n throw new Error(\"goto cant pop\");\n }\n e"\
  "lse {\n const destNode = this.stack.pop();\n this.stack.push(de"\
  "stNode);\n this.stack.push(destNode);\n }\n return true;\n case \""\
  "GOTO\":\n // take previous statement which should be const and "\
  "add a label\n {\n const prev = this.peek(expr.position - 1);\n i"\
  "f (prev !== null) {\n // TODO: check stack\n if (this.stack.len"\
  "gth < 1) {\n throw new Error(\"goto cant pop\");\n }\n const destN"\
  "ode = this.stack.pop();\n if (destNode !== null) {\n const valu"\
  "e = 0 | +destNode.toString();\n if (value > 0) {\n const destTo"\
  "ken = this.peek(value);\n if (destToken !== undefined) {\n dest"\
  "Token.label = \"label_\" + value;\n destToken.comment = \"hehe\";\n"\
  " const nn = new EsilNode(expr, \"goto\");\n const gn = this.getN"\
  "odeFor(destToken.position);\n if (gn != null) {\n nn.children.p"\
  "ush(gn);\n }\n this.root.children.push(nn);\n }\n else {\n console"\
  ".error(\"Cannot find goto node\");\n }\n }\n else {\n console.error"\
  "(\"Cannot find dest node for goto\");\n }\n }\n }\n }\n return true;"\
  "\n // controlflow\n case \"?{\": // ESIL_TOKEN_IF\n if (this.stack"\
  ".length >= 1) {\n const i0 = new EsilNode(new EsilToken(\"if\", "\
  "expr.position), \"none\");\n const i1 = this.stack.pop();\n const"\
  " nn = new EsilNode(expr, \"operation\");\n nn.setSides(i0, i1); "\
  "// left side can be ignored for now.. but we can express this"\
  " somehow\n const trueBlock = this.parseUntil(expr.position);\n "\
  "let falseBlock = null;\n // nn.addChildren(trueBlock, falseBlo"\
  "ck);\n if (trueBlock !== null) {\n nn.children.push(trueBlock);"\
  "\n this.nodes.push(trueBlock);\n falseBlock = this.parseUntil(t"\
  "rueBlock.token.position + 1);\n if (falseBlock !== null) {\n nn"\
  ".children.push(falseBlock);\n this.nodes.push(falseBlock);\n }\n"\
  " }\n // console.log(\"true\", trueBlock);\n // console.log(\"false"\
  "\", falseBlock);\n // this.stack.push(nn);\n this.nodes.push(nn)"\
  ";\n this.root.children.push(nn);\n if (falseBlock !== null) {\n "\
  "this.cur = falseBlock.token.position;\n }\n }\n else {\n throw ne"\
  "w Error(\"Stack needs more items\");\n }\n return true;\n case \"-\""\
  ":\n if (this.stack.length >= 2) {\n const i0 = this.stack.pop()"\
  ";\n const i1 = this.stack.pop();\n const nn = new EsilNode(expr"\
  ", \"operation\");\n nn.setSides(i0, i1);\n if (this.stack.length "\
  "=== 0) {\n //\tthis.root.children.push(nn);\n }\n this.stack.push"\
  "(nn);\n this.nodes.push(nn);\n }\n else {\n throw new Error(\"Stac"\
  "k needs more items\");\n }\n return true;\n // 2pop1push\n case \"<"\
  "\":\n case \">\":\n case \"^\":\n case \"&\":\n case \"|\":\n case \"+\":\n ca"\
  "se \"*\":\n case \"/\":\n case \">>=\":\n case \"<<=\":\n case \">>>=\":\n c"\
  "ase \"<<<=\":\n case \">>>>=\":\n case \"<<<<=\":\n if (this.stack.len"\
  "gth >= 2) {\n const i0 = this.stack.pop();\n const i1 = this.st"\
  "ack.pop();\n const nn = new EsilNode(expr, \"operation\");\n nn.s"\
  "etSides(i0, i1);\n if (this.stack.length === 0) {\n //\tthis.roo"\
  "t.children.push(nn);\n }\n this.stack.push(nn);\n this.nodes.pus"\
  "h(nn);\n }\n else {\n throw new Error(\"Stack needs more items\");"\
  "\n }\n return true;\n // 2pop0push\n case \"=\":\n case \":=\":\n case "\
  "\"-=\":\n case \"+=\":\n case \"==\":\n case \"=[1]\":\n case \"=[2]\":\n ca"\
  "se \"=[4]\":\n case \"=[8]\":\n if (this.stack.length >= 2) {\n cons"\
  "t i0 = this.stack.pop();\n const i1 = this.stack.pop();\n const"\
  " nn = new EsilNode(expr, \"operation\");\n nn.setSides(i0, i1);\n"\
  " if (this.stack.length === 0) {\n this.root.children.push(nn);"\
  "\n }\n this.nodes.push(nn);\n }\n else {\n throw new Error(\"Stack "\
  "needs more items\");\n }\n return true;\n }\n return false;\n }\n}\ne"\
  "xports.EsilParser = EsilParser;\n\"use strict\";\nObject.definePr"\
  "operty(exports, \"__esModule\", { value: true });\nexports.Base6"\
  "4 = void 0;\nclass Base64 {\n /**\n * Encode the given input str"\
  "ing using base64\n *\n * @param {string} input string to encode"\
  "\n * @returns {string} base64 encoded string\n */\n static encod"\
  "e(input) {\n return (0, exports.b64)(input);\n }\n /**\n * Decode"\
  " the given base64 string into plain text\n *\n * @param {string"\
  "} input string encoded in base64 format\n * @returns {string} "\
  "base64 decoded string\n */\n static decode(input) {\n return (0,"\
  " exports.b64)(input, true);\n }\n}\nexports.Base64 = Base64;\n\"us"\
  "e strict\";\nObject.defineProperty(exports, \"__esModule\", { val"\
  "ue: true });\nexports.newAsyncR2PipeFromSync = exports.R2PipeS"\
  "yncFromSync = void 0;\nclass R2PipeSyncFromSync {\n constructor"\
  "(r2p) {\n this.r2p = r2p;\n }\n /**\n * Run a command in the asso"\
  "ciated instance of radare2 and return the output as a string\n"\
  " *\n * @param {string} command to be executed inside radare2.\n"\
  " * @returns {string} The output of the command execution\n */\n"\
  " cmd(command) {\n return this.r2p.cmd(command);\n }\n cmdAt(comm"\
  "and, address) {\n return this.r2p.cmdAt(command, address);\n }\n"\
  " cmdj(cmd) {\n return this.r2p.cmdj(cmd);\n }\n call(command) {\n"\
  " return this.r2p.call(command);\n }\n callj(cmd) {\n return this"\
  ".r2p.cmdj(cmd);\n }\n callAt(command, address) {\n return this.r"\
  "2p.cmdAt(command, address);\n }\n log(msg) {\n return this.r2p.l"\
  "og(msg);\n }\n plugin(type, maker) {\n return this.r2p.plugin(ty"\
  "pe, maker);\n }\n unload(type, name) {\n return this.r2p.unload("\
  "type, name);\n }\n}\nexports.R2PipeSyncFromSync = R2PipeSyncFrom"\
  "Sync;\nfunction newAsyncR2PipeFromSync(r2p) {\n const asyncR2Pi"\
  "pe = new R2PipeSyncFromSync(r2p);\n return asyncR2Pipe;\n}\nexpo"\
  "rts.newAsyncR2PipeFromSync = newAsyncR2PipeFromSync;\n\"use str"\
  "ict\";\nObject.defineProperty(exports, \"__esModule\", { value: t"\
  "rue });\nexports.R2AI = void 0;\n/**\n * Provides a way to scrip"\
  "t the interactions with different language models using javas"\
  "cript from inside radare2.\n *\n * @typedef R2AI\n */\nclass R2AI"\
  " {\n constructor(r2, num, model) {\n /**\n * Instance variable t"\
  "hat informs if the `r2ai` plugin is loaded, must be true in o"\
  "rder to use the rest of the methods of this class.\n *\n * @typ"\
  "e {boolean}\n */\n this.available = false;\n /**\n * Name of the "\
  "model instantiated to be used for the subsequent calls.\n *\n *"\
  " @type {string}\n */\n this.model = \"\";\n this.r2 = r2;\n this.av"\
  "ailable = false;\n }\n checkAvailability() {\n if (this.availabl"\
  "e) {\n return true;\n }\n this.available = r2pipe_js_1.r2.cmd(\"r"\
  "2ai -h\").trim() !== \"\";\n /*\n if (this.available) {\n if (num) "\
  "{\n r2.call(`r2ai -n ${num}`)\n }\n // r2.call('r2ai -e DEBUG=1'"\
  ")\n if (model) {\n this.model = model;\n }\n }\n */\n return this.a"\
  "vailable;\n }\n /**\n * Reset conversation messages\n */\n reset()"\
  " {\n this.checkAvailability();\n if (this.available) {\n r2pipe_"\
  "js_1.r2.call(\"r2ai -R\");\n }\n }\n /**\n * Set the role (system p"\
  "rompt) message for the language model to obey.\n *\n * @param {"\
  "string} text containing the system prompt\n * @returns {boolea"\
  "n} true if successful\n */\n setRole(msg) {\n if (this.available"\
  ") {\n r2pipe_js_1.r2.call(`r2ai -r ${msg}`);\n return true;\n }\n"\
  " return false;\n }\n /**\n * Set the Model name or path to the G"\
  "GUF file to use.\n *\n * @param {string} model name or path to "\
  "GGUF file\n * @returns {boolean} true if successful\n */\n setMo"\
  "del(modelName) {\n if (this.available) {\n r2pipe_js_1.r2.call("\
  "`r2ai -m ${this.model}`);\n return true;\n }\n return false;\n }\n"\
  " /**\n * Get the current selected model name.\n *\n * @returns {"\
  "boolean} model name\n */\n getModel() {\n if (this.available) {\n"\
  " this.model = r2pipe_js_1.r2.call(\"r2ai -m\").trim();\n }\n retu"\
  "rn this.model;\n }\n /**\n * Get a list of suggestions for model"\
  " names to use.\n *\n * @returns {string[]} array of strings con"\
  "taining the model names known to work\n */\n listModels() {\n if"\
  " (this.available) {\n const models = r2pipe_js_1.r2.call(\"r2ai"\
  " -M\");\n return models\n .replace(/-m /, \"\")\n .trim()\n .split(/"\
  "\\n/g)\n .filter((x) => x.indexOf(\":\") !== -1);\n }\n return [];\n"\
  " }\n /**\n * Send message to the language model to be appended "\
  "to the current conversation (see `.reset()`)\n *\n * @param {st"\
  "ring} text sent from the user to the language model\n * @retur"\
  "ns {string} response from the language model\n */\n query(msg) "\
  "{\n if (!this.available || msg == \"\") {\n return \"\";\n }\n const "\
  "fmsg = msg.trim().replace(/\\n/g, \".\");\n const response = r2pi"\
  "pe_js_1.r2.call(`r2ai ${fmsg}`);\n return response.trim();\n }\n"\
  "}\nexports.R2AI = R2AI;\n\"use strict\";\n// main r2papi file\nObje"\
  "ct.defineProperty(exports, \"__esModule\", { value: true });\nex"\
  "ports.NativePointer = exports.NativeCallback = exports.Native"\
  "Function = exports.R2PapiSync = exports.Assembler = exports.P"\
  "rocessClass = exports.ModuleClass = exports.ThreadClass = voi"\
  "d 0;\nclass ThreadClass {\n constructor(r2) {\n this.api = null;"\
  "\n this.api = r2;\n }\n backtrace() {\n return r2pipe_js_1.r2.cal"\
  "l(\"dbtj\");\n }\n sleep(seconds) {\n return r2pipe_js_1.r2.call(\""\
  "sleep \" + seconds);\n }\n}\nexports.ThreadClass = ThreadClass;\nc"\
  "lass ModuleClass {\n constructor(r2) {\n this.api = null;\n this"\
  ".api = r2;\n }\n fileName() {\n return this.api.call(\"dpe\").trim"\
  "();\n }\n name() {\n return \"Module\";\n }\n findBaseAddress() {\n r"\
  "eturn \"TODO\";\n }\n getBaseAddress(name) {\n return \"TODO\";\n }\n "\
  "getExportByName(name) {\n const res = r2pipe_js_1.r2.call(\"iE,"\
  "name/eq/\" + name + \",vaddr/cols,:quiet\");\n return ptr(res);\n "\
  "}\n findExportByName(name) {\n return this.getExportByName(name"\
  ");\n }\n enumerateExports() {\n // TODO: adjust to be the same o"\
  "utput as Frida\n return r2pipe_js_1.r2.callj(\"iEj\");\n }\n enume"\
  "rateImports() {\n // TODO: adjust to be the same output as Fri"\
  "da\n return r2pipe_js_1.r2.callj(\"iij\");\n }\n enumerateSymbols("\
  ") {\n // TODO: adjust to be the same output as Frida\n return r"\
  "2pipe_js_1.r2.callj(\"isj\");\n }\n enumerateEntrypoints() {\n // "\
  "TODO: adjust to be the same output as Frida\n return r2pipe_js"\
  "_1.r2.callj(\"iej\");\n }\n enumerateRanges() {\n // TODO: adjust "\
  "to be the same output as Frida\n return r2pipe_js_1.r2.callj(\""\
  "omj\");\n }\n}\nexports.ModuleClass = ModuleClass;\nclass ProcessC"\
  "lass {\n constructor(r2) {\n this.r2 = null;\n this.r2 = r2;\n }\n"\
  " enumerateMallocRanges() { }\n enumerateSystemRanges() { }\n en"\
  "umerateRanges() { }\n enumerateThreads() {\n return r2pipe_js_1"\
  ".r2.callj(\"dptj\");\n }\n enumerateModules() {\n r2pipe_js_1.r2.c"\
  "all(\"cfg.json.num=string\"); // to handle 64bit values properl"\
  "y\n if (r2pipe_js_1.r2.callj(\"e cfg.debug\")) {\n const modules "\
  "= r2pipe_js_1.r2.callj(\"dmmj\");\n const res = [];\n for (const "\
  "mod of modules) {\n const entry = {\n base: new NativePointer(m"\
  "od.addr),\n size: new NativePointer(mod.addr_end).sub(mod.addr"\
  "),\n path: mod.file,\n name: mod.name\n };\n res.push(entry);\n }\n"\
  " return res;\n }\n else {\n const fname = (x) => {\n const y = x."\
  "split(\"/\");\n return y[y.length - 1];\n };\n const bobjs = r2pip"\
  "e_js_1.r2.callj(\"obj\");\n const res = [];\n for (const obj of b"\
  "objs) {\n const entry = {\n base: new NativePointer(obj.addr),\n"\
  " size: obj.size,\n path: obj.file,\n name: fname(obj.file)\n };\n"\
  " res.push(entry);\n }\n const libs = r2pipe_js_1.r2.callj(\"ilj\""\
  ");\n for (const lib of libs) {\n const entry = {\n base: 0,\n siz"\
  "e: 0,\n path: lib,\n name: fname(lib)\n };\n res.push(entry);\n }\n"\
  " return res;\n }\n }\n getModuleByAddress(addr) { }\n getModuleBy"\
  "Name(moduleName) { }\n codeSigningPolicy() {\n return \"optional"\
  "\";\n }\n getTmpDir() {\n return this.r2.call(\"e dir.tmp\").trim()"\
  ";\n }\n getHomeDir() {\n return this.r2.call(\"e dir.home\").trim("\
  ");\n }\n platform() {\n return this.r2.call(\"e asm.os\").trim();\n"\
  " }\n getCurrentDir() {\n return this.r2.call(\"pwd\").trim();\n }\n"\
  " getCurrentThreadId() {\n return +this.r2.call(\"dpq\");\n }\n pag"\
  "eSize() {\n if (this.r2.callj(\"e asm.bits\") === 64 &&\n this.r2"\
  ".call(\"e asm.arch\").startsWith(\"arm\")) {\n return 16384;\n }\n r"\
  "eturn 4096;\n }\n isDebuggerAttached() {\n return this.r2.callj("\
  "\"e cfg.debug\");\n }\n setExceptionHandler() {\n // do nothing\n }"\
  "\n id() {\n //\n return this.r2.callj(\"dpq\").trim();\n }\n pointer"\
  "Size() {\n return r2pipe_js_1.r2.callj(\"e asm.bits\") / 8;\n }\n}"\
  "\nexports.ProcessClass = ProcessClass;\n/**\n * Assembler and di"\
  "sassembler facilities to decode and encode instructions\n *\n *"\
  " @typedef Assembler\n */\nclass Assembler {\n constructor(myr2) "\
  "{\n this.program = \"\";\n this.labels = {};\n this.endian = false"\
  ";\n this.pc = ptr(0);\n if (myr2 === undefined) {\n this.r2 = (0"\
  ", r2pipe_js_1.newAsyncR2PipeFromSync)(r2pipe_js_1.r2);\n }\n el"\
  "se {\n this.r2 = myr2;\n }\n this.program = \"\";\n this.labels = {"\
  "};\n }\n /**\n * Change the address of the program counter, some"\
  " instructions need to know where\n * are they located before b"\
  "eing encoded or decoded.\n *\n * @param {NativePointerValue}\n *"\
  "/\n setProgramCounter(pc) {\n this.pc = pc;\n }\n setEndian(big) "\
  "{\n this.endian = big;\n }\n toString() {\n return this.program;\n"\
  " }\n append(x) {\n // append text\n this.pc = this.pc.add(x.leng"\
  "th / 2);\n this.program += x;\n }\n // api\n label(s) {\n const po"\
  "s = this.pc; // this.#program.length / 4;\n this.labels[s] = t"\
  "his.pc;\n return pos;\n }\n /**\n * Encode (assemble) an instruct"\
  "ion by taking the string representation.\n *\n * @param {string"\
  "} the string representation of the instruction to assemble\n *"\
  " @returns {string} the hexpairs that represent the assembled "\
  "instruciton\n */\n encode(s) {\n const output = this.r2.call(`pa"\
  " ${s}`);\n return output.trim();\n }\n /**\n * Decode (disassembl"\
  "e) an instruction by taking the hexpairs string as input.\n * "\
  "TODO: should take an array of bytes too\n *\n * @param {string}"\
  " the hexadecimal pairs of bytes to decode as an instruction\n "\
  "* @returns {string} the mnemonic and operands of the resultin"\
  "g decoding\n */\n decode(s) {\n const output = this.r2.call(`pad"\
  " ${s}`);\n return output.trim();\n }\n}\nexports.Assembler = Asse"\
  "mbler;\n/**\n * High level abstraction on top of the r2 command"\
  " interface provided by r2pipe.\n *\n * @typedef R2Papi\n */\nclas"\
  "s R2PapiSync {\n /**\n * Create a new instance of the R2Papi cl"\
  "ass, taking an r2pipe interface as reference.\n *\n * @param {R"\
  "2PipeSync} the r2pipe instance to use as backend.\n * @returns"\
  " {R2Papi} instance\n */\n constructor(r2) {\n this.r2 = r2;\n }\n "\
  "toString() {\n return \"[object R2Papi]\";\n }\n toJSON() {\n retur"\
  "n this.toString();\n }\n /**\n * Get the base address used by th"\
  "e current loaded binary\n *\n * @returns {NativePointer} addres"\
  "s of the base of the binary\n */\n getBaseAddress() {\n const v "\
  "= this.cmd(\"e bin.baddr\");\n return new NativePointer(v, this)"\
  ";\n }\n jsonToTypescript(name, a) {\n let str = `interface ${nam"\
  "e} {\\n`;\n if (a.length && a.length > 0) {\n a = a[0];\n }\n for "\
  "(const k of Object.keys(a)) {\n const typ = typeof a[k];\n cons"\
  "t nam = k;\n str += ` ${nam}: ${typ};\\n`;\n }\n return `${str}}\\"\
  "n`;\n }\n /**\n * Get the general purpose register size of the t"\
  "argize architecture in bits\n *\n * @returns {number} the regsi"\
  "ze\n */\n getBits() {\n return +this.cmd(\"-b\");\n }\n /**\n * Get t"\
  "he name of the arch plugin selected, which tends to be the sa"\
  "me target architecture.\n * Note that on some situations, this"\
  " info will be stored protected bby the AirForce.\n * When usin"\
  "g the r2ghidra arch plugin the underlying arch is in `asm.cpu"\
  "`:\n *\n * @returns {string} the name of the target architectur"\
  "e.\n */\n getArch() {\n return this.cmdTrim(\"-a\");\n }\n callTrim("\
  "x) {\n const res = this.call(x);\n return res.trim();\n }\n cmdTr"\
  "im(x) {\n const res = this.cmd(x);\n return res.trim();\n }\n /**"\
  "\n * Get the name of the selected CPU for the current selected"\
  " architecture.\n *\n * @returns {string} the value of asm.cpu\n "\
  "*/\n getCpu() {\n // return this.cmd('-c');\n return this.cmdTri"\
  "m(\"-e asm.cpu\"); // use arch.cpu\n }\n // TODO: setEndian, setC"\
  "pu, ...\n setArch(arch, bits) {\n this.cmd(\"-a \" + arch);\n if ("\
  "bits !== undefined) {\n this.cmd(\"-b \" + bits);\n }\n }\n setFlag"\
  "Space(name) {\n this.cmd(\"fs \" + name);\n }\n demangleSymbol(lan"\
  "g, mangledName) {\n return this.cmdTrim(\"iD \" + lang + \" \" + m"\
  "angledName);\n }\n setLogLevel(level) {\n this.cmd(\"e log.level="\
  "\" + level);\n }\n /**\n * should return the id for the new map u"\
  "sing the given file descriptor\n */\n // rename to createMap or"\
  " mapFile?\n newMap(fd, vaddr, size, paddr, perm, name = \"\") {\n"\
  " this.cmd(`om ${fd} ${vaddr} ${size} ${paddr} ${perm} ${name}"\
  "`);\n }\n at(a) {\n return new NativePointer(a, this);\n }\n getSh"\
  "ell() {\n return new shell_js_1.R2Shell(this);\n }\n // Radare/F"\
  "rida\n version() {\n const v = this.r2.cmd(\"?Vq\");\n return v.tr"\
  "im();\n }\n // Process\n platform() {\n const output = this.r2.cm"\
  "d(\"uname\");\n return output.trim();\n }\n arch() {\n const output"\
  " = this.r2.cmd(\"uname -a\");\n return output.trim();\n }\n bits()"\
  " {\n const output = this.r2.cmd(\"uname -b\");\n return output.tr"\
  "im();\n }\n id() {\n // getpid();\n return +this.r2.cmd(\"?vi:$p\")"\
  ";\n }\n // Other stuff\n printAt(msg, x, y) {\n // see pg, but pg"\
  " is obrken :D\n }\n clearScreen() {\n this.r2.cmd(\"!clear\");\n re"\
  "turn this;\n }\n getConfig(key) {\n if (key === \"\") {\n return ne"\
  "w Error(\"Empty key\");\n }\n const exist = this.r2.cmd(`e~^${key"\
  "} =`);\n if (exist.trim() === \"\") {\n return new Error(\"Config "\
  "key does not exist\");\n }\n const value = this.r2.call(\"e \" + k"\
  "ey);\n return value.trim();\n }\n setConfig(key, val) {\n this.r2"\
  ".call(\"e \" + key + \"=\" + val);\n return this;\n }\n getRegisterS"\
  "tateForEsil() {\n const dre = this.cmdj(\"dre\");\n return this.c"\
  "mdj(\"dre\");\n }\n getRegisters() {\n // this.r2.log(\"winrar\" + J"\
  "SON.stringify(JSON.parse(this.r2.cmd(\"drj\")),null, 2) );\n ret"\
  "urn this.cmdj(\"drj\");\n }\n resizeFile(newSize) {\n this.cmd(`r "\
  "${newSize}`);\n return this;\n }\n insertNullBytes(newSize, at) "\
  "{\n if (at === undefined) {\n at = \"$$\";\n }\n this.cmd(`r+${newS"\
  "ize}@${at}`);\n return this;\n }\n removeBytes(newSize, at) {\n i"\
  "f (at === undefined) {\n at = \"$$\";\n }\n this.cmd(`r-${newSize}"\
  "@${at}`);\n return this;\n }\n seek(addr) {\n this.cmd(`s ${addr}"\
  "`);\n return this;\n }\n currentSeek() {\n return new NativePoint"\
  "er(\"$$\", this);\n }\n seekToRelativeOpcode(nth) {\n this.cmd(`so"\
  " ${nth}`);\n return this.currentSeek();\n }\n getBlockSize() {\n "\
  "return +this.cmd(\"b\");\n }\n setBlockSize(a) {\n this.cmd(`b ${a"\
  "}`);\n return this;\n }\n countFlags() {\n return Number(this.cmd"\
  "(\"f~?\"));\n }\n countFunctions() {\n return Number(this.cmd(\"afl"\
  "c\"));\n }\n analyzeFunctionsWithEsil(depth) {\n this.cmd(\"aaef\")"\
  ";\n }\n analyzeProgramWithEsil(depth) {\n this.cmd(\"aae\");\n }\n a"\
  "nalyzeProgram(depth) {\n if (depth === undefined) {\n depth = 0"\
  ";\n }\n switch (depth) {\n case 0:\n this.cmd(\"aa\");\n break;\n cas"\
  "e 1:\n this.cmd(\"aaa\");\n break;\n case 2:\n this.cmd(\"aaaa\");\n b"\
  "reak;\n case 3:\n this.cmd(\"aaaaa\");\n break;\n }\n return this;\n "\
  "}\n enumerateThreads() {\n // TODO: use apt/dpt to list threads"\
  " at iterate over them to get the registers\n const regs0 = thi"\
  "s.cmdj(\"drj\");\n const thread0 = {\n context: regs0,\n id: 0,\n s"\
  "tate: \"waiting\",\n selected: true\n };\n return [thread0];\n }\n c"\
  "urrentThreadId() {\n if (+this.cmd(\"e cfg.debug\")) {\n return +"\
  "this.cmd(\"dpt.\");\n }\n return this.id();\n }\n setRegisters(obj)"\
  " {\n for (const r of Object.keys(obj)) {\n const v = obj[r];\n t"\
  "his.r2.cmd(\"dr \" + r + \"=\" + v);\n }\n }\n hex(s) {\n const outpu"\
  "t = this.r2.cmd(\"?v \" + s);\n return output.trim();\n }\n step()"\
  " {\n this.r2.cmd(\"ds\");\n return this;\n }\n stepOver() {\n this.r"\
  "2.cmd(\"dso\");\n return this;\n }\n math(expr) {\n return +this.r2"\
  ".cmd(\"?v \" + expr);\n }\n stepUntil(dst) {\n this.cmd(`dsu ${dst"\
  "}`);\n }\n enumerateXrefsTo(s) {\n const output = this.call(\"axt"\
  "q \" + s);\n return output.trim().split(/\\n/);\n }\n // TODO: ren"\
  "ame to searchXrefsTo ?\n findXrefsTo(s, use_esil) {\n if (use_e"\
  "sil) {\n this.call(\"/r \" + s);\n }\n else {\n this.call(\"/re \" + "\
  "s);\n }\n }\n analyzeFunctionsFromCalls() {\n this.call(\"aac\");\n "\
  "return this;\n }\n autonameAllFunctions() {\n this.call(\"aan\");\n"\
  " return this;\n }\n analyzeFunctionsWithPreludes() {\n this.call"\
  "(\"aap\");\n return this;\n }\n analyzeObjCReferences() {\n this.cm"\
  "d(\"aao\");\n return this;\n }\n analyzeImports() {\n this.cmd(\"af "\
  "@ sym.imp.*\");\n return this;\n }\n searchDisasm(s) {\n const res"\
  " = this.callj(\"/ad \" + s);\n return res;\n }\n searchString(s) {"\
  "\n const res = this.cmdj(\"/j \" + s);\n return res;\n }\n searchBy"\
  "tes(data) {\n function num2hex(data) {\n return (data & 0xff).t"\
  "oString(16);\n }\n const s = data.map(num2hex).join(\"\");\n const"\
  " res = this.cmdj(\"/xj \" + s);\n return res;\n }\n binInfo() {\n t"\
  "ry {\n return this.cmdj(\"ij~{bin}\");\n }\n catch (e) {\n return {"\
  "};\n }\n }\n // TODO: take a BinFile as argument instead of numb"\
  "er\n selectBinary(id) {\n this.call(`ob ${id}`);\n }\n openFile(n"\
  "ame) {\n const ofd = this.call(\"oqq\");\n this.call(`o ${name}`)"\
  ";\n const nfd = this.call(\"oqq\");\n if (ofd.trim() === nfd.trim"\
  "()) {\n return new Error(\"Cannot open file\");\n }\n return parse"\
  "Int(nfd);\n }\n openFileNomap(name) {\n const ofd = this.call(\"o"\
  "qq\");\n this.call(`of ${name}`);\n const nfd = this.call(\"oqq\")"\
  ";\n if (ofd.trim() === nfd.trim()) {\n return new Error(\"Cannot"\
  " open file\");\n }\n return parseInt(nfd);\n }\n currentFile(name)"\
  " {\n const v = this.call(\"o.\");\n return v.trim();\n }\n enumerat"\
  "ePlugins(type) {\n switch (type) {\n case \"bin\":\n return this.c"\
  "allj(\"Lij\");\n case \"io\":\n return this.callj(\"Loj\");\n case \"co"\
  "re\":\n return this.callj(\"Lcj\");\n case \"arch\":\n return this.ca"\
  "llj(\"LAj\");\n case \"anal\":\n return this.callj(\"Laj\");\n case \"l"\
  "ang\":\n return this.callj(\"Llj\");\n }\n return [];\n }\n enumerate"\
  "Modules() {\n return this.callj(\"dmmj\");\n }\n enumerateFiles() "\
  "{\n return this.callj(\"oj\");\n }\n enumerateBinaries() {\n return"\
  " this.callj(\"obj\");\n }\n enumerateMaps() {\n return this.callj("\
  "\"omj\");\n }\n enumerateClasses() {\n return this.callj(\"icj\");\n "\
  "}\n enumerateSymbols() {\n return this.callj(\"isj\");\n }\n enumer"\
  "ateExports() {\n return this.callj(\"iEj\");\n }\n enumerateImport"\
  "s() {\n return this.callj(\"iij\");\n }\n enumerateLibraries() {\n "\
  "return this.callj(\"ilj\");\n }\n enumerateSections() {\n return t"\
  "his.callj(\"iSj\");\n }\n enumerateSegments() {\n return this.call"\
  "j(\"iSSj\");\n }\n enumerateEntrypoints() {\n return this.callj(\"i"\
  "ej\");\n }\n enumerateRelocations() {\n return this.callj(\"irj\");"\
  "\n }\n enumerateFunctions() {\n return this.cmdj(\"aflj\");\n }\n en"\
  "umerateFlags() {\n return this.cmdj(\"fj\");\n }\n skip() {\n this."\
  "r2.cmd(\"dss\");\n }\n ptr(s) {\n return new NativePointer(s, this"\
  ");\n }\n call(s) {\n return this.r2.call(s);\n }\n callj(s) {\n con"\
  "st v = this.call(s);\n return JSON.parse(v);\n }\n cmd(s) {\n ret"\
  "urn this.r2.cmd(s);\n }\n cmdj(s) {\n const v = this.cmd(s);\n re"\
  "turn JSON.parse(v);\n }\n log(s) {\n return this.r2.log(s);\n }\n "\
  "clippy(msg) {\n const v = this.r2.cmd(\"?E \" + msg);\n this.r2.l"\
  "og(v);\n }\n ascii(msg) {\n const v = this.r2.cmd(\"?ea \" + msg);"\
  "\n this.r2.log(v);\n }\n}\nexports.R2PapiSync = R2PapiSync;\n// us"\
  "eful to call functions via dxc and to define and describe fun"\
  "ction signatures\nclass NativeFunction {\n constructor() { }\n}\n"\
  "exports.NativeFunction = NativeFunction;\n// uhm not sure how "\
  "to map this into r2 yet\nclass NativeCallback {\n constructor()"\
  " { }\n}\nexports.NativeCallback = NativeCallback;\nfunction clam"\
  "pByte(n) {\n return n & 0xff;\n}\nfunction byteToHex(n) {\n retur"\
  "n clampByte(n).toString(16).padStart(2, \"0\");\n}\nfunction byte"\
  "ArrayToHex(data) {\n let hex = \"\";\n for (let i = 0; i < data.l"\
  "ength; i++) {\n hex += byteToHex(data[i]);\n }\n return hex;\n}\nf"\
  "unction normalizeHexString(hex) {\n const normalized = hex.rep"\
  "lace(/0x/gi, \"\").replace(/\\s+/g, \"\");\n if (normalized.length "\
  "% 2 !== 0) {\n throw new Error(\"Hex string must contain an eve"\
  "n number of digits\");\n }\n return normalized.toLowerCase();\n}\n"\
  "function bytesToUnsignedBigInt(bytes, littleEndian) {\n const "\
  "ordered = littleEndian ? [...bytes].reverse() : bytes;\n let v"\
  "alue = 0n;\n for (const byte of ordered) {\n value = (value << "\
  "8n) | BigInt(clampByte(byte));\n }\n return value;\n}\nfunction b"\
  "ytesToSignedBigInt(bytes, littleEndian) {\n const unsigned = b"\
  "ytesToUnsignedBigInt(bytes, littleEndian);\n const bits = BigI"\
  "nt(bytes.length * 8);\n const signBit = 1n << (bits - 1n);\n if"\
  " ((unsigned & signBit) !== 0n) {\n return unsigned - (1n << bi"\
  "ts);\n }\n return unsigned;\n}\nfunction unsignedBigIntToBytes(va"\
  "lue, byteLength, littleEndian) {\n const bits = BigInt(byteLen"\
  "gth * 8);\n const max = 1n << bits;\n if (value < 0n || value >"\
  "= max) {\n throw new RangeError(`Value ${value} does not fit i"\
  "n ${byteLength * 8} bits`);\n }\n const bytes = new Array(byteL"\
  "ength).fill(0);\n let current = value;\n for (let i = byteLengt"\
  "h - 1; i >= 0; i--) {\n bytes[i] = Number(current & 0xffn);\n c"\
  "urrent >>= 8n;\n }\n return littleEndian ? bytes.reverse() : by"\
  "tes;\n}\nfunction signedBigIntToBytes(value, byteLength, little"\
  "Endian) {\n const bits = BigInt(byteLength * 8);\n const min = "\
  "-(1n << (bits - 1n));\n const max = (1n << (bits - 1n)) - 1n;\n"\
  " if (value < min || value > max) {\n throw new RangeError(`Val"\
  "ue ${value} does not fit in ${byteLength * 8} signed bits`);\n"\
  " }\n const normalized = value < 0n ? value + (1n << bits) : va"\
  "lue;\n return unsignedBigIntToBytes(normalized, byteLength, li"\
  "ttleEndian);\n}\nfunction parseInteger(value) {\n if (typeof val"\
  "ue === \"bigint\") {\n return value;\n }\n if (typeof value === \"n"\
  "umber\") {\n if (!Number.isFinite(value) || !Number.isInteger(v"\
  "alue)) {\n throw new TypeError(\"Expected an integer number\");\n"\
  " }\n return BigInt(value);\n }\n const trimmed = value.trim();\n "\
  "if (trimmed === \"\") {\n throw new TypeError(\"Expected a non-em"\
  "pty integer string\");\n }\n return BigInt(trimmed);\n}\nfunction "\
  "bigintToSafeNumber(value, methodName) {\n const numberValue = "\
  "Number(value);\n if (!Number.isSafeInteger(numberValue)) {\n th"\
  "row new RangeError(`${methodName} exceeds Number.MAX_SAFE_INT"\
  "EGER; use a bigint or string helper instead`);\n }\n return num"\
  "berValue;\n}\nfunction encodeUtf8String(text, zeroTerminated) {"\
  "\n const encoded = encodeURIComponent(text);\n const bytes = []"\
  ";\n for (let i = 0; i < encoded.length; i++) {\n const ch = enc"\
  "oded[i];\n if (ch === \"%\") {\n bytes.push(parseInt(encoded.slic"\
  "e(i + 1, i + 3), 16));\n i += 2;\n }\n else {\n bytes.push(ch.cha"\
  "rCodeAt(0));\n }\n }\n if (zeroTerminated) {\n bytes.push(0);\n }\n"\
  " return bytes;\n}\nfunction decodeUtf8Bytes(bytes) {\n let encod"\
  "ed = \"\";\n for (const byte of bytes) {\n encoded += \"%\" + byteT"\
  "oHex(byte);\n }\n try {\n return decodeURIComponent(encoded);\n }"\
  "\n catch (e) {\n let text = \"\";\n for (const byte of bytes) {\n t"\
  "ext += String.fromCharCode(clampByte(byte));\n }\n return text;"\
  "\n }\n}\nfunction encodeUtf16String(text, littleEndian, zeroTerm"\
  "inated) {\n const bytes = [];\n for (let i = 0; i < text.length"\
  "; i++) {\n const code = text.charCodeAt(i);\n const hi = (code "\
  ">> 8) & 0xff;\n const lo = code & 0xff;\n if (littleEndian) {\n "\
  "bytes.push(lo, hi);\n }\n else {\n bytes.push(hi, lo);\n }\n }\n if"\
  " (zeroTerminated) {\n bytes.push(0, 0);\n }\n return bytes;\n}\nfu"\
  "nction decodeUtf16Bytes(bytes, littleEndian) {\n const evenLen"\
  "gth = bytes.length - (bytes.length % 2);\n let text = \"\";\n for"\
  " (let i = 0; i < evenLength; i += 2) {\n const code = littleEn"\
  "dian\n ? clampByte(bytes[i]) | (clampByte(bytes[i + 1]) << 8)\n"\
  " : (clampByte(bytes[i]) << 8) | clampByte(bytes[i + 1]);\n if "\
  "(code === 0) {\n break;\n }\n text += String.fromCharCode(code);"\
  "\n }\n return text;\n}\n/**\n * Class providing a way to work with"\
  " 64bit pointers from Javascript, this API mimics the same\n * "\
  "well-known promitive available in Frida, but it's baked by th"\
  "e current session of r2.\n *\n * It is also possible to use thi"\
  "s class via the global `ptr` function.\n *\n * @typedef NativeP"\
  "ointer\n */\nclass NativePointer {\n constructor(s, api) {\n cons"\
  "t sourceApi = s instanceof NativePointer ? s.api : undefined;"\
  "\n this.api = api ?? sourceApi ?? exports.R;\n this.addr =\n s ="\
  "== undefined\n ? \"$$\"\n : s instanceof NativePointer\n ? s.addr."\
  "trim()\n : (\"\" + s).trim();\n }\n formatPointer(value) {\n return"\
  " value instanceof NativePointer ? value.addr.trim() : (\"\" + v"\
  "alue).trim();\n }\n newPointer(value) {\n return new NativePoint"\
  "er(value, this.api);\n }\n formatInteger(value) {\n return typeo"\
  "f value === \"bigint\" ? value.toString() : (\"\" + value).trim()"\
  ";\n }\n isBigEndian() {\n const output = this.api.call(\"e cfg.bi"\
  "gendian\");\n return output.trim() === \"true\";\n }\n readInteger("\
  "byteLength, signed, littleEndian) {\n const data = this.readBy"\
  "teArray(byteLength);\n const useLittleEndian = littleEndian ??"\
  " !(this.isBigEndian());\n return signed\n ? bytesToSignedBigInt"\
  "(data, useLittleEndian)\n : bytesToUnsignedBigInt(data, useLit"\
  "tleEndian);\n }\n writeInteger(value, byteLength, signed, littl"\
  "eEndian) {\n const useLittleEndian = littleEndian ?? !(this.is"\
  "BigEndian());\n const bigintValue = parseInteger(value);\n cons"\
  "t bytes = signed\n ? signedBigIntToBytes(bigintValue, byteLeng"\
  "th, useLittleEndian)\n : unsignedBigIntToBytes(bigintValue, by"\
  "teLength, useLittleEndian);\n this.writeByteArray(bytes);\n ret"\
  "urn true;\n }\n pointerSize() {\n const output = this.api.cmd(\"e"\
  " asm.bits\");\n return Math.max(1, parseInt(output.trim(), 10) "\
  "/ 8);\n }\n /**\n * Copy N bytes from current pointer to the des"\
  "tination\n *\n * @param {string|NativePointer|number} destinati"\
  "on address\n * @param {string|number} amount of bytes\n */\n cop"\
  "yTo(addr, size) {\n this.api.cmd(`wf ${this.addr} ${size} @ ${"\
  "this.formatPointer(addr)}`);\n }\n /**\n * Copy N bytes from giv"\
  "en address to the current destination\n *\n * @param {string|Na"\
  "tivePointer|number} source address\n * @param {string|number} "\
  "amount of bytes\n */\n copyFrom(addr, size) {\n this.api.cmd(`wf"\
  " ${this.formatPointer(addr)} ${size} @ ${this.addr}`);\n }\n /*"\
  "*\n * Fill N bytes in this address with zero\n *\n * @param {str"\
  "ing|number} amount of bytes\n */\n zeroFill(size) {\n this.api.c"\
  "md(`w0 ${size} @ ${this.addr}`);\n }\n /**\n * Filter a string t"\
  "o be used as a valid flag name\n *\n * @param {string} name of "\
  "the symbol name\n * @returns {string} filtered name to be used"\
  " as a flag\n */\n filterFlag(name) {\n return this.api.call(`fD "\
  "${name}`);\n }\n /**\n * Set a flag (name) at the address pointe"\
  "d\n *\n * @param {string} name of the flag to set\n * @returns {"\
  "string} base64 decoded string\n */\n setFlag(name) {\n this.api."\
  "call(`f ${name}=${this.addr}`);\n }\n /**\n * Remove the flag in"\
  " the current address\n *\n */\n unsetFlag() {\n this.api.call(`f-"\
  "${this.addr}`);\n }\n /**\n * Render an hexadecimal dump of the "\
  "bytes contained in the range starting\n * in the current point"\
  "er and given length.\n *\n * @param {number} length optional am"\
  "ount of bytes to dump, using blocksize\n * @returns {string} s"\
  "tring containing the hexadecimal dump of memory\n */\n hexdump("\
  "length) {\n const len = length === undefined ? \"\" : \"\" + lengt"\
  "h;\n return this.api.cmd(`x${len}@${this.addr}`);\n }\n function"\
  "Graph(format) {\n if (format === \"dot\") {\n return this.api.cmd"\
  "(`agfd@ ${this.addr}`);\n }\n if (format === \"json\") {\n return "\
  "this.api.cmd(`agfj@${this.addr}`);\n }\n if (format === \"mermai"\
  "d\") {\n return this.api.cmd(`agfm@${this.addr}`);\n }\n return t"\
  "his.api.cmd(`agf@${this.addr}`);\n }\n readByteArray(len) {\n if"\
  " (len <= 0) {\n return [];\n }\n return this.api.cmdj(`p8j ${len"\
  "}@${this.addr}`);\n }\n readHexString(len) {\n if (len <= 0) {\n "\
  "return \"\";\n }\n const output = this.api.cmd(`p8 ${len}@${this."\
  "addr}`);\n return output.trim();\n }\n slice(length) {\n return t"\
  "his.readByteArray(length);\n }\n writeHexString(hex) {\n const n"\
  "ormalized = normalizeHexString(hex);\n if (normalized !== \"\") "\
  "{\n this.api.cmd(`wx ${normalized} @ ${this.addr}`);\n }\n retur"\
  "n this;\n }\n and(a) {\n const addr = this.api.call(`?v ${this.a"\
  "ddr} & ${this.formatInteger(a)}`);\n return this.newPointer(ad"\
  "dr.trim());\n }\n or(a) {\n const addr = this.api.call(`?v ${thi"\
  "s.addr} | ${this.formatInteger(a)}`);\n return this.newPointer"\
  "(addr.trim());\n }\n add(a) {\n const addr = this.api.call(`?v $"\
  "{this.addr} + ${this.formatInteger(a)}`);\n return this.newPoi"\
  "nter(addr.trim());\n }\n sub(a) {\n const addr = this.api.call(`"\
  "?v ${this.addr} - ${this.formatInteger(a)}`);\n return this.ne"\
  "wPointer(addr.trim());\n }\n distance(a) {\n return (this.toBigI"\
  "nt()) - (this.newPointer(a).toBigInt());\n }\n writeByteArray(d"\
  "ata) {\n const hex = byteArrayToHex(data);\n if (hex !== \"\") {\n"\
  " this.api.cmd(`wx ${hex} @ ${this.addr}`);\n }\n return this;\n "\
  "}\n patchByteArray(data) {\n return this.writeByteArray(data);\n"\
  " }\n patchHexString(hex) {\n return this.writeHexString(hex);\n "\
  "}\n writeAssembly(instruction) {\n this.api.cmd(`wa ${instructi"\
  "on} @ ${this.addr}`);\n return this;\n }\n patchInstruction(inst"\
  "ruction) {\n return this.writeAssembly(instruction);\n }\n write"\
  "String(s) {\n return this.writeUtf8String(s, false);\n }\n write"\
  "Utf8String(s, zeroTerminated = false) {\n return this.writeByt"\
  "eArray(encodeUtf8String(s, zeroTerminated));\n }\n writeCString"\
  "(s) {\n return this.writeUtf8String(s, true);\n }\n writeUtf16St"\
  "ring(s, zeroTerminated = false, littleEndian) {\n const useLit"\
  "tleEndian = littleEndian ?? !(this.isBigEndian());\n return th"\
  "is.writeByteArray(encodeUtf16String(s, useLittleEndian, zeroT"\
  "erminated));\n }\n writeWideString(s) {\n return this.writeUtf16"\
  "String(s, true);\n }\n patchCString(s) {\n return this.writeCStr"\
  "ing(s);\n }\n patchWideString(s) {\n return this.writeWideString"\
  "(s);\n }\n patchData(data) {\n if (typeof data === \"string\") {\n "\
  "return this.writeHexString(data);\n }\n return this.writeByteAr"\
  "ray(data);\n }\n readString(length) {\n if (length === undefined"\
  ") {\n return this.readCString();\n }\n return this.readUtf8Strin"\
  "g(length);\n }\n readUtf8String(length) {\n if (length === undef"\
  "ined) {\n const output = this.api.cmdj(`pszj@${this.addr}`);\n "\
  "return output.string;\n }\n return decodeUtf8Bytes(this.readByt"\
  "eArray(length));\n }\n readUtf16String(length, littleEndian) {\n"\
  " if (length === undefined) {\n return this.readWideString();\n "\
  "}\n const useLittleEndian = littleEndian ?? !(this.isBigEndian"\
  "());\n return decodeUtf16Bytes(this.readByteArray(length), use"\
  "LittleEndian);\n }\n /**\n * Check if it's a pointer to the addr"\
  "ess zero. Also known as null pointer.\n *\n * @returns {boolean"\
  "} true if null\n */\n isNull() {\n return (this.toBigInt()) === "\
  "0n;\n }\n /**\n * Compare current pointer with the passed one, a"\
  "nd return -1, 0 or 1.\n *\n * * if (this < arg) return -1;\n * *"\
  " if (this > arg) return 1;\n * * if (this == arg) return 0;\n *"\
  "\n * @returns {number} returns -1, 0 or 1 depending on the com"\
  "parison of the pointers\n */\n compare(a) {\n const lhs = this.t"\
  "oBigInt();\n const rhs = this.newPointer(a).toBigInt();\n if (l"\
  "hs < rhs) {\n return -1;\n }\n if (lhs > rhs) {\n return 1;\n }\n r"\
  "eturn 0;\n }\n equals(a) {\n return (this.compare(a)) === 0;\n }\n"\
  " isBelow(a) {\n return (this.compare(a)) < 0;\n }\n isAbove(a) {"\
  "\n return (this.compare(a)) > 0;\n }\n /**\n * Check if it's a po"\
  "inter to the address zero. Also known as null pointer.\n *\n * "\
  "@returns {boolean} true if null\n */\n pointsToNull() {\n const "\
  "value = this.readPointer();\n return value.isNull();\n }\n toJSO"\
  "N() {\n const output = this.api.cmd(\"?vi \" + this.addr.trim())"\
  ";\n return output.trim();\n }\n toString() {\n const output = thi"\
  "s.api.cmd(\"?v \" + this.addr.trim());\n return output.trim();\n "\
  "}\n toBigInt() {\n return BigInt(this.toJSON());\n }\n toNumber()"\
  " {\n return bigintToSafeNumber(this.toBigInt(), \"NativePointer"\
  ".toNumber\");\n }\n writePointer(p) {\n this.api.cmd(`wvp ${this."\
  "formatPointer(p)} @ ${this.addr}`);\n return true;\n }\n readRel"\
  "ativePointer() {\n return this.add(this.readS32());\n }\n readPo"\
  "inter() {\n const address = this.api.cmd(`pvp@${this.addr}`);\n"\
  " return this.newPointer(address.trim());\n }\n follow(levels = "\
  "1) {\n let current = this;\n for (let i = 0; i < levels; i++) {"\
  "\n current = current.readPointer();\n }\n return current;\n }\n re"\
  "adPointers(count) {\n const pointers = [];\n const step = this."\
  "pointerSize();\n let current = this;\n for (let i = 0; i < coun"\
  "t; i++) {\n pointers.push(current.readPointer());\n current = c"\
  "urrent.add(step);\n }\n return pointers;\n }\n readS8() {\n return"\
  " bigintToSafeNumber(this.readInteger(1, true), \"readS8\");\n }\n"\
  " readU8() {\n return bigintToSafeNumber(this.readInteger(1, fa"\
  "lse), \"readU8\");\n }\n readU16() {\n return bigintToSafeNumber(t"\
  "his.readInteger(2, false), \"readU16\");\n }\n readU16le() {\n ret"\
  "urn bigintToSafeNumber(this.readInteger(2, false, true), \"rea"\
  "dU16le\");\n }\n readU16be() {\n return bigintToSafeNumber(this.r"\
  "eadInteger(2, false, false), \"readU16be\");\n }\n readS16() {\n r"\
  "eturn bigintToSafeNumber(this.readInteger(2, true), \"readS16\""\
  ");\n }\n readS16le() {\n return bigintToSafeNumber(this.readInte"\
  "ger(2, true, true), \"readS16le\");\n }\n readS16be() {\n return b"\
  "igintToSafeNumber(this.readInteger(2, true, false), \"readS16b"\
  "e\");\n }\n readS32() {\n return bigintToSafeNumber(this.readInte"\
  "ger(4, true), \"readS32\");\n }\n readS32le() {\n return bigintToS"\
  "afeNumber(this.readInteger(4, true, true), \"readS32le\");\n }\n "\
  "readS32be() {\n return bigintToSafeNumber(this.readInteger(4, "\
  "true, false), \"readS32be\");\n }\n readU32() {\n return bigintToS"\
  "afeNumber(this.readInteger(4, false), \"readU32\");\n }\n readU32"\
  "le() {\n return bigintToSafeNumber(this.readInteger(4, false, "\
  "true), \"readU32le\");\n }\n readU32be() {\n return bigintToSafeNu"\
  "mber(this.readInteger(4, false, false), \"readU32be\");\n }\n rea"\
  "dU64BigInt() {\n return this.readInteger(8, false);\n }\n readU6"\
  "4leBigInt() {\n return this.readInteger(8, false, true);\n }\n r"\
  "eadU64beBigInt() {\n return this.readInteger(8, false, false);"\
  "\n }\n readU64() {\n return bigintToSafeNumber(this.readU64BigIn"\
  "t(), \"readU64\");\n }\n readU64le() {\n return bigintToSafeNumber"\
  "(this.readU64leBigInt(), \"readU64le\");\n }\n readU64be() {\n ret"\
  "urn bigintToSafeNumber(this.readU64beBigInt(), \"readU64be\");\n"\
  " }\n readU64String() {\n return (this.readU64BigInt()).toString"\
  "();\n }\n readU64leString() {\n return (this.readU64leBigInt())."\
  "toString();\n }\n readU64beString() {\n return (this.readU64beBi"\
  "gInt()).toString();\n }\n readS64() {\n return this.readInteger("\
  "8, true);\n }\n readS64le() {\n return this.readInteger(8, true,"\
  " true);\n }\n readS64be() {\n return this.readInteger(8, true, f"\
  "alse);\n }\n readS64String() {\n return (this.readS64()).toStrin"\
  "g();\n }\n readS64leString() {\n return (this.readS64le()).toStr"\
  "ing();\n }\n readS64beString() {\n return (this.readS64be()).toS"\
  "tring();\n }\n writeInt(n) {\n return this.writeS32(n);\n }\n /**\n"\
  " * Write a byte in the current address, the value must be bet"\
  "ween 0 and 255\n *\n * @param {string} n number to write in the"\
  " pointed byte in the current address\n * @returns {boolean} fa"\
  "lse if the operation failed\n */\n writeU8(n) {\n return this.wr"\
  "iteInteger(n, 1, false);\n }\n writeS8(n) {\n return this.writeI"\
  "nteger(n, 1, true);\n }\n writeU16(n) {\n return this.writeInteg"\
  "er(n, 2, false);\n }\n writeU16be(n) {\n return this.writeIntege"\
  "r(n, 2, false, false);\n }\n writeU16le(n) {\n return this.write"\
  "Integer(n, 2, false, true);\n }\n writeS16(n) {\n return this.wr"\
  "iteInteger(n, 2, true);\n }\n writeS16be(n) {\n return this.writ"\
  "eInteger(n, 2, true, false);\n }\n writeS16le(n) {\n return this"\
  ".writeInteger(n, 2, true, true);\n }\n writeU32(n) {\n return th"\
  "is.writeInteger(n, 4, false);\n }\n writeU32be(n) {\n return thi"\
  "s.writeInteger(n, 4, false, false);\n }\n writeU32le(n) {\n retu"\
  "rn this.writeInteger(n, 4, false, true);\n }\n writeS32(n) {\n r"\
  "eturn this.writeInteger(n, 4, true);\n }\n writeS32be(n) {\n ret"\
  "urn this.writeInteger(n, 4, true, false);\n }\n writeS32le(n) {"\
  "\n return this.writeInteger(n, 4, true, true);\n }\n writeU64(n)"\
  " {\n return this.writeInteger(n, 8, false);\n }\n writeU64be(n) "\
  "{\n return this.writeInteger(n, 8, false, false);\n }\n writeU64"\
  "le(n) {\n return this.writeInteger(n, 8, false, true);\n }\n wri"\
  "teS64(n) {\n return this.writeInteger(n, 8, true);\n }\n writeS6"\
  "4be(n) {\n return this.writeInteger(n, 8, true, false);\n }\n wr"\
  "iteS64le(n) {\n return this.writeInteger(n, 8, true, true);\n }"\
  "\n readInt32() {\n return this.readS32();\n }\n readCString() {\n "\
  "const output = this.api.cmdj(`pszj@${this.addr}`);\n return ou"\
  "tput.string;\n }\n readWideString() {\n const output = this.api."\
  "cmdj(`pswj@${this.addr}`);\n return output.string;\n }\n readPas"\
  "calString() {\n const output = this.api.cmdj(`pspj@${this.addr"\
  "}`);\n return output.string;\n }\n instruction() {\n const output"\
  " = this.api.cmdj(`aoj@${this.addr}`);\n return output[0];\n }\n "\
  "disassemble(length) {\n const len = length === undefined ? \"\" "\
  ": \"\" + length;\n return this.api.cmd(`pd ${len}@${this.addr}`)"\
  ";\n }\n analyzeFunction() {\n this.api.cmd(\"af@\" + this.addr);\n "\
  "return this;\n }\n analyzeFunctionRecursively() {\n this.api.cmd"\
  "(\"afr@\" + this.addr);\n return this;\n }\n name() {\n const v = t"\
  "his.api.cmd(\"fd \" + this.addr);\n return v.trim();\n }\n methodN"\
  "ame() {\n // TODO: @ should be optional here, as addr should b"\
  "e passable as argument imho\n const v = this.api.cmd(\"ic.@\" + "\
  "this.addr);\n return v.trim();\n }\n symbolName() {\n // TODO: @ "\
  "should be optional here, as addr should be passable as argume"\
  "nt imho\n const name = this.api.cmd(\"isj.@\" + this.addr);\n ret"\
  "urn name.trim();\n }\n getFunction() {\n return this.api.cmdj(\"a"\
  "fij@\" + this.addr);\n }\n basicBlock() {\n return this.api.cmdj("\
  "\"abj@\" + this.addr);\n }\n functionBasicBlocks() {\n return this"\
  ".api.cmdj(\"afbj@\" + this.addr);\n }\n xrefs() {\n return this.ap"\
  "i.cmdj(\"axtj@\" + this.addr);\n }\n}\nexports.NativePointer = Nat"\
  "ivePointer;\nvar R2Papi=R2PapiSync;\n";
