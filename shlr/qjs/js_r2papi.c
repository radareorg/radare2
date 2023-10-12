static const char *const js_r2papi_qjs = "" \
  "Object.defineProperty(G,\"__esModule\",{value:!0}),G.Base64=G.N"\
  "ativePointer=G.NativeCallback=G.NativeFunction=G.R2Papi=G.Ass"\
  "embler=G.ProcessClass=G.ModuleClass=G.ThreadClass=void 0;cons"\
  "t shell_js_1=G;class ThreadClass{constructor(t){this.api=null"\
  ",this.api=t}backtrace(){return G.r2.call(\"dbtj\")}sleep(t){ret"\
  "urn G.r2.call(\"sleep \"+t)}}G.ThreadClass=ThreadClass;class Mo"\
  "duleClass{constructor(t){this.api=null,this.api=t}fileName(){"\
  "return this.api.call(\"dpe\").trim()}name(){return\"Module\"}find"\
  "BaseAddress(){return\"TODO\"}findExportByName(t){return\"TODO\"}g"\
  "etBaseAddress(t){return\"TODO\"}getExportByName(t){return G.r2."\
  "call(\"iE,name/eq/\"+t+\",vaddr/cols,:quiet\")}enumerateExports()"\
  "{return G.r2.callj(\"iEj\")}enumerateImports(){return G.r2.call"\
  "j(\"iij\")}enumerateRanges(){return G.r2.callj(\"isj\")}enumerate"\
  "Symbols(){return G.r2.callj(\"isj\")}}G.ModuleClass=ModuleClass"\
  ";class ProcessClass{constructor(t){this.r2=null,this.r2=t}enu"\
  "merateMallocRanges(){}enumerateSystemRanges(){}enumerateRange"\
  "s(){}enumerateThreads(){return G.r2.call(\"dptj\")}enumerateMod"\
  "ules(){if(G.r2.call(\"cfg.json.num=string\"),G.r2.callj(\"e cfg."\
  "debug\")){const t=G.r2.callj(\"dmmj\"),e=[];for(const r of t){co"\
  "nst t={base:new NativePointer(r.addr),size:new NativePointer("\
  "r.addr_end).sub(r.addr),path:r.file,name:r.name};e.push(t)}re"\
  "turn e}{const t=t=>{const e=t.split(\"/\");return e[e.length-1]"\
  "},e=G.r2.callj(\"obj\"),r=[];for(const s of e){const e={base:ne"\
  "w NativePointer(s.addr),size:s.size,path:s.file,name:t(s.file"\
  ")};r.push(e)}const s=G.r2.callj(\"ilj\");for(const e of s){cons"\
  "t s={base:0,size:0,path:e,name:t(e)};r.push(s)}return r}}getM"\
  "oduleByAddress(t){}getModuleByName(t){}codeSigningPolicy(){re"\
  "turn\"optional\"}getTmpDir(){return this.r2.call(\"e dir.tmp\").t"\
  "rim()}getHomeDir(){return this.r2.call(\"e dir.home\").trim()}p"\
  "latform(){return this.r2.call(\"e asm.os\").trim()}getCurrentDi"\
  "r(){return this.r2.call(\"pwd\").trim()}getCurrentThreadId(){re"\
  "turn+this.r2.call(\"dpq\")}pageSize(){return 64===this.r2.callj"\
  "(\"e asm.bits\")&&this.r2.call(\"e asm.arch\").startsWith(\"arm\")?"\
  "16384:4096}isDebuggerAttached(){return this.r2.callj(\"e cfg.d"\
  "ebug\")}setExceptionHandler(){}id(){return this.r2.callj(\"dpq\""\
  ")}pointerSize(){return G.r2.callj(\"e asm.bits\")/8}}G.ProcessC"\
  "lass=ProcessClass;class Assembler{constructor(t){this.program"\
  "=\"\",this.labels={},this.endian=!1,this.pc=0,this.r2=null,this"\
  ".r2=void 0===t?G.r2:t,this.program=\"\",this.labels={}}setProgr"\
  "amCounter(t){this.pc=t}setEndian(t){this.endian=t}toString(){"\
  "return this.program}append(t){this.pc+=t.length/2,this.progra"\
  "m+=t}label(t){const e=this.pc;return this.labels[t]=this.pc,e"\
  "}asm(t){let e=this.r2.cmd('\"\"pa '+t).trim();e.length<16||(e=\""\
  "____\"),this.append(e)}}G.Assembler=Assembler;class R2Papi{con"\
  "structor(t){this.r2=t}getBaseAddress(){return new NativePoint"\
  "er(this.cmd(\"e bin.baddr\"))}jsonToTypescript(t,e){let r=`inte"\
  "rface ${t} {\\n`;e.length&&e.length>0&&(e=e[0]);for(let t of O"\
  "bject.keys(e)){r+=`    ${t}: ${typeof e[t]};\\n`}return`${r}}\\"\
  "n`}getBits(){return this.cmd(\"-b\")}getArch(){return this.cmd("\
  "\"-a\")}getCpu(){return this.cmd(\"-e asm.cpu\")}setArch(t,e){thi"\
  "s.cmd(\"-a \"+t),void 0!==e&&this.cmd(\"-b \"+e)}setFlagSpace(t){"\
  "this.cmd(\"fs \"+t)}setLogLevel(t){return this.cmd(\"e log.level"\
  "=\"+t),this}newMap(t,e,r,s,i,n=\"\"){this.cmd(`om ${t} ${e} ${r}"\
  " ${s} ${i} ${n}`)}at(t){return new NativePointer(t)}getShell("\
  "){return new shell_js_1.R2PapiShell(this)}version(){return th"\
  "is.r2.cmd(\"?Vq\").trim()}platform(){return this.r2.cmd(\"uname\""\
  ").trim()}arch(){return this.r2.cmd(\"uname -a\").trim()}bits(){"\
  "return this.r2.cmd(\"uname -b\").trim()}id(){return+this.r2.cmd"\
  "(\"?vi:$p\")}printAt(t,e,r){}clearScreen(){return this.r2.cmd(\""\
  "!clear\"),this}getConfig(t){if(\"\"===t)return new Error(\"Empty "\
  "key\");return\"\"===this.r2.cmd(`e~^${t} =`).trim()?new Error(\"C"\
  "onfig key does not exist\"):this.r2.call(\"e \"+t).trim()}setCon"\
  "fig(t,e){return this.r2.call(\"e \"+t+\"=\"+e),this}getRegisterSt"\
  "ateForEsil(){return this.cmdj(\"dre\").trim()}getRegisters(){re"\
  "turn this.cmdj(\"drj\")}resizeFile(t){return this.cmd(`r ${t}`)"\
  ",this}insertNullBytes(t,e){return void 0===e&&(e=\"$$\"),this.c"\
  "md(`r+${t}@${e}`),this}removeBytes(t,e){return void 0===e&&(e"\
  "=\"$$\"),this.cmd(`r-${t}@${e}`),this}seek(t){return this.cmd(`"\
  "s ${t}`),this}currentSeek(){return new NativePointer(\"$$\")}se"\
  "ekToRelativeOpcode(t){return this.cmd(`so ${t}`),this.current"\
  "Seek()}getBlockSize(){return+this.cmd(\"b\")}setBlockSize(t){re"\
  "turn this.cmd(`b ${t}`),this}countFlags(){return Number(this."\
  "cmd(\"f~?\"))}countFunctions(){return Number(this.cmd(\"aflc\"))}"\
  "analyzeFunctionsWithEsil(t){this.cmd(\"aaef\")}analyzeProgramWi"\
  "thEsil(t){this.cmd(\"aae\")}analyzeProgram(t){switch(void 0===t"\
  "&&(t=0),t){case 0:this.cmd(\"aa\");break;case 1:this.cmd(\"aaa\")"\
  ";break;case 2:this.cmd(\"aaaa\");break;case 3:this.cmd(\"aaaaa\")"\
  "}return this}enumerateThreads(){return[{context:this.cmdj(\"dr"\
  "j\"),id:0,state:\"waiting\",selected:!0}]}currentThreadId(){retu"\
  "rn+this.cmd(\"e cfg.debug\")?+this.cmd(\"dpt.\"):this.id()}setReg"\
  "isters(t){for(let e of Object.keys(t)){const r=t[e];this.r2.c"\
  "md(\"dr \"+e+\"=\"+r)}}hex(t){return this.r2.cmd(\"?v \"+t).trim()}"\
  "step(){return this.r2.cmd(\"ds\"),this}stepOver(){return this.r"\
  "2.cmd(\"dso\"),this}math(t){return+this.r2.cmd(\"?v \"+t)}stepUnt"\
  "il(t){this.cmd(`dsu ${t}`)}enumerateXrefsTo(t){return this.ca"\
  "ll(\"axtq \"+t).trim().split(/\\n/)}findXrefsTo(t,e){e?this.call"\
  "(\"/r \"+t):this.call(\"/re \"+t)}analyzeFunctionsFromCalls(){ret"\
  "urn this.call(\"aac\"),this}analyzeFunctionsWithPreludes(){retu"\
  "rn this.call(\"aap\"),this}analyzeObjCReferences(){return this."\
  "cmd(\"aao\"),this}analyzeImports(){return this.cmd(\"af @ sym.im"\
  "p.*\"),this}searchDisasm(t){return this.callj(\"/ad \"+t)}search"\
  "String(t){return this.cmdj(\"/j \"+t)}searchBytes(t){const e=t."\
  "map((function(t){return(255&t).toString(16)})).join(\"\");retur"\
  "n this.cmdj(\"/xj \"+e)}binInfo(){try{return this.cmdj(\"ij~{bin"\
  "}\")}catch(t){return{}}}selectBinary(t){this.call(`ob ${t}`)}o"\
  "penFile(t){const e=this.call(\"oqq\").trim();this.call(`o ${t}`"\
  ");const r=this.call(\"oqq\").trim();return e===r?new Error(\"Can"\
  "not open file\"):parseInt(r)}openFileNomap(t){const e=this.cal"\
  "l(\"oqq\").trim();this.call(`of ${t}`);const r=this.call(\"oqq\")"\
  ".trim();return e===r?new Error(\"Cannot open file\"):parseInt(r"\
  ")}currentFile(t){return this.call(\"o.\").trim()}enumeratePlugi"\
  "ns(t){switch(t){case\"bin\":return this.callj(\"Lij\");case\"io\":r"\
  "eturn this.callj(\"Loj\");case\"core\":return this.callj(\"Lcj\");c"\
  "ase\"arch\":return this.callj(\"LAj\");case\"anal\":return this.cal"\
  "lj(\"Laj\");case\"lang\":return this.callj(\"Llj\")}return[]}enumer"\
  "ateModules(){return this.callj(\"dmmj\")}enumerateFiles(){retur"\
  "n this.callj(\"oj\")}enumerateBinaries(){return this.callj(\"obj"\
  "\")}enumerateMaps(){return this.callj(\"omj\")}enumerateClasses("\
  "){return this.callj(\"icj\")}enumerateSymbols(){return this.cal"\
  "lj(\"isj\")}enumerateExports(){return this.callj(\"iEj\")}enumera"\
  "teImports(){return this.callj(\"iij\")}enumerateLibraries(){ret"\
  "urn this.callj(\"ilj\")}enumerateSections(){return this.callj(\""\
  "iSj\")}enumerateSegments(){return this.callj(\"iSSj\")}enumerate"\
  "Entrypoints(){return this.callj(\"iej\")}enumerateRelocations()"\
  "{return this.callj(\"irj\")}enumerateFunctions(){return this.cm"\
  "dj(\"aflj\")}enumerateFlags(){return this.cmdj(\"fj\")}skip(){thi"\
  "s.r2.cmd(\"dss\")}ptr(t){return new NativePointer(t,this)}call("\
  "t){return this.r2.call(t)}callj(t){return JSON.parse(this.cal"\
  "l(t))}cmd(t){return this.r2.cmd(t)}cmdj(t){return JSON.parse("\
  "this.cmd(t))}log(t){return this.r2.log(t)}clippy(t){this.r2.l"\
  "og(this.r2.cmd(\"?E \"+t))}ascii(t){this.r2.log(this.r2.cmd(\"?e"\
  "a \"+t))}}G.R2Papi=R2Papi;class NativeFunction{constructor(){}"\
  "}G.NativeFunction=NativeFunction;class NativeCallback{constru"\
  "ctor(){}}G.NativeCallback=NativeCallback;class NativePointer{"\
  "constructor(t,e){this.api=void 0===e?G.R:e,this.addr=(\"\"+t).t"\
  "rim()}setFlag(t){this.api.call(`f ${t}=${this.addr}`)}unsetFl"\
  "ag(){this.api.call(`f-${this.addr}`)}hexdump(t){let e=void 0="\
  "==t?\"\":\"\"+t;return this.api.cmd(`x${e}@${this.addr}`)}functio"\
  "nGraph(t){return\"dot\"===t?this.api.cmd(`agfd@ ${this.addr}`):"\
  "\"json\"===t?this.api.cmd(`agfj@${this.addr}`):\"mermaid\"===t?th"\
  "is.api.cmd(`agfm@${this.addr}`):this.api.cmd(`agf@${this.addr"\
  "}`)}readByteArray(t){return JSON.parse(this.api.cmd(`p8j ${t}"\
  "@${this.addr}`))}readHexString(t){return this.api.cmd(`p8 ${t"\
  "}@${this.addr}`).trim()}and(t){const e=this.api.call(`?v ${th"\
  "is.addr} & ${t}`).trim();return new NativePointer(e)}or(t){co"\
  "nst e=this.api.call(`?v ${this.addr} | ${t}`).trim();return n"\
  "ew NativePointer(e)}add(t){const e=this.api.call(`?v ${this.a"\
  "ddr}+${t}`).trim();return new NativePointer(e)}sub(t){const e"\
  "=this.api.call(`?v ${this.addr}-${t}`).trim();return new Nati"\
  "vePointer(e)}writeByteArray(t){return this.api.cmd(\"wx \"+t.jo"\
  "in(\"\")),this}writeAssembly(t){return this.api.cmd(`wa ${t} @ "\
  "${this.addr}`),this}writeCString(t){return this.api.call(\"w \""\
  "+t),this}writeWideString(t){return this.api.call(\"ww \"+t),thi"\
  "s}asNumber(){const t=this.api.call(\"?vi \"+this.addr);return p"\
  "arseInt(t)}isNull(){return 0==this.asNumber()}compare(t){retu"\
  "rn\"string\"!=typeof t&&\"number\"!=typeof t||(t=new NativePointe"\
  "r(t)),t.addr===this.addr||new NativePointer(t.addr).asNumber("\
  ")===this.asNumber()}pointsToNull(){return this.readPointer()."\
  "compare(0)}toString(){return this.addr.trim()}writePointer(t)"\
  "{this.api.cmd(`wvp ${t}@${this}`)}readPointer(){return new Na"\
  "tivePointer(this.api.call(\"pvp@\"+this.addr))}readS8(){return "\
  "parseInt(this.api.cmd(`pv1d@${this.addr}`))}readU8(){return p"\
  "arseInt(this.api.cmd(`pv1u@${this.addr}`))}readU16(){return p"\
  "arseInt(this.api.cmd(`pv2d@${this.addr}`))}readU16le(){return"\
  " parseInt(this.api.cmd(`pv2d@${this.addr}@e:cfg.bigendian=fal"\
  "se`))}readU16be(){return parseInt(this.api.cmd(`pv2d@${this.a"\
  "ddr}@e:cfg.bigendian=true`))}readS16(){return parseInt(this.a"\
  "pi.cmd(`pv2d@${this.addr}`))}readS16le(){return parseInt(this"\
  ".api.cmd(`pv2d@${this.addr}@e:cfg.bigendian=false`))}readS16b"\
  "e(){return parseInt(this.api.cmd(`pv2d@${this.addr}@e:cfg.big"\
  "endian=true`))}readS32(){return parseInt(this.api.cmd(`pv4d@$"\
  "{this.addr}`))}readU32(){return parseInt(this.api.cmd(`pv4u@$"\
  "{this.addr}`))}readU32le(){return parseInt(this.api.cmd(`pv4u"\
  "@${this.addr}@e:cfg.bigendian=false`))}readU32be(){return par"\
  "seInt(this.api.cmd(`pv4u@${this.addr}@e:cfg.bigendian=true`))"\
  "}readU64(){return parseInt(this.api.cmd(`pv8u@${this.addr}`))"\
  "}readU64le(){return parseInt(this.api.cmd(`pv8u@${this.addr}@"\
  "e:cfg.bigendian=false`))}readU64be(){return parseInt(this.api"\
  ".cmd(`pv8u@${this.addr}@e:cfg.bigendian=true`))}writeInt(t){r"\
  "eturn this.writeU32(t)}writeU8(t){return this.api.cmd(`wv1 ${"\
  "t}@${this.addr}`),!0}writeU16(t){return this.api.cmd(`wv2 ${t"\
  "}@${this.addr}`),!0}writeU16be(t){return this.api.cmd(`wv2 ${"\
  "t}@${this.addr}@e:cfg.bigendian=true`),!0}writeU16le(t){retur"\
  "n this.api.cmd(`wv2 ${t}@${this.addr}@e:cfg.bigendian=false`)"\
  ",!0}writeU32(t){return this.api.cmd(`wv4 ${t}@${this.addr}`),"\
  "!0}writeU32be(t){return this.api.cmd(`wv4 ${t}@${this.addr}@e"\
  ":cfg.bigendian=true`),!0}writeU32le(t){return this.api.cmd(`w"\
  "v4 ${t}@${this.addr}@e:cfg.bigendian=false`),!0}writeU64(t){r"\
  "eturn this.api.cmd(`wv8 ${t}@${this.addr}`),!0}writeU64be(t){"\
  "return this.api.cmd(`wv8 ${t}@${this.addr}@e:cfg.bigendian=tr"\
  "ue`),!0}writeU64le(t){return this.api.cmd(`wv8 ${t}@${this.ad"\
  "dr}@e:cfg.bigendian=false`),!0}readInt32(){return this.readU3"\
  "2()}readCString(){return JSON.parse(this.api.cmd(`pszj@${this"\
  ".addr}`)).string}readWideString(){return JSON.parse(this.api."\
  "cmd(`pswj@${this.addr}`)).string}readPascalString(){return JS"\
  "ON.parse(this.api.cmd(`pspj@${this.addr}`)).string}instructio"\
  "n(){return this.api.cmdj(`aoj@${this.addr}`)[0]}disassemble(t"\
  "){let e=void 0===t?\"\":\"\"+t;return this.api.cmd(`pd ${e}@${thi"\
  "s.addr}`)}analyzeFunction(){return this.api.cmd(\"af@\"+this.ad"\
  "dr),this}analyzeFunctionRecursively(){return this.api.cmd(\"af"\
  "r@\"+this.addr),this}name(){return this.api.cmd(\"fd \"+this.add"\
  "r).trim()}methodName(){return this.api.cmd(\"ic.@\"+this.addr)."\
  "trim()}symbolName(){return this.api.cmd(\"isj.@\"+this.addr).tr"\
  "im()}getFunction(){return this.api.cmdj(\"afij@\"+this.addr)}ba"\
  "sicBlock(){return this.api.cmdj(\"abj@\"+this.addr)}functionBas"\
  "icBlocks(){return this.api.cmdj(\"afbj@\"+this.addr)}xrefs(){re"\
  "turn this.api.cmdj(\"axtj@\"+this.addr)}}G.NativePointer=Native"\
  "Pointer;class Base64{static encode(t){return(0,G.b64)(t)}stat"\
  "ic decode(t){return(0,G.b64)(t,!0)}}G.Base64=Base64,Object.de"\
  "fineProperty(G,\"__esModule\",{value:!0}),G.R2PapiShell=void 0;"\
  "class R2PapiShell{constructor(t){this.rp=t}mkdir(t,e){return!"\
  "0===e?this.rp.call(`mkdir -p ${t}`):this.rp.call(`mkdir ${t}`"\
  "),!0}unlink(t){return this.rp.call(`rm ${t}`),!0}chdir(t){ret"\
  "urn this.rp.call(`cd ${t}`),!0}ls(){return this.rp.call(\"ls -"\
  "q\").trim().split(\"\\n\")}fileExists(t){return!1}open(t){this.rp"\
  ".call(`open ${t}`)}system(t){return this.rp.call(`!${t}`),0}r"\
  "un(t){return this.rp.call(`rm ${t}`),0}mount(t,e){return this"\
  ".rp.call(`m ${t} ${e}`),!0}umount(t){this.rp.call(`m-${t}`)}c"\
  "hdir2(t){return void 0===t&&(t=\"/\"),this.rp.call(`mdq ${t}`),"\
  "!0}ls2(t){return void 0===t&&(t=\"/\"),this.rp.call(`mdq ${t}`)"\
  ".trim().split(\"\\n\")}enumerateMountpoints(){return this.rp.cmd"\
  "j(\"mlj\")}isSymlink(t){return!1}isDirectory(t){return!1}}G.R2P"\
  "apiShell=R2PapiShell,Object.defineProperty(G,\"__esModule\",{va"\
  "lue:!0}),G.EsilParser=G.EsilNode=G.EsilToken=void 0;class Esi"\
  "lToken{constructor(t=\"\",e=0){this.label=\"\",this.comment=\"\",th"\
  "is.text=\"\",this.addr=\"0\",this.position=0,this.text=t,this.pos"\
  "ition=e}toString(){return this.text}}G.EsilToken=EsilToken;cl"\
  "ass EsilNode{constructor(t=new EsilToken,e=\"none\"){this.type="\
  "\"none\",this.token=t,this.children=[]}setSides(t,e){this.lhs=t"\
  ",this.rhs=e}addChildren(t,e){void 0!==t&&this.children.push(t"\
  "),void 0!==e&&this.children.push(e)}toEsil(){if(void 0!==this"\
  ".lhs&&void 0!==this.rhs){let t=this.lhs.toEsil();return\"\"!==t"\
  "&&(t+=\",\"),`${this.rhs.toEsil()},${t}${this.token}`}return\"\"}"\
  "toString(){let t=\"\";if(\"\"!==this.token.label&&(t+=this.token."\
  "label+\":\\n\"),this.token.addr,\"\"!==this.token.comment&&(t+=\"/*"\
  "\"+this.token.comment+\"*/\\n\"),\"GOTO\"===this.token.toString())i"\
  "f(this.children.length>0){t+=\"goto label_\"+this.children[0].t"\
  "oken.position+\";\\n\"}else{t+=`goto label_${0};\\n`}if(this.chil"\
  "dren.length>0){t+=`  (if (${this.rhs})\\n`;for(let e of this.c"\
  "hildren)if(null!==e){const r=e.toString();\"\"!=r&&(t+=`  ${r}\\"\
  "n`)}t+=\"  )\\n\"}return void 0!==this.lhs&&void 0!==this.rhs?t+"\
  "`    ( ${this.lhs} ${this.token} ${this.rhs} )`:t+this.token."\
  "toString()}}G.EsilNode=EsilNode;class EsilParser{constructor("\
  "t){this.cur=0,this.r2=t,this.cur=0,this.stack=[],this.nodes=["\
  "],this.tokens=[],this.root=new EsilNode(new EsilToken(\"functi"\
  "on\",0),\"block\")}toJSON(){if(this.stack.length>0)throw new Err"\
  "or(\"The ESIL stack is not empty\");return JSON.stringify(this."\
  "root,null,2)}toEsil(){return this.nodes.map((t=>t.toEsil()))."\
  "join(\",\")}optimizeFlags(t){void 0!==t.rhs&&this.optimizeFlags"\
  "(t.rhs),void 0!==t.lhs&&this.optimizeFlags(t.lhs);for(let e=0"\
  ";e<t.children.length;e++)this.optimizeFlags(t.children[e]);co"\
  "nst e=t.toString();if(+e>4096){const r=r2.cmd(`fd.@ ${e}`).tr"\
  "im().split(\"\\n\")[0].trim();\"\"!=r&&-1===r.indexOf(\"+\")&&(t.tok"\
  "en.text=r)}}optimize(t){-1!=t.indexOf(\"flag\")&&this.optimizeF"\
  "lags(this.root)}toString(){return this.root.children.map((t=>"\
  "t.toString())).join(\";\\n\")}reset(){this.nodes=[],this.stack=["\
  "],this.tokens=[],this.cur=0,this.root=new EsilNode(new EsilTo"\
  "ken(\"function\",0),\"block\")}parseRange(t,e){let r=t;for(;r<thi"\
  "s.tokens.length&&r<e;){const t=this.peek(r);if(!t)break;this."\
  "cur=r,this.pushToken(t),r=this.cur,r++}}parseFunction(t){var "\
  "e=this;function r(t){const r=r2.cmd(\"pie \"+t+\" @e:scr.color=0"\
  "\").trim().split(\"\\n\");for(const t of r){if(0===t.length){cons"\
  "ole.log(\"Empty\");continue}const r=t.split(\" \");r.length>1&&(r"\
  "2.cmd(`s ${r[0]}`),e.parse(r[1],r[0]),e.optimize(\"flags,label"\
  "s\"))}}const s=r2.cmd(\"?v $$\").trim();void 0===t&&(t=s);const "\
  "i=r2.cmdj(`afbj@${t}`);for(let t of i)r2.cmd(`s ${t.addr}`),r"\
  "(t.ninstr);r2.cmd(`s ${s}`)}parse(t,e){const r=t.trim().split"\
  "(\",\").map((t=>t.trim())),s=this.tokens.length;for(let t of r)"\
  "{const r=new EsilToken(t,this.tokens.length);void 0!==e&&(r.a"\
  "ddr=e),this.tokens.push(r)}const i=this.tokens.length;this.pa"\
  "rseRange(s,i)}peek(t){return this.tokens[t]}pushToken(t){if(t"\
  "his.isNumber(t)){const e=new EsilNode(t,\"number\");this.stack."\
  "push(e),this.nodes.push(e)}else if(this.isInternal(t)){const "\
  "e=new EsilNode(t,\"flag\");this.stack.push(e),this.nodes.push(e"\
  ")}else if(this.isOperation(t));else{const e=new EsilNode(t,\"r"\
  "egister\");this.stack.push(e),this.nodes.push(e)}}isNumber(t){"\
  "return!!t.toString().startsWith(\"0\")||+t>0}isInternal(t){cons"\
  "t e=t.toString();return e.startsWith(\"$\")&&e.length>1}parseUn"\
  "til(t){const e=t+1;let r=e;const s=[],i=this.nodes.length;for"\
  "(this.stack.forEach((t=>s.push(t)));r<this.tokens.length;){co"\
  "nst t=this.peek(r);if(!t)break;if(\"}\"===t.toString())break;if"\
  "(\"}{\"===t.toString())break;r++}this.stack=s;const n=r;this.pa"\
  "rseRange(e,n);return this.nodes.length==i?null:this.nodes[thi"\
  "s.nodes.length-1]}getNodeFor(t){if(void 0===this.peek(t))retu"\
  "rn null;for(let e of this.nodes)if(e.token.position===t)retur"\
  "n e;return this.nodes.push(new EsilNode(new EsilToken(\"label\""\
  ",t),\"label\")),null}findNodeFor(t){for(let e of this.nodes)if("\
  "e.token.position===t)return e;return null}isOperation(t){swit"\
  "ch(t.toString()){case\"[1]\":case\"[2]\":case\"[4]\":case\"[8]\":if(!"\
  "(this.stack.length>=1))throw new Error(\"Stack needs more item"\
  "s\");{const t=this.stack.pop();new EsilNode(t.token,\"operation"\
  "\");this.stack.push(t)}return!0;case\"!\":if(!(this.stack.length"\
  ">=1))throw new Error(\"Stack needs more items\");{const e=new E"\
  "silNode(new EsilToken(\"\",t.position),\"none\"),r=this.stack.pop"\
  "(),s=new EsilNode(t,\"operation\");s.setSides(e,r),this.stack.p"\
  "ush(s)}return!0;case\"\":case\"}\":case\"}{\":return!0;case\"DUP\":{i"\
  "f(this.stack.length<1)throw new Error(\"goto cant pop\");const "\
  "t=this.stack.pop();this.stack.push(t),this.stack.push(t)}retu"\
  "rn!0;case\"GOTO\":if(null!==this.peek(t.position-1)){if(this.st"\
  "ack.length<1)throw new Error(\"goto cant pop\");const e=this.st"\
  "ack.pop();if(null!==e){const r=0|+e.toString();if(r>0){const "\
  "e=this.peek(r);if(void 0!==e){e.label=\"label_\"+r,e.comment=\"h"\
  "ehe\";const s=new EsilNode(t,\"goto\"),i=this.getNodeFor(e.posit"\
  "ion);null!=i&&s.children.push(i),this.root.children.push(s)}e"\
  "lse console.error(\"Cannot find goto node\")}else console.error"\
  "(\"Cannot find dest node for goto\")}}return!0;case\"?{\":if(!(th"\
  "is.stack.length>=1))throw new Error(\"Stack needs more items\")"\
  ";{const e=new EsilNode(new EsilToken(\"if\",t.position),\"none\")"\
  ",r=this.stack.pop(),s=new EsilNode(t,\"operation\");s.setSides("\
  "e,r);let i=this.parseUntil(t.position),n=null;null!==i&&(s.ch"\
  "ildren.push(i),this.nodes.push(i),n=this.parseUntil(i.token.p"\
  "osition+1),null!==n&&(s.children.push(n),this.nodes.push(n)))"\
  ",this.nodes.push(s),this.root.children.push(s),null!==n&&(thi"\
  "s.cur=n.token.position)}return!0;case\"-\":if(!(this.stack.leng"\
  "th>=2))throw new Error(\"Stack needs more items\");{const e=thi"\
  "s.stack.pop(),r=this.stack.pop(),s=new EsilNode(t,\"operation\""\
  ");s.setSides(e,r),this.stack.length,this.stack.push(s),this.n"\
  "odes.push(s)}return!0;case\"<\":case\">\":case\"^\":case\"&\":case\"|\""\
  ":case\"+\":case\"*\":case\"/\":case\">>=\":case\"<<=\":case\">>>=\":case\""\
  "<<<=\":case\">>>>=\":case\"<<<<=\":if(!(this.stack.length>=2))thro"\
  "w new Error(\"Stack needs more items\");{const e=this.stack.pop"\
  "(),r=this.stack.pop(),s=new EsilNode(t,\"operation\");s.setSide"\
  "s(e,r),this.stack.length,this.stack.push(s),this.nodes.push(s"\
  ")}return!0;case\"=\":case\":=\":case\"-=\":case\"+=\":case\"==\":case\"="\
  "[1]\":case\"=[2]\":case\"=[4]\":case\"=[8]\":if(!(this.stack.length>"\
  "=2))throw new Error(\"Stack needs more items\");{const e=this.s"\
  "tack.pop(),r=this.stack.pop(),s=new EsilNode(t,\"operation\");s"\
  ".setSides(e,r),0===this.stack.length&&this.root.children.push"\
  "(s),this.nodes.push(s)}return!0}return!1}}G.EsilParser=EsilPa"\
  "rser;\n";
