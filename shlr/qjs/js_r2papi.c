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
  "structor(t){this.r2=t}toString(){return\"[object R2Papi]\"}toJS"\
  "ON(){return this.toString()}getBaseAddress(){return new Nativ"\
  "ePointer(this.cmd(\"e bin.baddr\"))}jsonToTypescript(t,e){let r"\
  "=`interface ${t} {\\n`;e.length&&e.length>0&&(e=e[0]);for(let "\
  "t of Object.keys(e)){r+=`    ${t}: ${typeof e[t]};\\n`}return`"\
  "${r}}\\n`}getBits(){return this.cmd(\"-b\")}getArch(){return thi"\
  "s.cmd(\"-a\")}getCpu(){return this.cmd(\"-e asm.cpu\")}setArch(t,"\
  "e){this.cmd(\"-a \"+t),void 0!==e&&this.cmd(\"-b \"+e)}setFlagSpa"\
  "ce(t){this.cmd(\"fs \"+t)}setLogLevel(t){return this.cmd(\"e log"\
  ".level=\"+t),this}newMap(t,e,r,s,i,n=\"\"){this.cmd(`om ${t} ${e"\
  "} ${r} ${s} ${i} ${n}`)}at(t){return new NativePointer(t)}get"\
  "Shell(){return new shell_js_1.R2PapiShell(this)}version(){ret"\
  "urn this.r2.cmd(\"?Vq\").trim()}platform(){return this.r2.cmd(\""\
  "uname\").trim()}arch(){return this.r2.cmd(\"uname -a\").trim()}b"\
  "its(){return this.r2.cmd(\"uname -b\").trim()}id(){return+this."\
  "r2.cmd(\"?vi:$p\")}printAt(t,e,r){}clearScreen(){return this.r2"\
  ".cmd(\"!clear\"),this}getConfig(t){if(\"\"===t)return new Error(\""\
  "Empty key\");return\"\"===this.r2.cmd(`e~^${t} =`).trim()?new Er"\
  "ror(\"Config key does not exist\"):this.r2.call(\"e \"+t).trim()}"\
  "setConfig(t,e){return this.r2.call(\"e \"+t+\"=\"+e),this}getRegi"\
  "sterStateForEsil(){return this.cmdj(\"dre\").trim()}getRegister"\
  "s(){return this.cmdj(\"drj\")}resizeFile(t){return this.cmd(`r "\
  "${t}`),this}insertNullBytes(t,e){return void 0===e&&(e=\"$$\"),"\
  "this.cmd(`r+${t}@${e}`),this}removeBytes(t,e){return void 0=="\
  "=e&&(e=\"$$\"),this.cmd(`r-${t}@${e}`),this}seek(t){return this"\
  ".cmd(`s ${t}`),this}currentSeek(){return new NativePointer(\"$"\
  "$\")}seekToRelativeOpcode(t){return this.cmd(`so ${t}`),this.c"\
  "urrentSeek()}getBlockSize(){return+this.cmd(\"b\")}setBlockSize"\
  "(t){return this.cmd(`b ${t}`),this}countFlags(){return Number"\
  "(this.cmd(\"f~?\"))}countFunctions(){return Number(this.cmd(\"af"\
  "lc\"))}analyzeFunctionsWithEsil(t){this.cmd(\"aaef\")}analyzePro"\
  "gramWithEsil(t){this.cmd(\"aae\")}analyzeProgram(t){switch(void"\
  " 0===t&&(t=0),t){case 0:this.cmd(\"aa\");break;case 1:this.cmd("\
  "\"aaa\");break;case 2:this.cmd(\"aaaa\");break;case 3:this.cmd(\"a"\
  "aaaa\")}return this}enumerateThreads(){return[{context:this.cm"\
  "dj(\"drj\"),id:0,state:\"waiting\",selected:!0}]}currentThreadId("\
  "){return+this.cmd(\"e cfg.debug\")?+this.cmd(\"dpt.\"):this.id()}"\
  "setRegisters(t){for(let e of Object.keys(t)){const r=t[e];thi"\
  "s.r2.cmd(\"dr \"+e+\"=\"+r)}}hex(t){return this.r2.cmd(\"?v \"+t).t"\
  "rim()}step(){return this.r2.cmd(\"ds\"),this}stepOver(){return "\
  "this.r2.cmd(\"dso\"),this}math(t){return+this.r2.cmd(\"?v \"+t)}s"\
  "tepUntil(t){this.cmd(`dsu ${t}`)}enumerateXrefsTo(t){return t"\
  "his.call(\"axtq \"+t).trim().split(/\\n/)}findXrefsTo(t,e){e?thi"\
  "s.call(\"/r \"+t):this.call(\"/re \"+t)}analyzeFunctionsFromCalls"\
  "(){return this.call(\"aac\"),this}analyzeFunctionsWithPreludes("\
  "){return this.call(\"aap\"),this}analyzeObjCReferences(){return"\
  " this.cmd(\"aao\"),this}analyzeImports(){return this.cmd(\"af @ "\
  "sym.imp.*\"),this}searchDisasm(t){return this.callj(\"/ad \"+t)}"\
  "searchString(t){return this.cmdj(\"/j \"+t)}searchBytes(t){cons"\
  "t e=t.map((function(t){return(255&t).toString(16)})).join(\"\")"\
  ";return this.cmdj(\"/xj \"+e)}binInfo(){try{return this.cmdj(\"i"\
  "j~{bin}\")}catch(t){return{}}}selectBinary(t){this.call(`ob ${"\
  "t}`)}openFile(t){const e=this.call(\"oqq\").trim();this.call(`o"\
  " ${t}`);const r=this.call(\"oqq\").trim();return e===r?new Erro"\
  "r(\"Cannot open file\"):parseInt(r)}openFileNomap(t){const e=th"\
  "is.call(\"oqq\").trim();this.call(`of ${t}`);const r=this.call("\
  "\"oqq\").trim();return e===r?new Error(\"Cannot open file\"):pars"\
  "eInt(r)}currentFile(t){return this.call(\"o.\").trim()}enumerat"\
  "ePlugins(t){switch(t){case\"bin\":return this.callj(\"Lij\");case"\
  "\"io\":return this.callj(\"Loj\");case\"core\":return this.callj(\"L"\
  "cj\");case\"arch\":return this.callj(\"LAj\");case\"anal\":return th"\
  "is.callj(\"Laj\");case\"lang\":return this.callj(\"Llj\")}return[]}"\
  "enumerateModules(){return this.callj(\"dmmj\")}enumerateFiles()"\
  "{return this.callj(\"oj\")}enumerateBinaries(){return this.call"\
  "j(\"obj\")}enumerateMaps(){return this.callj(\"omj\")}enumerateCl"\
  "asses(){return this.callj(\"icj\")}enumerateSymbols(){return th"\
  "is.callj(\"isj\")}enumerateExports(){return this.callj(\"iEj\")}e"\
  "numerateImports(){return this.callj(\"iij\")}enumerateLibraries"\
  "(){return this.callj(\"ilj\")}enumerateSections(){return this.c"\
  "allj(\"iSj\")}enumerateSegments(){return this.callj(\"iSSj\")}enu"\
  "merateEntrypoints(){return this.callj(\"iej\")}enumerateRelocat"\
  "ions(){return this.callj(\"irj\")}enumerateFunctions(){return t"\
  "his.cmdj(\"aflj\")}enumerateFlags(){return this.cmdj(\"fj\")}skip"\
  "(){this.r2.cmd(\"dss\")}ptr(t){return new NativePointer(t,this)"\
  "}call(t){return this.r2.call(t)}callj(t){return JSON.parse(th"\
  "is.call(t))}cmd(t){return this.r2.cmd(t)}cmdj(t){return JSON."\
  "parse(this.cmd(t))}log(t){return this.r2.log(t)}clippy(t){thi"\
  "s.r2.log(this.r2.cmd(\"?E \"+t))}ascii(t){this.r2.log(this.r2.c"\
  "md(\"?ea \"+t))}}G.R2Papi=R2Papi;class NativeFunction{construct"\
  "or(){}}G.NativeFunction=NativeFunction;class NativeCallback{c"\
  "onstructor(){}}G.NativeCallback=NativeCallback;class NativePo"\
  "inter{constructor(t,e){this.api=void 0===e?G.R:e,this.addr=(\""\
  "\"+t).trim()}setFlag(t){this.api.call(`f ${t}=${this.addr}`)}u"\
  "nsetFlag(){this.api.call(`f-${this.addr}`)}hexdump(t){let e=v"\
  "oid 0===t?\"\":\"\"+t;return this.api.cmd(`x${e}@${this.addr}`)}f"\
  "unctionGraph(t){return\"dot\"===t?this.api.cmd(`agfd@ ${this.ad"\
  "dr}`):\"json\"===t?this.api.cmd(`agfj@${this.addr}`):\"mermaid\"="\
  "==t?this.api.cmd(`agfm@${this.addr}`):this.api.cmd(`agf@${thi"\
  "s.addr}`)}readByteArray(t){return JSON.parse(this.api.cmd(`p8"\
  "j ${t}@${this.addr}`))}readHexString(t){return this.api.cmd(`"\
  "p8 ${t}@${this.addr}`).trim()}and(t){const e=this.api.call(`?"\
  "v ${this.addr} & ${t}`).trim();return new NativePointer(e)}or"\
  "(t){const e=this.api.call(`?v ${this.addr} | ${t}`).trim();re"\
  "turn new NativePointer(e)}add(t){const e=this.api.call(`?v ${"\
  "this.addr}+${t}`).trim();return new NativePointer(e)}sub(t){c"\
  "onst e=this.api.call(`?v ${this.addr}-${t}`).trim();return ne"\
  "w NativePointer(e)}writeByteArray(t){return this.api.cmd(\"wx "\
  "\"+t.join(\"\")),this}writeAssembly(t){return this.api.cmd(`wa $"\
  "{t} @ ${this.addr}`),this}writeCString(t){return this.api.cal"\
  "l(\"w \"+t),this}writeWideString(t){return this.api.call(\"ww \"+"\
  "t),this}asNumber(){const t=this.api.call(\"?vi \"+this.addr);re"\
  "turn parseInt(t)}isNull(){return 0==this.asNumber()}compare(t"\
  "){return\"string\"!=typeof t&&\"number\"!=typeof t||(t=new Native"\
  "Pointer(t)),t.addr===this.addr||new NativePointer(t.addr).asN"\
  "umber()===this.asNumber()}pointsToNull(){return this.readPoin"\
  "ter().compare(0)}toJSON(){return this.toString()}toString(){r"\
  "eturn this.addr.trim()}writePointer(t){this.api.cmd(`wvp ${t}"\
  "@${this}`)}readRelativePointer(){return this.add(this.readS32"\
  "())}readPointer(){return new NativePointer(this.api.call(\"pvp"\
  "@\"+this.addr))}readS8(){return parseInt(this.api.cmd(`pv1d@${"\
  "this.addr}`))}readU8(){return parseInt(this.api.cmd(`pv1u@${t"\
  "his.addr}`))}readU16(){return parseInt(this.api.cmd(`pv2d@${t"\
  "his.addr}`))}readU16le(){return parseInt(this.api.cmd(`pv2d@$"\
  "{this.addr}@e:cfg.bigendian=false`))}readU16be(){return parse"\
  "Int(this.api.cmd(`pv2d@${this.addr}@e:cfg.bigendian=true`))}r"\
  "eadS16(){return parseInt(this.api.cmd(`pv2d@${this.addr}`))}r"\
  "eadS16le(){return parseInt(this.api.cmd(`pv2d@${this.addr}@e:"\
  "cfg.bigendian=false`))}readS16be(){return parseInt(this.api.c"\
  "md(`pv2d@${this.addr}@e:cfg.bigendian=true`))}readS32(){retur"\
  "n parseInt(this.api.cmd(`pv4d@${this.addr}`))}readU32(){retur"\
  "n parseInt(this.api.cmd(`pv4u@${this.addr}`))}readU32le(){ret"\
  "urn parseInt(this.api.cmd(`pv4u@${this.addr}@e:cfg.bigendian="\
  "false`))}readU32be(){return parseInt(this.api.cmd(`pv4u@${thi"\
  "s.addr}@e:cfg.bigendian=true`))}readU64(){return parseInt(thi"\
  "s.api.cmd(`pv8u@${this.addr}`))}readU64le(){return parseInt(t"\
  "his.api.cmd(`pv8u@${this.addr}@e:cfg.bigendian=false`))}readU"\
  "64be(){return parseInt(this.api.cmd(`pv8u@${this.addr}@e:cfg."\
  "bigendian=true`))}writeInt(t){return this.writeU32(t)}writeU8"\
  "(t){return this.api.cmd(`wv1 ${t}@${this.addr}`),!0}writeU16("\
  "t){return this.api.cmd(`wv2 ${t}@${this.addr}`),!0}writeU16be"\
  "(t){return this.api.cmd(`wv2 ${t}@${this.addr}@e:cfg.bigendia"\
  "n=true`),!0}writeU16le(t){return this.api.cmd(`wv2 ${t}@${thi"\
  "s.addr}@e:cfg.bigendian=false`),!0}writeU32(t){return this.ap"\
  "i.cmd(`wv4 ${t}@${this.addr}`),!0}writeU32be(t){return this.a"\
  "pi.cmd(`wv4 ${t}@${this.addr}@e:cfg.bigendian=true`),!0}write"\
  "U32le(t){return this.api.cmd(`wv4 ${t}@${this.addr}@e:cfg.big"\
  "endian=false`),!0}writeU64(t){return this.api.cmd(`wv8 ${t}@$"\
  "{this.addr}`),!0}writeU64be(t){return this.api.cmd(`wv8 ${t}@"\
  "${this.addr}@e:cfg.bigendian=true`),!0}writeU64le(t){return t"\
  "his.api.cmd(`wv8 ${t}@${this.addr}@e:cfg.bigendian=false`),!0"\
  "}readInt32(){return this.readU32()}readCString(){return JSON."\
  "parse(this.api.cmd(`pszj@${this.addr}`)).string}readWideStrin"\
  "g(){return JSON.parse(this.api.cmd(`pswj@${this.addr}`)).stri"\
  "ng}readPascalString(){return JSON.parse(this.api.cmd(`pspj@${"\
  "this.addr}`)).string}instruction(){return this.api.cmdj(`aoj@"\
  "${this.addr}`)[0]}disassemble(t){let e=void 0===t?\"\":\"\"+t;ret"\
  "urn this.api.cmd(`pd ${e}@${this.addr}`)}analyzeFunction(){re"\
  "turn this.api.cmd(\"af@\"+this.addr),this}analyzeFunctionRecurs"\
  "ively(){return this.api.cmd(\"afr@\"+this.addr),this}name(){ret"\
  "urn this.api.cmd(\"fd \"+this.addr).trim()}methodName(){return "\
  "this.api.cmd(\"ic.@\"+this.addr).trim()}symbolName(){return thi"\
  "s.api.cmd(\"isj.@\"+this.addr).trim()}getFunction(){return this"\
  ".api.cmdj(\"afij@\"+this.addr)}basicBlock(){return this.api.cmd"\
  "j(\"abj@\"+this.addr)}functionBasicBlocks(){return this.api.cmd"\
  "j(\"afbj@\"+this.addr)}xrefs(){return this.api.cmdj(\"axtj@\"+thi"\
  "s.addr)}}G.NativePointer=NativePointer;class Base64{static en"\
  "code(t){return(0,G.b64)(t)}static decode(t){return(0,G.b64)(t"\
  ",!0)}}G.Base64=Base64;class R2AI{constructor(t,e){this.availa"\
  "ble=!1,this.model=\"\",this.available=\"\"!==G.r2.call(\"r2ai -h\")"\
  ".trim(),this.available?(G.r2.call(`r2ai -n ${t}`),this.model="\
  "e):console.error(\"ERROR: r2ai is not installed\")}reset(){this"\
  ".available&&G.r2.call(\"r2ai -R\")}setRole(t){this.available&&G"\
  ".r2.call(`r2ai -r ${t}`)}query(t){if(!this.available||\"\"==t)r"\
  "eturn\"\";G.r2.call(`r2ai -m ${this.model}`);const e=t.trim().r"\
  "eplace(/\\n/g,\".\");return G.r2.call(`r2ai ${e}`)}}Object.defin"\
  "eProperty(G,\"__esModule\",{value:!0}),G.R2PapiShell=void 0;cla"\
  "ss R2PapiShell{constructor(t){this.rp=t}mkdir(t,e){return!0=="\
  "=e?this.rp.call(`mkdir -p ${t}`):this.rp.call(`mkdir ${t}`),!"\
  "0}unlink(t){return this.rp.call(`rm ${t}`),!0}chdir(t){return"\
  " this.rp.call(`cd ${t}`),!0}ls(){return this.rp.call(\"ls -q\")"\
  ".trim().split(\"\\n\")}fileExists(t){return!1}open(t){this.rp.ca"\
  "ll(`open ${t}`)}system(t){return this.rp.call(`!${t}`),0}run("\
  "t){return this.rp.call(`rm ${t}`),0}mount(t,e){return this.rp"\
  ".call(`m ${t} ${e}`),!0}umount(t){this.rp.call(`m-${t}`)}chdi"\
  "r2(t){return void 0===t&&(t=\"/\"),this.rp.call(`mdq ${t}`),!0}"\
  "ls2(t){return void 0===t&&(t=\"/\"),this.rp.call(`mdq ${t}`).tr"\
  "im().split(\"\\n\")}enumerateMountpoints(){return this.rp.cmdj(\""\
  "mlj\")}isSymlink(t){return!1}isDirectory(t){return!1}}G.R2Papi"\
  "Shell=R2PapiShell,Object.defineProperty(G,\"__esModule\",{value"\
  ":!0}),G.EsilParser=G.EsilNode=G.EsilToken=void 0;class EsilTo"\
  "ken{constructor(t=\"\",e=0){this.label=\"\",this.comment=\"\",this."\
  "text=\"\",this.addr=\"0\",this.position=0,this.text=t,this.positi"\
  "on=e}toString(){return this.text}}G.EsilToken=EsilToken;class"\
  " EsilNode{constructor(t=new EsilToken,e=\"none\"){this.type=\"no"\
  "ne\",this.token=t,this.children=[]}setSides(t,e){this.lhs=t,th"\
  "is.rhs=e}addChildren(t,e){void 0!==t&&this.children.push(t),v"\
  "oid 0!==e&&this.children.push(e)}toEsil(){if(void 0!==this.lh"\
  "s&&void 0!==this.rhs){let t=this.lhs.toEsil();return\"\"!==t&&("\
  "t+=\",\"),`${this.rhs.toEsil()},${t}${this.token}`}return\"\"}toS"\
  "tring(){let t=\"\";if(\"\"!==this.token.label&&(t+=this.token.lab"\
  "el+\":\\n\"),this.token.addr,\"\"!==this.token.comment&&(t+=\"/*\"+t"\
  "his.token.comment+\"*/\\n\"),\"GOTO\"===this.token.toString())if(t"\
  "his.children.length>0){t+=\"goto label_\"+this.children[0].toke"\
  "n.position+\";\\n\"}else{t+=`goto label_${0};\\n`}if(this.childre"\
  "n.length>0){t+=`  (if (${this.rhs})\\n`;for(let e of this.chil"\
  "dren)if(null!==e){const r=e.toString();\"\"!=r&&(t+=`  ${r}\\n`)"\
  "}t+=\"  )\\n\"}return void 0!==this.lhs&&void 0!==this.rhs?t+`  "\
  "  ( ${this.lhs} ${this.token} ${this.rhs} )`:t+this.token.toS"\
  "tring()}}G.EsilNode=EsilNode;class EsilParser{constructor(t){"\
  "this.cur=0,this.r2=t,this.cur=0,this.stack=[],this.nodes=[],t"\
  "his.tokens=[],this.root=new EsilNode(new EsilToken(\"function\""\
  ",0),\"block\")}toJSON(){if(this.stack.length>0)throw new Error("\
  "\"The ESIL stack is not empty\");return JSON.stringify(this.roo"\
  "t,null,2)}toEsil(){return this.nodes.map((t=>t.toEsil())).joi"\
  "n(\",\")}optimizeFlags(t){void 0!==t.rhs&&this.optimizeFlags(t."\
  "rhs),void 0!==t.lhs&&this.optimizeFlags(t.lhs);for(let e=0;e<"\
  "t.children.length;e++)this.optimizeFlags(t.children[e]);const"\
  " e=t.toString();if(+e>4096){const r=r2.cmd(`fd.@ ${e}`).trim("\
  ").split(\"\\n\")[0].trim();\"\"!=r&&-1===r.indexOf(\"+\")&&(t.token."\
  "text=r)}}optimize(t){-1!=t.indexOf(\"flag\")&&this.optimizeFlag"\
  "s(this.root)}toString(){return this.root.children.map((t=>t.t"\
  "oString())).join(\";\\n\")}reset(){this.nodes=[],this.stack=[],t"\
  "his.tokens=[],this.cur=0,this.root=new EsilNode(new EsilToken"\
  "(\"function\",0),\"block\")}parseRange(t,e){let r=t;for(;r<this.t"\
  "okens.length&&r<e;){const t=this.peek(r);if(!t)break;this.cur"\
  "=r,this.pushToken(t),r=this.cur,r++}}parseFunction(t){var e=t"\
  "his;function r(t){const r=r2.cmd(\"pie \"+t+\" @e:scr.color=0\")."\
  "trim().split(\"\\n\");for(const t of r){if(0===t.length){console"\
  ".log(\"Empty\");continue}const r=t.split(\" \");r.length>1&&(r2.c"\
  "md(`s ${r[0]}`),e.parse(r[1],r[0]),e.optimize(\"flags,labels\")"\
  ")}}const s=r2.cmd(\"?v $$\").trim();void 0===t&&(t=s);const i=r"\
  "2.cmdj(`afbj@${t}`);for(let t of i)r2.cmd(`s ${t.addr}`),r(t."\
  "ninstr);r2.cmd(`s ${s}`)}parse(t,e){const r=t.trim().split(\","\
  "\").map((t=>t.trim())),s=this.tokens.length;for(let t of r){co"\
  "nst r=new EsilToken(t,this.tokens.length);void 0!==e&&(r.addr"\
  "=e),this.tokens.push(r)}const i=this.tokens.length;this.parse"\
  "Range(s,i)}peek(t){return this.tokens[t]}pushToken(t){if(this"\
  ".isNumber(t)){const e=new EsilNode(t,\"number\");this.stack.pus"\
  "h(e),this.nodes.push(e)}else if(this.isInternal(t)){const e=n"\
  "ew EsilNode(t,\"flag\");this.stack.push(e),this.nodes.push(e)}e"\
  "lse if(this.isOperation(t));else{const e=new EsilNode(t,\"regi"\
  "ster\");this.stack.push(e),this.nodes.push(e)}}isNumber(t){ret"\
  "urn!!t.toString().startsWith(\"0\")||+t>0}isInternal(t){const e"\
  "=t.toString();return e.startsWith(\"$\")&&e.length>1}parseUntil"\
  "(t){const e=t+1;let r=e;const s=[],i=this.nodes.length;for(th"\
  "is.stack.forEach((t=>s.push(t)));r<this.tokens.length;){const"\
  " t=this.peek(r);if(!t)break;if(\"}\"===t.toString())break;if(\"}"\
  "{\"===t.toString())break;r++}this.stack=s;const n=r;this.parse"\
  "Range(e,n);return this.nodes.length==i?null:this.nodes[this.n"\
  "odes.length-1]}getNodeFor(t){if(void 0===this.peek(t))return "\
  "null;for(let e of this.nodes)if(e.token.position===t)return e"\
  ";return this.nodes.push(new EsilNode(new EsilToken(\"label\",t)"\
  ",\"label\")),null}findNodeFor(t){for(let e of this.nodes)if(e.t"\
  "oken.position===t)return e;return null}isOperation(t){switch("\
  "t.toString()){case\"[1]\":case\"[2]\":case\"[4]\":case\"[8]\":if(!(th"\
  "is.stack.length>=1))throw new Error(\"Stack needs more items\")"\
  ";{const t=this.stack.pop();new EsilNode(t.token,\"operation\");"\
  "this.stack.push(t)}return!0;case\"!\":if(!(this.stack.length>=1"\
  "))throw new Error(\"Stack needs more items\");{const e=new Esil"\
  "Node(new EsilToken(\"\",t.position),\"none\"),r=this.stack.pop(),"\
  "s=new EsilNode(t,\"operation\");s.setSides(e,r),this.stack.push"\
  "(s)}return!0;case\"\":case\"}\":case\"}{\":return!0;case\"DUP\":{if(t"\
  "his.stack.length<1)throw new Error(\"goto cant pop\");const t=t"\
  "his.stack.pop();this.stack.push(t),this.stack.push(t)}return!"\
  "0;case\"GOTO\":if(null!==this.peek(t.position-1)){if(this.stack"\
  ".length<1)throw new Error(\"goto cant pop\");const e=this.stack"\
  ".pop();if(null!==e){const r=0|+e.toString();if(r>0){const e=t"\
  "his.peek(r);if(void 0!==e){e.label=\"label_\"+r,e.comment=\"hehe"\
  "\";const s=new EsilNode(t,\"goto\"),i=this.getNodeFor(e.position"\
  ");null!=i&&s.children.push(i),this.root.children.push(s)}else"\
  " console.error(\"Cannot find goto node\")}else console.error(\"C"\
  "annot find dest node for goto\")}}return!0;case\"?{\":if(!(this."\
  "stack.length>=1))throw new Error(\"Stack needs more items\");{c"\
  "onst e=new EsilNode(new EsilToken(\"if\",t.position),\"none\"),r="\
  "this.stack.pop(),s=new EsilNode(t,\"operation\");s.setSides(e,r"\
  ");let i=this.parseUntil(t.position),n=null;null!==i&&(s.child"\
  "ren.push(i),this.nodes.push(i),n=this.parseUntil(i.token.posi"\
  "tion+1),null!==n&&(s.children.push(n),this.nodes.push(n))),th"\
  "is.nodes.push(s),this.root.children.push(s),null!==n&&(this.c"\
  "ur=n.token.position)}return!0;case\"-\":if(!(this.stack.length>"\
  "=2))throw new Error(\"Stack needs more items\");{const e=this.s"\
  "tack.pop(),r=this.stack.pop(),s=new EsilNode(t,\"operation\");s"\
  ".setSides(e,r),this.stack.length,this.stack.push(s),this.node"\
  "s.push(s)}return!0;case\"<\":case\">\":case\"^\":case\"&\":case\"|\":ca"\
  "se\"+\":case\"*\":case\"/\":case\">>=\":case\"<<=\":case\">>>=\":case\"<<<"\
  "=\":case\">>>>=\":case\"<<<<=\":if(!(this.stack.length>=2))throw n"\
  "ew Error(\"Stack needs more items\");{const e=this.stack.pop(),"\
  "r=this.stack.pop(),s=new EsilNode(t,\"operation\");s.setSides(e"\
  ",r),this.stack.length,this.stack.push(s),this.nodes.push(s)}r"\
  "eturn!0;case\"=\":case\":=\":case\"-=\":case\"+=\":case\"==\":case\"=[1]"\
  "\":case\"=[2]\":case\"=[4]\":case\"=[8]\":if(!(this.stack.length>=2)"\
  ")throw new Error(\"Stack needs more items\");{const e=this.stac"\
  "k.pop(),r=this.stack.pop(),s=new EsilNode(t,\"operation\");s.se"\
  "tSides(e,r),0===this.stack.length&&this.root.children.push(s)"\
  ",this.nodes.push(s)}return!0}return!1}}G.EsilParser=EsilParse"\
  "r;\n";
