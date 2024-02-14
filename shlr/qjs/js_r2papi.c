static const char *const js_r2papi_qjs = "" \
  "Object.defineProperty(G,\"__esModule\",{value:!0}),G.NativePoin"\
  "ter=G.NativeCallback=G.NativeFunction=G.R2Papi=G.Assembler=G."\
  "ProcessClass=G.ModuleClass=G.ThreadClass=void 0;const shell_j"\
  "s_1=G;class ThreadClass{constructor(t){this.api=null,this.api"\
  "=t}backtrace(){return r2pipe_js_1.r2.call(\"dbtj\")}sleep(t){re"\
  "turn r2pipe_js_1.r2.call(\"sleep \"+t)}}G.ThreadClass=ThreadCla"\
  "ss;class ModuleClass{constructor(t){this.api=null,this.api=t}"\
  "fileName(){return this.api.call(\"dpe\").trim()}name(){return\"M"\
  "odule\"}findBaseAddress(){return\"TODO\"}findExportByName(t){ret"\
  "urn\"TODO\"}getBaseAddress(t){return\"TODO\"}getExportByName(t){r"\
  "eturn r2pipe_js_1.r2.call(\"iE,name/eq/\"+t+\",vaddr/cols,:quiet"\
  "\")}enumerateExports(){return r2pipe_js_1.r2.callj(\"iEj\")}enum"\
  "erateImports(){return r2pipe_js_1.r2.callj(\"iij\")}enumerateRa"\
  "nges(){return r2pipe_js_1.r2.callj(\"isj\")}enumerateSymbols(){"\
  "return r2pipe_js_1.r2.callj(\"isj\")}}G.ModuleClass=ModuleClass"\
  ";class ProcessClass{constructor(t){this.r2=null,this.r2=t}enu"\
  "merateMallocRanges(){}enumerateSystemRanges(){}enumerateRange"\
  "s(){}enumerateThreads(){return r2pipe_js_1.r2.call(\"dptj\")}en"\
  "umerateModules(){if(r2pipe_js_1.r2.call(\"cfg.json.num=string\""\
  "),r2pipe_js_1.r2.callj(\"e cfg.debug\")){const t=r2pipe_js_1.r2"\
  ".callj(\"dmmj\"),e=[];for(const r of t){const t={base:new Nativ"\
  "ePointer(r.addr),size:new NativePointer(r.addr_end).sub(r.add"\
  "r),path:r.file,name:r.name};e.push(t)}return e}{const t=t=>{c"\
  "onst e=t.split(\"/\");return e[e.length-1]},e=r2pipe_js_1.r2.ca"\
  "llj(\"obj\"),r=[];for(const s of e){const e={base:new NativePoi"\
  "nter(s.addr),size:s.size,path:s.file,name:t(s.file)};r.push(e"\
  ")}const s=r2pipe_js_1.r2.callj(\"ilj\");for(const e of s){const"\
  " s={base:0,size:0,path:e,name:t(e)};r.push(s)}return r}}getMo"\
  "duleByAddress(t){}getModuleByName(t){}codeSigningPolicy(){ret"\
  "urn\"optional\"}getTmpDir(){return this.r2.call(\"e dir.tmp\").tr"\
  "im()}getHomeDir(){return this.r2.call(\"e dir.home\").trim()}pl"\
  "atform(){return this.r2.call(\"e asm.os\").trim()}getCurrentDir"\
  "(){return this.r2.call(\"pwd\").trim()}getCurrentThreadId(){ret"\
  "urn+this.r2.call(\"dpq\")}pageSize(){return 64===this.r2.callj("\
  "\"e asm.bits\")&&this.r2.call(\"e asm.arch\").startsWith(\"arm\")?1"\
  "6384:4096}isDebuggerAttached(){return this.r2.callj(\"e cfg.de"\
  "bug\")}setExceptionHandler(){}id(){return this.r2.callj(\"dpq\")"\
  "}pointerSize(){return r2pipe_js_1.r2.callj(\"e asm.bits\")/8}}G"\
  ".ProcessClass=ProcessClass;class Assembler{constructor(t){thi"\
  "s.program=\"\",this.labels={},this.endian=!1,this.pc=0,this.r2="\
  "null,this.r2=void 0===t?r2pipe_js_1.r2:t,this.program=\"\",this"\
  ".labels={}}setProgramCounter(t){this.pc=t}setEndian(t){this.e"\
  "ndian=t}toString(){return this.program}append(t){this.pc+=t.l"\
  "ength/2,this.program+=t}label(t){const e=this.pc;return this."\
  "labels[t]=this.pc,e}asm(t){let e=this.r2.cmd('\"\"pa '+t).trim("\
  ");e.length<16||(e=\"____\"),this.append(e)}}G.Assembler=Assembl"\
  "er;class R2Papi{constructor(t){this.r2=t}toString(){return\"[o"\
  "bject R2Papi]\"}toJSON(){return this.toString()}getBaseAddress"\
  "(){return new NativePointer(this.cmd(\"e bin.baddr\"))}jsonToTy"\
  "pescript(t,e){let r=`interface ${t} {\\n`;e.length&&e.length>0"\
  "&&(e=e[0]);for(let t of Object.keys(e)){r+=`    ${t}: ${typeo"\
  "f e[t]};\\n`}return`${r}}\\n`}getBits(){return this.cmd(\"-b\")}g"\
  "etArch(){return this.cmd(\"-a\")}getCpu(){return this.cmd(\"-e a"\
  "sm.cpu\")}setArch(t,e){this.cmd(\"-a \"+t),void 0!==e&&this.cmd("\
  "\"-b \"+e)}setFlagSpace(t){this.cmd(\"fs \"+t)}setLogLevel(t){ret"\
  "urn this.cmd(\"e log.level=\"+t),this}newMap(t,e,r,s,i,n=\"\"){th"\
  "is.cmd(`om ${t} ${e} ${r} ${s} ${i} ${n}`)}at(t){return new N"\
  "ativePointer(t)}getShell(){return new shell_js_1.R2PapiShell("\
  "this)}version(){return this.r2.cmd(\"?Vq\").trim()}platform(){r"\
  "eturn this.r2.cmd(\"uname\").trim()}arch(){return this.r2.cmd(\""\
  "uname -a\").trim()}bits(){return this.r2.cmd(\"uname -b\").trim("\
  ")}id(){return+this.r2.cmd(\"?vi:$p\")}printAt(t,e,r){}clearScre"\
  "en(){return this.r2.cmd(\"!clear\"),this}getConfig(t){if(\"\"===t"\
  ")return new Error(\"Empty key\");return\"\"===this.r2.cmd(`e~^${t"\
  "} =`).trim()?new Error(\"Config key does not exist\"):this.r2.c"\
  "all(\"e \"+t).trim()}setConfig(t,e){return this.r2.call(\"e \"+t+"\
  "\"=\"+e),this}getRegisterStateForEsil(){return this.cmdj(\"dre\")"\
  ".trim()}getRegisters(){return this.cmdj(\"drj\")}resizeFile(t){"\
  "return this.cmd(`r ${t}`),this}insertNullBytes(t,e){return vo"\
  "id 0===e&&(e=\"$$\"),this.cmd(`r+${t}@${e}`),this}removeBytes(t"\
  ",e){return void 0===e&&(e=\"$$\"),this.cmd(`r-${t}@${e}`),this}"\
  "seek(t){return this.cmd(`s ${t}`),this}currentSeek(){return n"\
  "ew NativePointer(\"$$\")}seekToRelativeOpcode(t){return this.cm"\
  "d(`so ${t}`),this.currentSeek()}getBlockSize(){return+this.cm"\
  "d(\"b\")}setBlockSize(t){return this.cmd(`b ${t}`),this}countFl"\
  "ags(){return Number(this.cmd(\"f~?\"))}countFunctions(){return "\
  "Number(this.cmd(\"aflc\"))}analyzeFunctionsWithEsil(t){this.cmd"\
  "(\"aaef\")}analyzeProgramWithEsil(t){this.cmd(\"aae\")}analyzePro"\
  "gram(t){switch(void 0===t&&(t=0),t){case 0:this.cmd(\"aa\");bre"\
  "ak;case 1:this.cmd(\"aaa\");break;case 2:this.cmd(\"aaaa\");break"\
  ";case 3:this.cmd(\"aaaaa\")}return this}enumerateThreads(){retu"\
  "rn[{context:this.cmdj(\"drj\"),id:0,state:\"waiting\",selected:!0"\
  "}]}currentThreadId(){return+this.cmd(\"e cfg.debug\")?+this.cmd"\
  "(\"dpt.\"):this.id()}setRegisters(t){for(let e of Object.keys(t"\
  ")){const r=t[e];this.r2.cmd(\"dr \"+e+\"=\"+r)}}hex(t){return thi"\
  "s.r2.cmd(\"?v \"+t).trim()}step(){return this.r2.cmd(\"ds\"),this"\
  "}stepOver(){return this.r2.cmd(\"dso\"),this}math(t){return+thi"\
  "s.r2.cmd(\"?v \"+t)}stepUntil(t){this.cmd(`dsu ${t}`)}enumerate"\
  "XrefsTo(t){return this.call(\"axtq \"+t).trim().split(/\\n/)}fin"\
  "dXrefsTo(t,e){e?this.call(\"/r \"+t):this.call(\"/re \"+t)}analyz"\
  "eFunctionsFromCalls(){return this.call(\"aac\"),this}analyzeFun"\
  "ctionsWithPreludes(){return this.call(\"aap\"),this}analyzeObjC"\
  "References(){return this.cmd(\"aao\"),this}analyzeImports(){ret"\
  "urn this.cmd(\"af @ sym.imp.*\"),this}searchDisasm(t){return th"\
  "is.callj(\"/ad \"+t)}searchString(t){return this.cmdj(\"/j \"+t)}"\
  "searchBytes(t){const e=t.map((function(t){return(255&t).toStr"\
  "ing(16)})).join(\"\");return this.cmdj(\"/xj \"+e)}binInfo(){try{"\
  "return this.cmdj(\"ij~{bin}\")}catch(t){return{}}}selectBinary("\
  "t){this.call(`ob ${t}`)}openFile(t){const e=this.call(\"oqq\")."\
  "trim();this.call(`o ${t}`);const r=this.call(\"oqq\").trim();re"\
  "turn e===r?new Error(\"Cannot open file\"):parseInt(r)}openFile"\
  "Nomap(t){const e=this.call(\"oqq\").trim();this.call(`of ${t}`)"\
  ";const r=this.call(\"oqq\").trim();return e===r?new Error(\"Cann"\
  "ot open file\"):parseInt(r)}currentFile(t){return this.call(\"o"\
  ".\").trim()}enumeratePlugins(t){switch(t){case\"bin\":return thi"\
  "s.callj(\"Lij\");case\"io\":return this.callj(\"Loj\");case\"core\":r"\
  "eturn this.callj(\"Lcj\");case\"arch\":return this.callj(\"LAj\");c"\
  "ase\"anal\":return this.callj(\"Laj\");case\"lang\":return this.cal"\
  "lj(\"Llj\")}return[]}enumerateModules(){return this.callj(\"dmmj"\
  "\")}enumerateFiles(){return this.callj(\"oj\")}enumerateBinaries"\
  "(){return this.callj(\"obj\")}enumerateMaps(){return this.callj"\
  "(\"omj\")}enumerateClasses(){return this.callj(\"icj\")}enumerate"\
  "Symbols(){return this.callj(\"isj\")}enumerateExports(){return "\
  "this.callj(\"iEj\")}enumerateImports(){return this.callj(\"iij\")"\
  "}enumerateLibraries(){return this.callj(\"ilj\")}enumerateSecti"\
  "ons(){return this.callj(\"iSj\")}enumerateSegments(){return thi"\
  "s.callj(\"iSSj\")}enumerateEntrypoints(){return this.callj(\"iej"\
  "\")}enumerateRelocations(){return this.callj(\"irj\")}enumerateF"\
  "unctions(){return this.cmdj(\"aflj\")}enumerateFlags(){return t"\
  "his.cmdj(\"fj\")}skip(){this.r2.cmd(\"dss\")}ptr(t){return new Na"\
  "tivePointer(t,this)}call(t){return this.r2.call(t)}callj(t){r"\
  "eturn JSON.parse(this.call(t))}cmd(t){return this.r2.cmd(t)}c"\
  "mdj(t){return JSON.parse(this.cmd(t))}log(t){return this.r2.l"\
  "og(t)}clippy(t){this.r2.log(this.r2.cmd(\"?E \"+t))}ascii(t){th"\
  "is.r2.log(this.r2.cmd(\"?ea \"+t))}}G.R2Papi=R2Papi;class Nativ"\
  "eFunction{constructor(){}}G.NativeFunction=NativeFunction;cla"\
  "ss NativeCallback{constructor(){}}G.NativeCallback=NativeCall"\
  "back;class NativePointer{constructor(t,e){this.api=void 0===e"\
  "?G.R:e,this.addr=(\"\"+t).trim()}setFlag(t){this.api.call(`f ${"\
  "t}=${this.addr}`)}unsetFlag(){this.api.call(`f-${this.addr}`)"\
  "}hexdump(t){let e=void 0===t?\"\":\"\"+t;return this.api.cmd(`x${"\
  "e}@${this.addr}`)}functionGraph(t){return\"dot\"===t?this.api.c"\
  "md(`agfd@ ${this.addr}`):\"json\"===t?this.api.cmd(`agfj@${this"\
  ".addr}`):\"mermaid\"===t?this.api.cmd(`agfm@${this.addr}`):this"\
  ".api.cmd(`agf@${this.addr}`)}readByteArray(t){return JSON.par"\
  "se(this.api.cmd(`p8j ${t}@${this.addr}`))}readHexString(t){re"\
  "turn this.api.cmd(`p8 ${t}@${this.addr}`).trim()}and(t){const"\
  " e=this.api.call(`?v ${this.addr} & ${t}`).trim();return new "\
  "NativePointer(e)}or(t){const e=this.api.call(`?v ${this.addr}"\
  " | ${t}`).trim();return new NativePointer(e)}add(t){const e=t"\
  "his.api.call(`?v ${this.addr}+${t}`).trim();return new Native"\
  "Pointer(e)}sub(t){const e=this.api.call(`?v ${this.addr}-${t}"\
  "`).trim();return new NativePointer(e)}writeByteArray(t){retur"\
  "n this.api.cmd(\"wx \"+t.join(\"\")),this}writeAssembly(t){return"\
  " this.api.cmd(`wa ${t} @ ${this.addr}`),this}writeCString(t){"\
  "return this.api.call(\"w \"+t),this}writeWideString(t){return t"\
  "his.api.call(\"ww \"+t),this}isNull(){return 0==this.toNumber()"\
  "}compare(t){return\"string\"!=typeof t&&\"number\"!=typeof t||(t="\
  "new NativePointer(t)),t.addr===this.addr||new NativePointer(t"\
  ".addr).toNumber()===this.toNumber()}pointsToNull(){return thi"\
  "s.readPointer().compare(0)}toJSON(){return this.api.cmd(\"?vi "\
  "\"+this.addr.trim()).trim()}toString(){return this.api.cmd(\"?v"\
  " \"+this.addr.trim()).trim()}toNumber(){return parseInt(this.t"\
  "oString())}writePointer(t){this.api.cmd(`wvp ${t}@${this}`)}r"\
  "eadRelativePointer(){return this.add(this.readS32())}readPoin"\
  "ter(){return new NativePointer(this.api.call(\"pvp@\"+this.addr"\
  "))}readS8(){return parseInt(this.api.cmd(`pv1d@${this.addr}`)"\
  ")}readU8(){return parseInt(this.api.cmd(`pv1u@${this.addr}`))"\
  "}readU16(){return parseInt(this.api.cmd(`pv2d@${this.addr}`))"\
  "}readU16le(){return parseInt(this.api.cmd(`pv2d@${this.addr}@"\
  "e:cfg.bigendian=false`))}readU16be(){return parseInt(this.api"\
  ".cmd(`pv2d@${this.addr}@e:cfg.bigendian=true`))}readS16(){ret"\
  "urn parseInt(this.api.cmd(`pv2d@${this.addr}`))}readS16le(){r"\
  "eturn parseInt(this.api.cmd(`pv2d@${this.addr}@e:cfg.bigendia"\
  "n=false`))}readS16be(){return parseInt(this.api.cmd(`pv2d@${t"\
  "his.addr}@e:cfg.bigendian=true`))}readS32(){return parseInt(t"\
  "his.api.cmd(`pv4d@${this.addr}`))}readU32(){return parseInt(t"\
  "his.api.cmd(`pv4u@${this.addr}`))}readU32le(){return parseInt"\
  "(this.api.cmd(`pv4u@${this.addr}@e:cfg.bigendian=false`))}rea"\
  "dU32be(){return parseInt(this.api.cmd(`pv4u@${this.addr}@e:cf"\
  "g.bigendian=true`))}readU64(){return parseInt(this.api.cmd(`p"\
  "v8u@${this.addr}`))}readU64le(){return parseInt(this.api.cmd("\
  "`pv8u@${this.addr}@e:cfg.bigendian=false`))}readU64be(){retur"\
  "n parseInt(this.api.cmd(`pv8u@${this.addr}@e:cfg.bigendian=tr"\
  "ue`))}writeInt(t){return this.writeU32(t)}writeU8(t){return t"\
  "his.api.cmd(`wv1 ${t}@${this.addr}`),!0}writeU16(t){return th"\
  "is.api.cmd(`wv2 ${t}@${this.addr}`),!0}writeU16be(t){return t"\
  "his.api.cmd(`wv2 ${t}@${this.addr}@e:cfg.bigendian=true`),!0}"\
  "writeU16le(t){return this.api.cmd(`wv2 ${t}@${this.addr}@e:cf"\
  "g.bigendian=false`),!0}writeU32(t){return this.api.cmd(`wv4 $"\
  "{t}@${this.addr}`),!0}writeU32be(t){return this.api.cmd(`wv4 "\
  "${t}@${this.addr}@e:cfg.bigendian=true`),!0}writeU32le(t){ret"\
  "urn this.api.cmd(`wv4 ${t}@${this.addr}@e:cfg.bigendian=false"\
  "`),!0}writeU64(t){return this.api.cmd(`wv8 ${t}@${this.addr}`"\
  "),!0}writeU64be(t){return this.api.cmd(`wv8 ${t}@${this.addr}"\
  "@e:cfg.bigendian=true`),!0}writeU64le(t){return this.api.cmd("\
  "`wv8 ${t}@${this.addr}@e:cfg.bigendian=false`),!0}readInt32()"\
  "{return this.readU32()}readCString(){return JSON.parse(this.a"\
  "pi.cmd(`pszj@${this.addr}`)).string}readWideString(){return J"\
  "SON.parse(this.api.cmd(`pswj@${this.addr}`)).string}readPasca"\
  "lString(){return JSON.parse(this.api.cmd(`pspj@${this.addr}`)"\
  ").string}instruction(){return this.api.cmdj(`aoj@${this.addr}"\
  "`)[0]}disassemble(t){let e=void 0===t?\"\":\"\"+t;return this.api"\
  ".cmd(`pd ${e}@${this.addr}`)}analyzeFunction(){return this.ap"\
  "i.cmd(\"af@\"+this.addr),this}analyzeFunctionRecursively(){retu"\
  "rn this.api.cmd(\"afr@\"+this.addr),this}name(){return this.api"\
  ".cmd(\"fd \"+this.addr).trim()}methodName(){return this.api.cmd"\
  "(\"ic.@\"+this.addr).trim()}symbolName(){return this.api.cmd(\"i"\
  "sj.@\"+this.addr).trim()}getFunction(){return this.api.cmdj(\"a"\
  "fij@\"+this.addr)}basicBlock(){return this.api.cmdj(\"abj@\"+thi"\
  "s.addr)}functionBasicBlocks(){return this.api.cmdj(\"afbj@\"+th"\
  "is.addr)}xrefs(){return this.api.cmdj(\"axtj@\"+this.addr)}}G.N"\
  "ativePointer=NativePointer,Object.defineProperty(G,\"__esModul"\
  "e\",{value:!0}),Object.defineProperty(G,\"__esModule\",{value:!0"\
  "}),G.Base64=void 0;class Base64{static encode(t){return(0,G.b"\
  "64)(t)}static decode(t){return(0,G.b64)(t,!0)}}G.Base64=Base6"\
  "4,Object.defineProperty(G,\"__esModule\",{value:!0}),G.R2AI=voi"\
  "d 0;class R2AI{constructor(t,e){if(this.available=!1,this.mod"\
  "el=\"\",this.available=\"\"!==r2pipe_js_1.r2.cmd(\"r2ai -h\").trim("\
  "),!this.available)throw new Error(\"ERROR: r2ai is not install"\
  "ed\");t&&r2pipe_js_1.r2.call(`r2ai -n ${t}`),e&&(this.model=e)"\
  "}reset(){this.available&&r2pipe_js_1.r2.call(\"r2ai -R\")}setRo"\
  "le(t){this.available&&r2pipe_js_1.r2.call(`r2ai -r ${t}`)}set"\
  "Model(t){this.available&&r2pipe_js_1.r2.call(`r2ai -m ${this."\
  "model}`)}getModel(){return this.available?r2pipe_js_1.r2.call"\
  "(\"r2ai -m\"):this.model}listModels(){return this.available?r2p"\
  "ipe_js_1.r2.call(\"r2ai -M\").trim().split(/\\n/g):[]}query(t){i"\
  "f(!this.available||\"\"==t)return\"\";const e=t.trim().replace(/\\"\
  "n/g,\".\");return r2pipe_js_1.r2.call(`r2ai ${e}`)}}G.R2AI=R2AI"\
  ",Object.defineProperty(G,\"__esModule\",{value:!0}),G.R2PapiShe"\
  "ll=void 0;class R2PapiShell{constructor(t){this.rp=t}mkdir(t,"\
  "e){return!0===e?this.rp.call(`mkdir -p ${t}`):this.rp.call(`m"\
  "kdir ${t}`),!0}unlink(t){return this.rp.call(`rm ${t}`),!0}ch"\
  "dir(t){return this.rp.call(`cd ${t}`),!0}ls(){return this.rp."\
  "call(\"ls -q\").trim().split(\"\\n\")}fileExists(t){return!1}open("\
  "t){this.rp.call(`open ${t}`)}system(t){return this.rp.call(`!"\
  "${t}`),0}run(t){return this.rp.call(`rm ${t}`),0}mount(t,e){r"\
  "eturn this.rp.call(`m ${t} ${e}`),!0}umount(t){this.rp.call(`"\
  "m-${t}`)}chdir2(t){return void 0===t&&(t=\"/\"),this.rp.call(`m"\
  "dq ${t}`),!0}ls2(t){return void 0===t&&(t=\"/\"),this.rp.call(`"\
  "mdq ${t}`).trim().split(\"\\n\")}enumerateMountpoints(){return t"\
  "his.rp.cmdj(\"mlj\")}isSymlink(t){return!1}isDirectory(t){retur"\
  "n!1}}G.R2PapiShell=R2PapiShell,Object.defineProperty(G,\"__esM"\
  "odule\",{value:!0}),G.EsilParser=G.EsilNode=G.EsilToken=void 0"\
  ";class EsilToken{constructor(t=\"\",e=0){this.label=\"\",this.com"\
  "ment=\"\",this.text=\"\",this.addr=\"0\",this.position=0,this.text="\
  "t,this.position=e}toString(){return this.text}}G.EsilToken=Es"\
  "ilToken;class EsilNode{constructor(t=new EsilToken,e=\"none\"){"\
  "this.type=\"none\",this.token=t,this.children=[]}setSides(t,e){"\
  "this.lhs=t,this.rhs=e}addChildren(t,e){void 0!==t&&this.child"\
  "ren.push(t),void 0!==e&&this.children.push(e)}toEsil(){if(voi"\
  "d 0!==this.lhs&&void 0!==this.rhs){let t=this.lhs.toEsil();re"\
  "turn\"\"!==t&&(t+=\",\"),`${this.rhs.toEsil()},${t}${this.token}`"\
  "}return\"\"}toString(){let t=\"\";if(\"\"!==this.token.label&&(t+=t"\
  "his.token.label+\":\\n\"),this.token.addr,\"\"!==this.token.commen"\
  "t&&(t+=\"/*\"+this.token.comment+\"*/\\n\"),\"GOTO\"===this.token.to"\
  "String())if(this.children.length>0){t+=\"goto label_\"+this.chi"\
  "ldren[0].token.position+\";\\n\"}else{t+=`goto label_${0};\\n`}if"\
  "(this.children.length>0){t+=`  (if (${this.rhs})\\n`;for(let e"\
  " of this.children)if(null!==e){const r=e.toString();\"\"!=r&&(t"\
  "+=`  ${r}\\n`)}t+=\"  )\\n\"}return void 0!==this.lhs&&void 0!==t"\
  "his.rhs?t+`    ( ${this.lhs} ${this.token} ${this.rhs} )`:t+t"\
  "his.token.toString()}}G.EsilNode=EsilNode;class EsilParser{co"\
  "nstructor(t){this.cur=0,this.r2=t,this.cur=0,this.stack=[],th"\
  "is.nodes=[],this.tokens=[],this.root=new EsilNode(new EsilTok"\
  "en(\"function\",0),\"block\")}toJSON(){if(this.stack.length>0)thr"\
  "ow new Error(\"The ESIL stack is not empty\");return JSON.strin"\
  "gify(this.root,null,2)}toEsil(){return this.nodes.map((t=>t.t"\
  "oEsil())).join(\",\")}optimizeFlags(t){void 0!==t.rhs&&this.opt"\
  "imizeFlags(t.rhs),void 0!==t.lhs&&this.optimizeFlags(t.lhs);f"\
  "or(let e=0;e<t.children.length;e++)this.optimizeFlags(t.child"\
  "ren[e]);const e=t.toString();if(+e>4096){const r=r2.cmd(`fd.@"\
  " ${e}`).trim().split(\"\\n\")[0].trim();\"\"!=r&&-1===r.indexOf(\"+"\
  "\")&&(t.token.text=r)}}optimize(t){-1!=t.indexOf(\"flag\")&&this"\
  ".optimizeFlags(this.root)}toString(){return this.root.childre"\
  "n.map((t=>t.toString())).join(\";\\n\")}reset(){this.nodes=[],th"\
  "is.stack=[],this.tokens=[],this.cur=0,this.root=new EsilNode("\
  "new EsilToken(\"function\",0),\"block\")}parseRange(t,e){let r=t;"\
  "for(;r<this.tokens.length&&r<e;){const t=this.peek(r);if(!t)b"\
  "reak;this.cur=r,this.pushToken(t),r=this.cur,r++}}parseFuncti"\
  "on(t){var e=this;function r(t){const r=r2.cmd(\"pie \"+t+\" @e:s"\
  "cr.color=0\").trim().split(\"\\n\");for(const t of r){if(0===t.le"\
  "ngth){console.log(\"Empty\");continue}const r=t.split(\" \");r.le"\
  "ngth>1&&(r2.cmd(`s ${r[0]}`),e.parse(r[1],r[0]),e.optimize(\"f"\
  "lags,labels\"))}}const s=r2.cmd(\"?v $$\").trim();void 0===t&&(t"\
  "=s);const i=r2.cmdj(`afbj@${t}`);for(let t of i)r2.cmd(`s ${t"\
  ".addr}`),r(t.ninstr);r2.cmd(`s ${s}`)}parse(t,e){const r=t.tr"\
  "im().split(\",\").map((t=>t.trim())),s=this.tokens.length;for(l"\
  "et t of r){const r=new EsilToken(t,this.tokens.length);void 0"\
  "!==e&&(r.addr=e),this.tokens.push(r)}const i=this.tokens.leng"\
  "th;this.parseRange(s,i)}peek(t){return this.tokens[t]}pushTok"\
  "en(t){if(this.isNumber(t)){const e=new EsilNode(t,\"number\");t"\
  "his.stack.push(e),this.nodes.push(e)}else if(this.isInternal("\
  "t)){const e=new EsilNode(t,\"flag\");this.stack.push(e),this.no"\
  "des.push(e)}else if(this.isOperation(t));else{const e=new Esi"\
  "lNode(t,\"register\");this.stack.push(e),this.nodes.push(e)}}is"\
  "Number(t){return!!t.toString().startsWith(\"0\")||+t>0}isIntern"\
  "al(t){const e=t.toString();return e.startsWith(\"$\")&&e.length"\
  ">1}parseUntil(t){const e=t+1;let r=e;const s=[],i=this.nodes."\
  "length;for(this.stack.forEach((t=>s.push(t)));r<this.tokens.l"\
  "ength;){const t=this.peek(r);if(!t)break;if(\"}\"===t.toString("\
  "))break;if(\"}{\"===t.toString())break;r++}this.stack=s;const n"\
  "=r;this.parseRange(e,n);return this.nodes.length==i?null:this"\
  ".nodes[this.nodes.length-1]}getNodeFor(t){if(void 0===this.pe"\
  "ek(t))return null;for(let e of this.nodes)if(e.token.position"\
  "===t)return e;return this.nodes.push(new EsilNode(new EsilTok"\
  "en(\"label\",t),\"label\")),null}findNodeFor(t){for(let e of this"\
  ".nodes)if(e.token.position===t)return e;return null}isOperati"\
  "on(t){switch(t.toString()){case\"[1]\":case\"[2]\":case\"[4]\":case"\
  "\"[8]\":if(!(this.stack.length>=1))throw new Error(\"Stack needs"\
  " more items\");{const t=this.stack.pop();new EsilNode(t.token,"\
  "\"operation\");this.stack.push(t)}return!0;case\"!\":if(!(this.st"\
  "ack.length>=1))throw new Error(\"Stack needs more items\");{con"\
  "st e=new EsilNode(new EsilToken(\"\",t.position),\"none\"),r=this"\
  ".stack.pop(),s=new EsilNode(t,\"operation\");s.setSides(e,r),th"\
  "is.stack.push(s)}return!0;case\"\":case\"}\":case\"}{\":return!0;ca"\
  "se\"DUP\":{if(this.stack.length<1)throw new Error(\"goto cant po"\
  "p\");const t=this.stack.pop();this.stack.push(t),this.stack.pu"\
  "sh(t)}return!0;case\"GOTO\":if(null!==this.peek(t.position-1)){"\
  "if(this.stack.length<1)throw new Error(\"goto cant pop\");const"\
  " e=this.stack.pop();if(null!==e){const r=0|+e.toString();if(r"\
  ">0){const e=this.peek(r);if(void 0!==e){e.label=\"label_\"+r,e."\
  "comment=\"hehe\";const s=new EsilNode(t,\"goto\"),i=this.getNodeF"\
  "or(e.position);null!=i&&s.children.push(i),this.root.children"\
  ".push(s)}else console.error(\"Cannot find goto node\")}else con"\
  "sole.error(\"Cannot find dest node for goto\")}}return!0;case\"?"\
  "{\":if(!(this.stack.length>=1))throw new Error(\"Stack needs mo"\
  "re items\");{const e=new EsilNode(new EsilToken(\"if\",t.positio"\
  "n),\"none\"),r=this.stack.pop(),s=new EsilNode(t,\"operation\");s"\
  ".setSides(e,r);let i=this.parseUntil(t.position),n=null;null!"\
  "==i&&(s.children.push(i),this.nodes.push(i),n=this.parseUntil"\
  "(i.token.position+1),null!==n&&(s.children.push(n),this.nodes"\
  ".push(n))),this.nodes.push(s),this.root.children.push(s),null"\
  "!==n&&(this.cur=n.token.position)}return!0;case\"-\":if(!(this."\
  "stack.length>=2))throw new Error(\"Stack needs more items\");{c"\
  "onst e=this.stack.pop(),r=this.stack.pop(),s=new EsilNode(t,\""\
  "operation\");s.setSides(e,r),this.stack.length,this.stack.push"\
  "(s),this.nodes.push(s)}return!0;case\"<\":case\">\":case\"^\":case\""\
  "&\":case\"|\":case\"+\":case\"*\":case\"/\":case\">>=\":case\"<<=\":case\">"\
  ">>=\":case\"<<<=\":case\">>>>=\":case\"<<<<=\":if(!(this.stack.lengt"\
  "h>=2))throw new Error(\"Stack needs more items\");{const e=this"\
  ".stack.pop(),r=this.stack.pop(),s=new EsilNode(t,\"operation\")"\
  ";s.setSides(e,r),this.stack.length,this.stack.push(s),this.no"\
  "des.push(s)}return!0;case\"=\":case\":=\":case\"-=\":case\"+=\":case\""\
  "==\":case\"=[1]\":case\"=[2]\":case\"=[4]\":case\"=[8]\":if(!(this.sta"\
  "ck.length>=2))throw new Error(\"Stack needs more items\");{cons"\
  "t e=this.stack.pop(),r=this.stack.pop(),s=new EsilNode(t,\"ope"\
  "ration\");s.setSides(e,r),0===this.stack.length&&this.root.chi"\
  "ldren.push(s),this.nodes.push(s)}return!0}return!1}}G.EsilPar"\
  "ser=EsilParser;const r2pipe_js_1=G;\n";
