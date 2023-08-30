static const char *const js_r2papi_qjs = "" \
  "Object.defineProperty(G,\"__esModule\",{value:!0}),G.Base64=G.N"\
  "ativePointer=G.R2Papi=G.Assembler=void 0;const shell_js_1=G;c"\
  "lass Assembler{constructor(t){this.program=\"\",this.labels={},"\
  "this.endian=!1,this.pc=0,this.r2=null,this.r2=void 0===t?G.r2"\
  ":t,this.program=\"\",this.labels={}}setProgramCounter(t){this.p"\
  "c=t}setEndian(t){this.endian=t}toString(){return this.program"\
  "}append(t){this.pc+=t.length/2,this.program+=t}label(t){const"\
  " e=this.pc;return this.labels[t]=this.pc,e}asm(t){let e=this."\
  "r2.cmd('\"\"pa '+t).trim();e.length<16||(e=\"____\"),this.append("\
  "e)}}G.Assembler=Assembler;class R2Papi{constructor(t){this.r2"\
  "=t}getBaseAddress(){return new NativePointer(this.cmd(\"e bin."\
  "baddr\"))}jsonToTypescript(t,e){let s=`interface ${t} {\\n`;e.l"\
  "ength&&e.length>0&&(e=e[0]);for(let t of Object.keys(e)){s+=`"\
  "    ${t}: ${typeof e[t]};\\n`}return`${s}}\\n`}getBits(){return"\
  " this.cmd(\"-b\")}getArch(){return this.cmd(\"-a\")}getCpu(){retu"\
  "rn this.cmd(\"-e asm.cpu\")}setArch(t,e){this.cmd(\"-a \"+t),void"\
  " 0!==e&&this.cmd(\"-b \"+e)}setLogLevel(t){return this.cmd(\"e l"\
  "og.level=\"+t),this}newMap(t,e,s,i,r,n=\"\"){this.cmd(`om ${t} $"\
  "{e} ${s} ${i} ${r} ${n}`)}at(t){return new NativePointer(t)}g"\
  "etShell(){return new shell_js_1.R2PapiShell(this)}version(){r"\
  "eturn this.r2.cmd(\"?Vq\").trim()}platform(){return this.r2.cmd"\
  "(\"uname\").trim()}arch(){return this.r2.cmd(\"uname -a\").trim()"\
  "}bits(){return this.r2.cmd(\"uname -b\").trim()}id(){return+thi"\
  "s.r2.cmd(\"?vi:$p\")}printAt(t,e,s){}clearScreen(){return this."\
  "r2.cmd(\"!clear\"),this}getConfig(t){if(\"\"===t)throw new Error("\
  "\"Invalid key\");return this.r2.call(\"e \"+t).trim()}setConfig(t"\
  ",e){return this.r2.call(\"e \"+t+\"=\"+e),this}getRegisterStateFo"\
  "rEsil(){return this.cmdj(\"dre\").trim()}getRegisters(){return "\
  "this.cmdj(\"drj\")}resizeFile(t){return this.cmd(`r ${t}`),this"\
  "}insertNullBytes(t,e){return void 0===e&&(e=\"$$\"),this.cmd(`r"\
  "+${t}@${e}`),this}removeBytes(t,e){return void 0===e&&(e=\"$$\""\
  "),this.cmd(`r-${t}@${e}`),this}seek(t){return this.cmd(`s ${t"\
  "}`),this}currentSeek(){return new NativePointer(\"$$\")}seekToR"\
  "elativeOpcode(t){return this.cmd(`so ${t}`),this.currentSeek("\
  ")}getBlockSize(){return+this.cmd(\"b\")}setBlockSize(t){return "\
  "this.cmd(`b ${t}`),this}countFlags(){return Number(this.cmd(\""\
  "f~?\"))}countFunctions(){return Number(this.cmd(\"aflc\"))}analy"\
  "zeFunctionsWithEsil(t){this.cmd(\"aaef\")}analyzeProgramWithEsi"\
  "l(t){this.cmd(\"aae\")}analyzeProgram(t){switch(void 0===t&&(t="\
  "0),t){case 0:this.cmd(\"aa\");break;case 1:this.cmd(\"aaa\");brea"\
  "k;case 2:this.cmd(\"aaaa\");break;case 3:this.cmd(\"aaaaa\")}retu"\
  "rn this}enumerateThreads(){return[{context:this.cmdj(\"drj\"),i"\
  "d:0,state:\"waiting\",selected:!0}]}currentThreadId(){return+th"\
  "is.cmd(\"e cfg.debug\")?+this.cmd(\"dpt.\"):this.id()}setRegister"\
  "s(t){for(let e of Object.keys(t)){const s=t[e];this.r2.cmd(\"d"\
  "r \"+e+\"=\"+s)}}hex(t){return this.r2.cmd(\"?v \"+t).trim()}step("\
  "){return this.r2.cmd(\"ds\"),this}stepOver(){return this.r2.cmd"\
  "(\"dso\"),this}math(t){return+this.r2.cmd(\"?v \"+t)}stepUntil(t)"\
  "{this.cmd(`dsu ${t}`)}enumerateXrefsTo(t){return this.call(\"a"\
  "xtq \"+t).trim().split(/\\n/)}findXrefsTo(t,e){e?this.call(\"/r "\
  "\"+t):this.call(\"/re \"+t)}analyzeFunctionsFromCalls(){return t"\
  "his.call(\"aac\"),this}analyzeFunctionsWithPreludes(){return th"\
  "is.call(\"aap\"),this}analyzeObjCReferences(){return this.cmd(\""\
  "aao\"),this}analyzeImports(){return this.cmd(\"af @ sym.imp.*\")"\
  ",this}searchDisasm(t){return this.callj(\"/ad \"+t)}searchStrin"\
  "g(t){return this.cmdj(\"/j \"+t)}searchBytes(t){const e=t.map(("\
  "function(t){return(255&t).toString(16)})).join(\"\");return thi"\
  "s.cmdj(\"/xj \"+e)}binInfo(){try{return this.cmdj(\"ij~{bin}\")}c"\
  "atch(t){return{}}}selectBinary(t){this.call(`ob ${t}`)}openFi"\
  "le(t){this.call(`o ${t}`)}currentFile(t){return this.call(\"o."\
  "\").trim()}enumeratePlugins(t){switch(t){case\"bin\":return this"\
  ".callj(\"Lij\");case\"io\":return this.callj(\"Loj\");case\"core\":re"\
  "turn this.callj(\"Lcj\");case\"arch\":return this.callj(\"LAj\");ca"\
  "se\"anal\":return this.callj(\"Laj\");case\"lang\":return this.call"\
  "j(\"Llj\")}return[]}enumerateModules(){return this.callj(\"dmmj\""\
  ")}enumerateFiles(){return this.callj(\"oj\")}enumerateBinaries("\
  "){return this.callj(\"obj\")}enumerateMaps(){return this.callj("\
  "\"omj\")}enumerateSymbols(){return this.callj(\"isj\")}enumerateE"\
  "xports(){return this.callj(\"iEj\")}enumerateImports(){return t"\
  "his.callj(\"iij\")}enumerateLibraries(){return this.callj(\"ilj\""\
  ")}enumerateSections(){return this.callj(\"iSj\")}enumerateSegme"\
  "nts(){return this.callj(\"iSSj\")}enumerateEntrypoints(){return"\
  " this.callj(\"iej\")}enumerateRelocations(){return this.callj(\""\
  "irj\")}enumerateFunctions(){return this.cmdj(\"aflj\")}enumerate"\
  "Flags(){return this.cmdj(\"fj\")}skip(){this.r2.cmd(\"dss\")}ptr("\
  "t){return new NativePointer(t,this)}call(t){return this.r2.ca"\
  "ll(t)}callj(t){return JSON.parse(this.call(t))}cmd(t){return "\
  "this.r2.cmd(t)}cmdj(t){return JSON.parse(this.cmd(t))}log(t){"\
  "return this.r2.log(t)}clippy(t){this.r2.log(this.r2.cmd(\"?E \""\
  "+t))}ascii(t){this.r2.log(this.r2.cmd(\"?ea \"+t))}}G.R2Papi=R2"\
  "Papi;class NativePointer{constructor(t,e){this.api=void 0===e"\
  "?G.R:e,this.addr=(\"\"+t).trim()}hexdump(t){let e=void 0===t?\"\""\
  ":\"\"+t;return this.api.cmd(`x${e}@${this.addr}`)}functionGraph"\
  "(t){return\"dot\"===t?this.api.cmd(`agfd@ ${this.addr}`):\"json\""\
  "===t?this.api.cmd(`agfj@${this.addr}`):\"mermaid\"===t?this.api"\
  ".cmd(`agfm@${this.addr}`):this.api.cmd(`agf@${this.addr}`)}re"\
  "adByteArray(t){return JSON.parse(this.api.cmd(`p8j ${t}@${thi"\
  "s.addr}`))}readHexString(t){return this.api.cmd(`p8 ${t}@${th"\
  "is.addr}`).trim()}and(t){const e=this.api.call(`?v ${this.add"\
  "r} & ${t}`).trim();return new NativePointer(e)}or(t){const e="\
  "this.api.call(`?v ${this.addr} | ${t}`).trim();return new Nat"\
  "ivePointer(e)}add(t){const e=this.api.call(`?v ${this.addr}+$"\
  "{t}`).trim();return new NativePointer(e)}sub(t){const e=this."\
  "api.call(`?v ${this.addr}-${t}`).trim();return new NativePoin"\
  "ter(e)}writeByteArray(t){return this.api.cmd(\"wx \"+t.join(\"\")"\
  "),this}writeAssembly(t){return this.api.cmd(`wa ${t} @ ${this"\
  ".addr}`),this}writeCString(t){return this.api.call(\"w \"+t),th"\
  "is}writeWideString(t){return this.api.call(\"ww \"+t),this}asNu"\
  "mber(){const t=this.api.call(\"?vi \"+this.addr);return parseIn"\
  "t(t)}isNull(){return 0==this.asNumber()}compare(t){return\"str"\
  "ing\"!=typeof t&&\"number\"!=typeof t||(t=new NativePointer(t)),"\
  "t.addr===this.addr||new NativePointer(t.addr).asNumber()===th"\
  "is.asNumber()}pointsToNull(){return this.readPointer().compar"\
  "e(0)}toString(){return this.addr.trim()}writePointer(t){this."\
  "api.cmd(`wvp ${t}@${this}`)}readPointer(){return new NativePo"\
  "inter(this.api.call(\"pvp@\"+this.addr))}readU8(){return parseI"\
  "nt(this.api.cmd(`pv1d@${this.addr}`))}readU16(){return parseI"\
  "nt(this.api.cmd(`pv2d@${this.addr}`))}readU16le(){return pars"\
  "eInt(this.api.cmd(`pv2d@${this.addr}@e:cfg.bigendian=false`))"\
  "}readU16be(){return parseInt(this.api.cmd(`pv2d@${this.addr}@"\
  "e:cfg.bigendian=true`))}readU32(){return parseInt(this.api.cm"\
  "d(`pv4d@${this.addr}`))}readU32le(){return parseInt(this.api."\
  "cmd(`pv4d@${this.addr}@e:cfg.bigendian=false`))}readU32be(){r"\
  "eturn parseInt(this.api.cmd(`pv4d@${this.addr}@e:cfg.bigendia"\
  "n=true`))}readU64(){return parseInt(this.api.cmd(`pv8d@${this"\
  ".addr}`))}readU64le(){return parseInt(this.api.cmd(`pv8d@${th"\
  "is.addr}@e:cfg.bigendian=false`))}readU64be(){return parseInt"\
  "(this.api.cmd(`pv8d@${this.addr}@e:cfg.bigendian=true`))}writ"\
  "eInt(t){return this.writeU32(t)}writeU8(t){return this.api.cm"\
  "d(`wv1 ${t}@${this.addr}`),!0}writeU16(t){return this.api.cmd"\
  "(`wv2 ${t}@${this.addr}`),!0}writeU16be(t){return this.api.cm"\
  "d(`wv2 ${t}@${this.addr}@e:cfg.bigendian=true`),!0}writeU16le"\
  "(t){return this.api.cmd(`wv2 ${t}@${this.addr}@e:cfg.bigendia"\
  "n=false`),!0}writeU32(t){return this.api.cmd(`wv4 ${t}@${this"\
  ".addr}`),!0}writeU32be(t){return this.api.cmd(`wv4 ${t}@${thi"\
  "s.addr}@e:cfg.bigendian=true`),!0}writeU32le(t){return this.a"\
  "pi.cmd(`wv4 ${t}@${this.addr}@e:cfg.bigendian=false`),!0}writ"\
  "eU64(t){return this.api.cmd(`wv8 ${t}@${this.addr}`),!0}write"\
  "U64be(t){return this.api.cmd(`wv8 ${t}@${this.addr}@e:cfg.big"\
  "endian=true`),!0}writeU64le(t){return this.api.cmd(`wv8 ${t}@"\
  "${this.addr}@e:cfg.bigendian=false`),!0}readInt(){return this"\
  ".readU32()}readCString(){return JSON.parse(this.api.cmd(`pszj"\
  "@${this.addr}`)).string}readWideString(){return JSON.parse(th"\
  "is.api.cmd(`pswj@${this.addr}`)).string}readPascalString(){re"\
  "turn JSON.parse(this.api.cmd(`pspj@${this.addr}`)).string}ins"\
  "truction(){return this.api.cmdj(`aoj@${this.addr}`)[0]}disass"\
  "emble(t){let e=void 0===t?\"\":\"\"+t;return this.api.cmd(`pd ${e"\
  "}@${this.addr}`)}analyzeFunction(){return this.api.cmd(\"af@\"+"\
  "this.addr),this}analyzeFunctionRecursively(){return this.api."\
  "cmd(\"afr@\"+this.addr),this}name(){return this.api.cmd(\"fd \"+t"\
  "his.addr).trim()}getFunction(){return this.api.cmdj(\"afij@\"+t"\
  "his.addr)}basicBlock(){return this.api.cmdj(\"abj@\"+this.addr)"\
  "}functionBasicBlocks(){return this.api.cmdj(\"afbj@\"+this.addr"\
  ")}xrefs(){return this.api.cmdj(\"axtj@\"+this.addr)}}G.NativePo"\
  "inter=NativePointer;class Base64{static encode(t){return(0,G."\
  "b64)(t)}static decode(t){return(0,G.b64)(t,!0)}}G.Base64=Base"\
  "64,Object.defineProperty(G,\"__esModule\",{value:!0}),G.R2PapiS"\
  "hell=void 0;class R2PapiShell{constructor(t){this.rp=t}mkdir("\
  "t,e){return!0===e?this.rp.call(`mkdir -p ${t}`):this.rp.call("\
  "`mkdir ${t}`),!0}unlink(t){return this.rp.call(`rm ${t}`),!0}"\
  "chdir(t){return this.rp.call(`cd ${t}`),!0}ls(){return this.r"\
  "p.call(\"ls -q\").trim().split(\"\\n\")}fileExists(t){return!1}ope"\
  "n(t){this.rp.call(`open ${t}`)}system(t){return this.rp.call("\
  "`!${t}`),0}run(t){return this.rp.call(`rm ${t}`),0}mount(t,e)"\
  "{return this.rp.call(`m ${t} ${e}`),!0}umount(t){this.rp.call"\
  "(`m-${t}`)}chdir2(t){return void 0===t&&(t=\"/\"),this.rp.call("\
  "`mdq ${t}`),!0}ls2(t){return void 0===t&&(t=\"/\"),this.rp.call"\
  "(`mdq ${t}`).trim().split(\"\\n\")}enumerateMountpoints(){return"\
  " this.rp.cmdj(\"mlj\")}isSymlink(t){return!1}isDirectory(t){ret"\
  "urn!1}}G.R2PapiShell=R2PapiShell,Object.defineProperty(G,\"__e"\
  "sModule\",{value:!0}),G.EsilParser=G.EsilNode=G.EsilToken=void"\
  " 0;class EsilToken{constructor(t=\"\",e=0){this.label=\"\",this.c"\
  "omment=\"\",this.text=\"\",this.addr=\"0\",this.position=0,this.tex"\
  "t=t,this.position=e}toString(){return this.text}}G.EsilToken="\
  "EsilToken;class EsilNode{constructor(t=new EsilToken,e=\"none\""\
  "){this.type=\"none\",this.token=t,this.children=[]}setSides(t,e"\
  "){this.lhs=t,this.rhs=e}addChildren(t,e){void 0!==t&&this.chi"\
  "ldren.push(t),void 0!==e&&this.children.push(e)}toEsil(){if(v"\
  "oid 0!==this.lhs&&void 0!==this.rhs){let t=this.lhs.toEsil();"\
  "return\"\"!==t&&(t+=\",\"),`${this.rhs.toEsil()},${t}${this.token"\
  "}`}return\"\"}toString(){let t=\"\";if(\"\"!==this.token.label&&(t+"\
  "=this.token.label+\":\\n\"),this.token.addr,\"\"!==this.token.comm"\
  "ent&&(t+=\"/*\"+this.token.comment+\"*/\\n\"),\"GOTO\"===this.token."\
  "toString())if(this.children.length>0){t+=\"goto label_\"+this.c"\
  "hildren[0].token.position+\";\\n\"}else{t+=`goto label_${0};\\n`}"\
  "if(this.children.length>0){t+=`  (if (${this.rhs})\\n`;for(let"\
  " e of this.children)if(null!==e){const s=e.toString();\"\"!=s&&"\
  "(t+=`  ${s}\\n`)}t+=\"  )\\n\"}return void 0!==this.lhs&&void 0!="\
  "=this.rhs?t+`    ( ${this.lhs} ${this.token} ${this.rhs} )`:t"\
  "+this.token.toString()}}G.EsilNode=EsilNode;class EsilParser{"\
  "constructor(t){this.cur=0,this.r2=t,this.cur=0,this.stack=[],"\
  "this.nodes=[],this.tokens=[],this.root=new EsilNode(new EsilT"\
  "oken(\"function\",0),\"block\")}toJSON(){if(this.stack.length>0)t"\
  "hrow new Error(\"The ESIL stack is not empty\");return JSON.str"\
  "ingify(this.root,null,2)}toEsil(){return this.nodes.map((t=>t"\
  ".toEsil())).join(\",\")}optimizeFlags(t){void 0!==t.rhs&&this.o"\
  "ptimizeFlags(t.rhs),void 0!==t.lhs&&this.optimizeFlags(t.lhs)"\
  ";for(let e=0;e<t.children.length;e++)this.optimizeFlags(t.chi"\
  "ldren[e]);const e=t.toString();if(+e>4096){const s=r2.cmd(`fd"\
  ".@ ${e}`).trim().split(\"\\n\")[0].trim();\"\"!=s&&-1===s.indexOf("\
  "\"+\")&&(t.token.text=s)}}optimize(t){-1!=t.indexOf(\"flag\")&&th"\
  "is.optimizeFlags(this.root)}toString(){return this.root.child"\
  "ren.map((t=>t.toString())).join(\";\\n\")}reset(){this.nodes=[],"\
  "this.stack=[],this.tokens=[],this.cur=0,this.root=new EsilNod"\
  "e(new EsilToken(\"function\",0),\"block\")}parseRange(t,e){let s="\
  "t;for(;s<this.tokens.length&&s<e;){const t=this.peek(s);if(!t"\
  ")break;this.cur=s,this.pushToken(t),s=this.cur,s++}}parseFunc"\
  "tion(t){var e=this;function s(t){const s=r2.cmd(\"pie \"+t+\" @e"\
  ":scr.color=0\").trim().split(\"\\n\");for(const t of s){if(0===t."\
  "length){console.log(\"Empty\");continue}const s=t.split(\" \");s."\
  "length>1&&(r2.cmd(`s ${s[0]}`),e.parse(s[1],s[0]),e.optimize("\
  "\"flags,labels\"))}}const i=r2.cmd(\"?v $$\").trim();void 0===t&&"\
  "(t=i);const r=r2.cmdj(`afbj@${t}`);for(let t of r)r2.cmd(`s $"\
  "{t.addr}`),s(t.ninstr);r2.cmd(`s ${i}`)}parse(t,e){const s=t."\
  "trim().split(\",\").map((t=>t.trim())),i=this.tokens.length;for"\
  "(let t of s){const s=new EsilToken(t,this.tokens.length);void"\
  " 0!==e&&(s.addr=e),this.tokens.push(s)}const r=this.tokens.le"\
  "ngth;this.parseRange(i,r)}peek(t){return this.tokens[t]}pushT"\
  "oken(t){if(this.isNumber(t)){const e=new EsilNode(t,\"number\")"\
  ";this.stack.push(e),this.nodes.push(e)}else if(this.isInterna"\
  "l(t)){const e=new EsilNode(t,\"flag\");this.stack.push(e),this."\
  "nodes.push(e)}else if(this.isOperation(t));else{const e=new E"\
  "silNode(t,\"register\");this.stack.push(e),this.nodes.push(e)}}"\
  "isNumber(t){return!!t.toString().startsWith(\"0\")||+t>0}isInte"\
  "rnal(t){const e=t.toString();return e.startsWith(\"$\")&&e.leng"\
  "th>1}parseUntil(t){const e=t+1;let s=e;const i=[],r=this.node"\
  "s.length;for(this.stack.forEach((t=>i.push(t)));s<this.tokens"\
  ".length;){const t=this.peek(s);if(!t)break;if(\"}\"===t.toStrin"\
  "g())break;if(\"}{\"===t.toString())break;s++}this.stack=i;const"\
  " n=s;this.parseRange(e,n);return this.nodes.length==r?null:th"\
  "is.nodes[this.nodes.length-1]}getNodeFor(t){if(void 0===this."\
  "peek(t))return null;for(let e of this.nodes)if(e.token.positi"\
  "on===t)return e;return this.nodes.push(new EsilNode(new EsilT"\
  "oken(\"label\",t),\"label\")),null}findNodeFor(t){for(let e of th"\
  "is.nodes)if(e.token.position===t)return e;return null}isOpera"\
  "tion(t){switch(t.toString()){case\"[1]\":case\"[2]\":case\"[4]\":ca"\
  "se\"[8]\":if(!(this.stack.length>=1))throw new Error(\"Stack nee"\
  "ds more items\");{const t=this.stack.pop();new EsilNode(t.toke"\
  "n,\"operation\");this.stack.push(t)}return!0;case\"!\":if(!(this."\
  "stack.length>=1))throw new Error(\"Stack needs more items\");{c"\
  "onst e=new EsilNode(new EsilToken(\"\",t.position),\"none\"),s=th"\
  "is.stack.pop(),i=new EsilNode(t,\"operation\");i.setSides(e,s),"\
  "this.stack.push(i)}return!0;case\"\":case\"}\":case\"}{\":return!0;"\
  "case\"DUP\":{if(this.stack.length<1)throw new Error(\"goto cant "\
  "pop\");const t=this.stack.pop();this.stack.push(t),this.stack."\
  "push(t)}return!0;case\"GOTO\":if(null!==this.peek(t.position-1)"\
  "){if(this.stack.length<1)throw new Error(\"goto cant pop\");con"\
  "st e=this.stack.pop();if(null!==e){const s=0|+e.toString();if"\
  "(s>0){const e=this.peek(s);if(void 0!==e){e.label=\"label_\"+s,"\
  "e.comment=\"hehe\";const i=new EsilNode(t,\"goto\"),r=this.getNod"\
  "eFor(e.position);null!=r&&i.children.push(r),this.root.childr"\
  "en.push(i)}else console.error(\"Cannot find goto node\")}else c"\
  "onsole.error(\"Cannot find dest node for goto\")}}return!0;case"\
  "\"?{\":if(!(this.stack.length>=1))throw new Error(\"Stack needs "\
  "more items\");{const e=new EsilNode(new EsilToken(\"if\",t.posit"\
  "ion),\"none\"),s=this.stack.pop(),i=new EsilNode(t,\"operation\")"\
  ";i.setSides(e,s);let r=this.parseUntil(t.position),n=null;nul"\
  "l!==r&&(i.children.push(r),this.nodes.push(r),n=this.parseUnt"\
  "il(r.token.position+1),null!==n&&(i.children.push(n),this.nod"\
  "es.push(n))),this.nodes.push(i),this.root.children.push(i),nu"\
  "ll!==n&&(this.cur=n.token.position)}return!0;case\"-\":if(!(thi"\
  "s.stack.length>=2))throw new Error(\"Stack needs more items\");"\
  "{const e=this.stack.pop(),s=this.stack.pop(),i=new EsilNode(t"\
  ",\"operation\");i.setSides(e,s),this.stack.length,this.stack.pu"\
  "sh(i),this.nodes.push(i)}return!0;case\"<\":case\">\":case\"^\":cas"\
  "e\"&\":case\"|\":case\"+\":case\"*\":case\"/\":case\">>=\":case\"<<=\":case"\
  "\">>>=\":case\"<<<=\":case\">>>>=\":case\"<<<<=\":if(!(this.stack.len"\
  "gth>=2))throw new Error(\"Stack needs more items\");{const e=th"\
  "is.stack.pop(),s=this.stack.pop(),i=new EsilNode(t,\"operation"\
  "\");i.setSides(e,s),this.stack.length,this.stack.push(i),this."\
  "nodes.push(i)}return!0;case\"=\":case\":=\":case\"-=\":case\"+=\":cas"\
  "e\"==\":case\"=[1]\":case\"=[2]\":case\"=[4]\":case\"=[8]\":if(!(this.s"\
  "tack.length>=2))throw new Error(\"Stack needs more items\");{co"\
  "nst e=this.stack.pop(),s=this.stack.pop(),i=new EsilNode(t,\"o"\
  "peration\");i.setSides(e,s),0===this.stack.length&&this.root.c"\
  "hildren.push(i),this.nodes.push(i)}return!0}return!1}}G.EsilP"\
  "arser=EsilParser;\n";
