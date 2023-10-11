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
  " 0!==e&&this.cmd(\"-b \"+e)}setFlagSpace(t){this.cmd(\"fs \"+t)}s"\
  "etLogLevel(t){return this.cmd(\"e log.level=\"+t),this}newMap(t"\
  ",e,s,i,r,n=\"\"){this.cmd(`om ${t} ${e} ${s} ${i} ${r} ${n}`)}a"\
  "t(t){return new NativePointer(t)}getShell(){return new shell_"\
  "js_1.R2PapiShell(this)}version(){return this.r2.cmd(\"?Vq\").tr"\
  "im()}platform(){return this.r2.cmd(\"uname\").trim()}arch(){ret"\
  "urn this.r2.cmd(\"uname -a\").trim()}bits(){return this.r2.cmd("\
  "\"uname -b\").trim()}id(){return+this.r2.cmd(\"?vi:$p\")}printAt("\
  "t,e,s){}clearScreen(){return this.r2.cmd(\"!clear\"),this}getCo"\
  "nfig(t){if(\"\"===t)throw new Error(\"Invalid key\");return this."\
  "r2.call(\"e \"+t).trim()}setConfig(t,e){return this.r2.call(\"e "\
  "\"+t+\"=\"+e),this}getRegisterStateForEsil(){return this.cmdj(\"d"\
  "re\").trim()}getRegisters(){return this.cmdj(\"drj\")}resizeFile"\
  "(t){return this.cmd(`r ${t}`),this}insertNullBytes(t,e){retur"\
  "n void 0===e&&(e=\"$$\"),this.cmd(`r+${t}@${e}`),this}removeByt"\
  "es(t,e){return void 0===e&&(e=\"$$\"),this.cmd(`r-${t}@${e}`),t"\
  "his}seek(t){return this.cmd(`s ${t}`),this}currentSeek(){retu"\
  "rn new NativePointer(\"$$\")}seekToRelativeOpcode(t){return thi"\
  "s.cmd(`so ${t}`),this.currentSeek()}getBlockSize(){return+thi"\
  "s.cmd(\"b\")}setBlockSize(t){return this.cmd(`b ${t}`),this}cou"\
  "ntFlags(){return Number(this.cmd(\"f~?\"))}countFunctions(){ret"\
  "urn Number(this.cmd(\"aflc\"))}analyzeFunctionsWithEsil(t){this"\
  ".cmd(\"aaef\")}analyzeProgramWithEsil(t){this.cmd(\"aae\")}analyz"\
  "eProgram(t){switch(void 0===t&&(t=0),t){case 0:this.cmd(\"aa\")"\
  ";break;case 1:this.cmd(\"aaa\");break;case 2:this.cmd(\"aaaa\");b"\
  "reak;case 3:this.cmd(\"aaaaa\")}return this}enumerateThreads(){"\
  "return[{context:this.cmdj(\"drj\"),id:0,state:\"waiting\",selecte"\
  "d:!0}]}currentThreadId(){return+this.cmd(\"e cfg.debug\")?+this"\
  ".cmd(\"dpt.\"):this.id()}setRegisters(t){for(let e of Object.ke"\
  "ys(t)){const s=t[e];this.r2.cmd(\"dr \"+e+\"=\"+s)}}hex(t){return"\
  " this.r2.cmd(\"?v \"+t).trim()}step(){return this.r2.cmd(\"ds\"),"\
  "this}stepOver(){return this.r2.cmd(\"dso\"),this}math(t){return"\
  "+this.r2.cmd(\"?v \"+t)}stepUntil(t){this.cmd(`dsu ${t}`)}enume"\
  "rateXrefsTo(t){return this.call(\"axtq \"+t).trim().split(/\\n/)"\
  "}findXrefsTo(t,e){e?this.call(\"/r \"+t):this.call(\"/re \"+t)}an"\
  "alyzeFunctionsFromCalls(){return this.call(\"aac\"),this}analyz"\
  "eFunctionsWithPreludes(){return this.call(\"aap\"),this}analyze"\
  "ObjCReferences(){return this.cmd(\"aao\"),this}analyzeImports()"\
  "{return this.cmd(\"af @ sym.imp.*\"),this}searchDisasm(t){retur"\
  "n this.callj(\"/ad \"+t)}searchString(t){return this.cmdj(\"/j \""\
  "+t)}searchBytes(t){const e=t.map((function(t){return(255&t).t"\
  "oString(16)})).join(\"\");return this.cmdj(\"/xj \"+e)}binInfo(){"\
  "try{return this.cmdj(\"ij~{bin}\")}catch(t){return{}}}selectBin"\
  "ary(t){this.call(`ob ${t}`)}openFile(t){const e=this.call(\"oq"\
  "q\").trim();this.call(`o ${t}`);const s=this.call(\"oqq\").trim("\
  ");return e===s?new Error(\"Cannot open file\"):parseInt(s)}curr"\
  "entFile(t){return this.call(\"o.\").trim()}enumeratePlugins(t){"\
  "switch(t){case\"bin\":return this.callj(\"Lij\");case\"io\":return "\
  "this.callj(\"Loj\");case\"core\":return this.callj(\"Lcj\");case\"ar"\
  "ch\":return this.callj(\"LAj\");case\"anal\":return this.callj(\"La"\
  "j\");case\"lang\":return this.callj(\"Llj\")}return[]}enumerateMod"\
  "ules(){return this.callj(\"dmmj\")}enumerateFiles(){return this"\
  ".callj(\"oj\")}enumerateBinaries(){return this.callj(\"obj\")}enu"\
  "merateMaps(){return this.callj(\"omj\")}enumerateClasses(){retu"\
  "rn this.callj(\"icj\")}enumerateSymbols(){return this.callj(\"is"\
  "j\")}enumerateExports(){return this.callj(\"iEj\")}enumerateImpo"\
  "rts(){return this.callj(\"iij\")}enumerateLibraries(){return th"\
  "is.callj(\"ilj\")}enumerateSections(){return this.callj(\"iSj\")}"\
  "enumerateSegments(){return this.callj(\"iSSj\")}enumerateEntryp"\
  "oints(){return this.callj(\"iej\")}enumerateRelocations(){retur"\
  "n this.callj(\"irj\")}enumerateFunctions(){return this.cmdj(\"af"\
  "lj\")}enumerateFlags(){return this.cmdj(\"fj\")}skip(){this.r2.c"\
  "md(\"dss\")}ptr(t){return new NativePointer(t,this)}call(t){ret"\
  "urn this.r2.call(t)}callj(t){return JSON.parse(this.call(t))}"\
  "cmd(t){return this.r2.cmd(t)}cmdj(t){return JSON.parse(this.c"\
  "md(t))}log(t){return this.r2.log(t)}clippy(t){this.r2.log(thi"\
  "s.r2.cmd(\"?E \"+t))}ascii(t){this.r2.log(this.r2.cmd(\"?ea \"+t)"\
  ")}}G.R2Papi=R2Papi;class NativePointer{constructor(t,e){this."\
  "api=void 0===e?G.R:e,this.addr=(\"\"+t).trim()}setFlag(t){this."\
  "api.call(`f ${t}=${this.addr}`)}unsetFlag(){this.api.call(`f-"\
  "${this.addr}`)}hexdump(t){let e=void 0===t?\"\":\"\"+t;return thi"\
  "s.api.cmd(`x${e}@${this.addr}`)}functionGraph(t){return\"dot\"="\
  "==t?this.api.cmd(`agfd@ ${this.addr}`):\"json\"===t?this.api.cm"\
  "d(`agfj@${this.addr}`):\"mermaid\"===t?this.api.cmd(`agfm@${thi"\
  "s.addr}`):this.api.cmd(`agf@${this.addr}`)}readByteArray(t){r"\
  "eturn JSON.parse(this.api.cmd(`p8j ${t}@${this.addr}`))}readH"\
  "exString(t){return this.api.cmd(`p8 ${t}@${this.addr}`).trim("\
  ")}and(t){const e=this.api.call(`?v ${this.addr} & ${t}`).trim"\
  "();return new NativePointer(e)}or(t){const e=this.api.call(`?"\
  "v ${this.addr} | ${t}`).trim();return new NativePointer(e)}ad"\
  "d(t){const e=this.api.call(`?v ${this.addr}+${t}`).trim();ret"\
  "urn new NativePointer(e)}sub(t){const e=this.api.call(`?v ${t"\
  "his.addr}-${t}`).trim();return new NativePointer(e)}writeByte"\
  "Array(t){return this.api.cmd(\"wx \"+t.join(\"\")),this}writeAsse"\
  "mbly(t){return this.api.cmd(`wa ${t} @ ${this.addr}`),this}wr"\
  "iteCString(t){return this.api.call(\"w \"+t),this}writeWideStri"\
  "ng(t){return this.api.call(\"ww \"+t),this}asNumber(){const t=t"\
  "his.api.call(\"?vi \"+this.addr);return parseInt(t)}isNull(){re"\
  "turn 0==this.asNumber()}compare(t){return\"string\"!=typeof t&&"\
  "\"number\"!=typeof t||(t=new NativePointer(t)),t.addr===this.ad"\
  "dr||new NativePointer(t.addr).asNumber()===this.asNumber()}po"\
  "intsToNull(){return this.readPointer().compare(0)}toString(){"\
  "return this.addr.trim()}writePointer(t){this.api.cmd(`wvp ${t"\
  "}@${this}`)}readPointer(){return new NativePointer(this.api.c"\
  "all(\"pvp@\"+this.addr))}readU8(){return parseInt(this.api.cmd("\
  "`pv1d@${this.addr}`))}readU16(){return parseInt(this.api.cmd("\
  "`pv2d@${this.addr}`))}readU16le(){return parseInt(this.api.cm"\
  "d(`pv2d@${this.addr}@e:cfg.bigendian=false`))}readU16be(){ret"\
  "urn parseInt(this.api.cmd(`pv2d@${this.addr}@e:cfg.bigendian="\
  "true`))}readS16(){return parseInt(this.api.cmd(`pv2d@${this.a"\
  "ddr}`))}readS16le(){return parseInt(this.api.cmd(`pv2d@${this"\
  ".addr}@e:cfg.bigendian=false`))}readS16be(){return parseInt(t"\
  "his.api.cmd(`pv2d@${this.addr}@e:cfg.bigendian=true`))}readS3"\
  "2(){return parseInt(this.api.cmd(`pv4d@${this.addr}`))}readU3"\
  "2(){return parseInt(this.api.cmd(`pv4u@${this.addr}`))}readU3"\
  "2le(){return parseInt(this.api.cmd(`pv4u@${this.addr}@e:cfg.b"\
  "igendian=false`))}readU32be(){return parseInt(this.api.cmd(`p"\
  "v4u@${this.addr}@e:cfg.bigendian=true`))}readU64(){return par"\
  "seInt(this.api.cmd(`pv8u@${this.addr}`))}readU64le(){return p"\
  "arseInt(this.api.cmd(`pv8u@${this.addr}@e:cfg.bigendian=false"\
  "`))}readU64be(){return parseInt(this.api.cmd(`pv8u@${this.add"\
  "r}@e:cfg.bigendian=true`))}writeInt(t){return this.writeU32(t"\
  ")}writeU8(t){return this.api.cmd(`wv1 ${t}@${this.addr}`),!0}"\
  "writeU16(t){return this.api.cmd(`wv2 ${t}@${this.addr}`),!0}w"\
  "riteU16be(t){return this.api.cmd(`wv2 ${t}@${this.addr}@e:cfg"\
  ".bigendian=true`),!0}writeU16le(t){return this.api.cmd(`wv2 $"\
  "{t}@${this.addr}@e:cfg.bigendian=false`),!0}writeU32(t){retur"\
  "n this.api.cmd(`wv4 ${t}@${this.addr}`),!0}writeU32be(t){retu"\
  "rn this.api.cmd(`wv4 ${t}@${this.addr}@e:cfg.bigendian=true`)"\
  ",!0}writeU32le(t){return this.api.cmd(`wv4 ${t}@${this.addr}@"\
  "e:cfg.bigendian=false`),!0}writeU64(t){return this.api.cmd(`w"\
  "v8 ${t}@${this.addr}`),!0}writeU64be(t){return this.api.cmd(`"\
  "wv8 ${t}@${this.addr}@e:cfg.bigendian=true`),!0}writeU64le(t)"\
  "{return this.api.cmd(`wv8 ${t}@${this.addr}@e:cfg.bigendian=f"\
  "alse`),!0}readInt(){return this.readU32()}readCString(){retur"\
  "n JSON.parse(this.api.cmd(`pszj@${this.addr}`)).string}readWi"\
  "deString(){return JSON.parse(this.api.cmd(`pswj@${this.addr}`"\
  ")).string}readPascalString(){return JSON.parse(this.api.cmd(`"\
  "pspj@${this.addr}`)).string}instruction(){return this.api.cmd"\
  "j(`aoj@${this.addr}`)[0]}disassemble(t){let e=void 0===t?\"\":\""\
  "\"+t;return this.api.cmd(`pd ${e}@${this.addr}`)}analyzeFuncti"\
  "on(){return this.api.cmd(\"af@\"+this.addr),this}analyzeFunctio"\
  "nRecursively(){return this.api.cmd(\"afr@\"+this.addr),this}nam"\
  "e(){return this.api.cmd(\"fd \"+this.addr).trim()}methodName(){"\
  "return this.api.cmd(\"ic.@\"+this.addr).trim()}symbolName(){ret"\
  "urn this.api.cmd(\"isj.@\"+this.addr).trim()}getFunction(){retu"\
  "rn this.api.cmdj(\"afij@\"+this.addr)}basicBlock(){return this."\
  "api.cmdj(\"abj@\"+this.addr)}functionBasicBlocks(){return this."\
  "api.cmdj(\"afbj@\"+this.addr)}xrefs(){return this.api.cmdj(\"axt"\
  "j@\"+this.addr)}}G.NativePointer=NativePointer;class Base64{st"\
  "atic encode(t){return(0,G.b64)(t)}static decode(t){return(0,G"\
  ".b64)(t,!0)}}G.Base64=Base64,Object.defineProperty(G,\"__esMod"\
  "ule\",{value:!0}),G.R2PapiShell=void 0;class R2PapiShell{const"\
  "ructor(t){this.rp=t}mkdir(t,e){return!0===e?this.rp.call(`mkd"\
  "ir -p ${t}`):this.rp.call(`mkdir ${t}`),!0}unlink(t){return t"\
  "his.rp.call(`rm ${t}`),!0}chdir(t){return this.rp.call(`cd ${"\
  "t}`),!0}ls(){return this.rp.call(\"ls -q\").trim().split(\"\\n\")}"\
  "fileExists(t){return!1}open(t){this.rp.call(`open ${t}`)}syst"\
  "em(t){return this.rp.call(`!${t}`),0}run(t){return this.rp.ca"\
  "ll(`rm ${t}`),0}mount(t,e){return this.rp.call(`m ${t} ${e}`)"\
  ",!0}umount(t){this.rp.call(`m-${t}`)}chdir2(t){return void 0="\
  "==t&&(t=\"/\"),this.rp.call(`mdq ${t}`),!0}ls2(t){return void 0"\
  "===t&&(t=\"/\"),this.rp.call(`mdq ${t}`).trim().split(\"\\n\")}enu"\
  "merateMountpoints(){return this.rp.cmdj(\"mlj\")}isSymlink(t){r"\
  "eturn!1}isDirectory(t){return!1}}G.R2PapiShell=R2PapiShell,Ob"\
  "ject.defineProperty(G,\"__esModule\",{value:!0}),G.EsilParser=G"\
  ".EsilNode=G.EsilToken=void 0;class EsilToken{constructor(t=\"\""\
  ",e=0){this.label=\"\",this.comment=\"\",this.text=\"\",this.addr=\"0"\
  "\",this.position=0,this.text=t,this.position=e}toString(){retu"\
  "rn this.text}}G.EsilToken=EsilToken;class EsilNode{constructo"\
  "r(t=new EsilToken,e=\"none\"){this.type=\"none\",this.token=t,thi"\
  "s.children=[]}setSides(t,e){this.lhs=t,this.rhs=e}addChildren"\
  "(t,e){void 0!==t&&this.children.push(t),void 0!==e&&this.chil"\
  "dren.push(e)}toEsil(){if(void 0!==this.lhs&&void 0!==this.rhs"\
  "){let t=this.lhs.toEsil();return\"\"!==t&&(t+=\",\"),`${this.rhs."\
  "toEsil()},${t}${this.token}`}return\"\"}toString(){let t=\"\";if("\
  "\"\"!==this.token.label&&(t+=this.token.label+\":\\n\"),this.token"\
  ".addr,\"\"!==this.token.comment&&(t+=\"/*\"+this.token.comment+\"*"\
  "/\\n\"),\"GOTO\"===this.token.toString())if(this.children.length>"\
  "0){t+=\"goto label_\"+this.children[0].token.position+\";\\n\"}els"\
  "e{t+=`goto label_${0};\\n`}if(this.children.length>0){t+=`  (i"\
  "f (${this.rhs})\\n`;for(let e of this.children)if(null!==e){co"\
  "nst s=e.toString();\"\"!=s&&(t+=`  ${s}\\n`)}t+=\"  )\\n\"}return v"\
  "oid 0!==this.lhs&&void 0!==this.rhs?t+`    ( ${this.lhs} ${th"\
  "is.token} ${this.rhs} )`:t+this.token.toString()}}G.EsilNode="\
  "EsilNode;class EsilParser{constructor(t){this.cur=0,this.r2=t"\
  ",this.cur=0,this.stack=[],this.nodes=[],this.tokens=[],this.r"\
  "oot=new EsilNode(new EsilToken(\"function\",0),\"block\")}toJSON("\
  "){if(this.stack.length>0)throw new Error(\"The ESIL stack is n"\
  "ot empty\");return JSON.stringify(this.root,null,2)}toEsil(){r"\
  "eturn this.nodes.map((t=>t.toEsil())).join(\",\")}optimizeFlags"\
  "(t){void 0!==t.rhs&&this.optimizeFlags(t.rhs),void 0!==t.lhs&"\
  "&this.optimizeFlags(t.lhs);for(let e=0;e<t.children.length;e+"\
  "+)this.optimizeFlags(t.children[e]);const e=t.toString();if(+"\
  "e>4096){const s=r2.cmd(`fd.@ ${e}`).trim().split(\"\\n\")[0].tri"\
  "m();\"\"!=s&&-1===s.indexOf(\"+\")&&(t.token.text=s)}}optimize(t)"\
  "{-1!=t.indexOf(\"flag\")&&this.optimizeFlags(this.root)}toStrin"\
  "g(){return this.root.children.map((t=>t.toString())).join(\";\\"\
  "n\")}reset(){this.nodes=[],this.stack=[],this.tokens=[],this.c"\
  "ur=0,this.root=new EsilNode(new EsilToken(\"function\",0),\"bloc"\
  "k\")}parseRange(t,e){let s=t;for(;s<this.tokens.length&&s<e;){"\
  "const t=this.peek(s);if(!t)break;this.cur=s,this.pushToken(t)"\
  ",s=this.cur,s++}}parseFunction(t){var e=this;function s(t){co"\
  "nst s=r2.cmd(\"pie \"+t+\" @e:scr.color=0\").trim().split(\"\\n\");f"\
  "or(const t of s){if(0===t.length){console.log(\"Empty\");contin"\
  "ue}const s=t.split(\" \");s.length>1&&(r2.cmd(`s ${s[0]}`),e.pa"\
  "rse(s[1],s[0]),e.optimize(\"flags,labels\"))}}const i=r2.cmd(\"?"\
  "v $$\").trim();void 0===t&&(t=i);const r=r2.cmdj(`afbj@${t}`);"\
  "for(let t of r)r2.cmd(`s ${t.addr}`),s(t.ninstr);r2.cmd(`s ${"\
  "i}`)}parse(t,e){const s=t.trim().split(\",\").map((t=>t.trim())"\
  "),i=this.tokens.length;for(let t of s){const s=new EsilToken("\
  "t,this.tokens.length);void 0!==e&&(s.addr=e),this.tokens.push"\
  "(s)}const r=this.tokens.length;this.parseRange(i,r)}peek(t){r"\
  "eturn this.tokens[t]}pushToken(t){if(this.isNumber(t)){const "\
  "e=new EsilNode(t,\"number\");this.stack.push(e),this.nodes.push"\
  "(e)}else if(this.isInternal(t)){const e=new EsilNode(t,\"flag\""\
  ");this.stack.push(e),this.nodes.push(e)}else if(this.isOperat"\
  "ion(t));else{const e=new EsilNode(t,\"register\");this.stack.pu"\
  "sh(e),this.nodes.push(e)}}isNumber(t){return!!t.toString().st"\
  "artsWith(\"0\")||+t>0}isInternal(t){const e=t.toString();return"\
  " e.startsWith(\"$\")&&e.length>1}parseUntil(t){const e=t+1;let "\
  "s=e;const i=[],r=this.nodes.length;for(this.stack.forEach((t="\
  ">i.push(t)));s<this.tokens.length;){const t=this.peek(s);if(!"\
  "t)break;if(\"}\"===t.toString())break;if(\"}{\"===t.toString())br"\
  "eak;s++}this.stack=i;const n=s;this.parseRange(e,n);return th"\
  "is.nodes.length==r?null:this.nodes[this.nodes.length-1]}getNo"\
  "deFor(t){if(void 0===this.peek(t))return null;for(let e of th"\
  "is.nodes)if(e.token.position===t)return e;return this.nodes.p"\
  "ush(new EsilNode(new EsilToken(\"label\",t),\"label\")),null}find"\
  "NodeFor(t){for(let e of this.nodes)if(e.token.position===t)re"\
  "turn e;return null}isOperation(t){switch(t.toString()){case\"["\
  "1]\":case\"[2]\":case\"[4]\":case\"[8]\":if(!(this.stack.length>=1))"\
  "throw new Error(\"Stack needs more items\");{const t=this.stack"\
  ".pop();new EsilNode(t.token,\"operation\");this.stack.push(t)}r"\
  "eturn!0;case\"!\":if(!(this.stack.length>=1))throw new Error(\"S"\
  "tack needs more items\");{const e=new EsilNode(new EsilToken(\""\
  "\",t.position),\"none\"),s=this.stack.pop(),i=new EsilNode(t,\"op"\
  "eration\");i.setSides(e,s),this.stack.push(i)}return!0;case\"\":"\
  "case\"}\":case\"}{\":return!0;case\"DUP\":{if(this.stack.length<1)t"\
  "hrow new Error(\"goto cant pop\");const t=this.stack.pop();this"\
  ".stack.push(t),this.stack.push(t)}return!0;case\"GOTO\":if(null"\
  "!==this.peek(t.position-1)){if(this.stack.length<1)throw new "\
  "Error(\"goto cant pop\");const e=this.stack.pop();if(null!==e){"\
  "const s=0|+e.toString();if(s>0){const e=this.peek(s);if(void "\
  "0!==e){e.label=\"label_\"+s,e.comment=\"hehe\";const i=new EsilNo"\
  "de(t,\"goto\"),r=this.getNodeFor(e.position);null!=r&&i.childre"\
  "n.push(r),this.root.children.push(i)}else console.error(\"Cann"\
  "ot find goto node\")}else console.error(\"Cannot find dest node"\
  " for goto\")}}return!0;case\"?{\":if(!(this.stack.length>=1))thr"\
  "ow new Error(\"Stack needs more items\");{const e=new EsilNode("\
  "new EsilToken(\"if\",t.position),\"none\"),s=this.stack.pop(),i=n"\
  "ew EsilNode(t,\"operation\");i.setSides(e,s);let r=this.parseUn"\
  "til(t.position),n=null;null!==r&&(i.children.push(r),this.nod"\
  "es.push(r),n=this.parseUntil(r.token.position+1),null!==n&&(i"\
  ".children.push(n),this.nodes.push(n))),this.nodes.push(i),thi"\
  "s.root.children.push(i),null!==n&&(this.cur=n.token.position)"\
  "}return!0;case\"-\":if(!(this.stack.length>=2))throw new Error("\
  "\"Stack needs more items\");{const e=this.stack.pop(),s=this.st"\
  "ack.pop(),i=new EsilNode(t,\"operation\");i.setSides(e,s),this."\
  "stack.length,this.stack.push(i),this.nodes.push(i)}return!0;c"\
  "ase\"<\":case\">\":case\"^\":case\"&\":case\"|\":case\"+\":case\"*\":case\"/"\
  "\":case\">>=\":case\"<<=\":case\">>>=\":case\"<<<=\":case\">>>>=\":case\""\
  "<<<<=\":if(!(this.stack.length>=2))throw new Error(\"Stack need"\
  "s more items\");{const e=this.stack.pop(),s=this.stack.pop(),i"\
  "=new EsilNode(t,\"operation\");i.setSides(e,s),this.stack.lengt"\
  "h,this.stack.push(i),this.nodes.push(i)}return!0;case\"=\":case"\
  "\":=\":case\"-=\":case\"+=\":case\"==\":case\"=[1]\":case\"=[2]\":case\"=["\
  "4]\":case\"=[8]\":if(!(this.stack.length>=2))throw new Error(\"St"\
  "ack needs more items\");{const e=this.stack.pop(),s=this.stack"\
  ".pop(),i=new EsilNode(t,\"operation\");i.setSides(e,s),0===this"\
  ".stack.length&&this.root.children.push(i),this.nodes.push(i)}"\
  "return!0}return!1}}G.EsilParser=EsilParser;\n";
