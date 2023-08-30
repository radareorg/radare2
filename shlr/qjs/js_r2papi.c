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
  "    ${t}: ${typeof e[t]};\\n`}return`${s}}\\n`}setLogLevel(t){r"\
  "eturn this.cmd(\"e log.level=\"+t),this}newMap(t,e,s,i,r,n=\"\"){"\
  "this.cmd(`om ${t} ${e} ${s} ${i} ${r} ${n}`)}at(t){return new"\
  " NativePointer(t)}getShell(){return new shell_js_1.R2PapiShel"\
  "l(this)}version(){return this.r2.cmd(\"?Vq\").trim()}platform()"\
  "{return this.r2.cmd(\"uname\").trim()}arch(){return this.r2.cmd"\
  "(\"uname -a\").trim()}bits(){return this.r2.cmd(\"uname -b\").tri"\
  "m()}id(){return+this.r2.cmd(\"?vi:$p\")}printAt(t,e,s){}clearSc"\
  "reen(){return this.r2.cmd(\"!clear\"),this}getConfig(t){return "\
  "this.r2.call(\"e \"+t).trim()}setConfig(t,e){return this.r2.cal"\
  "l(\"e \"+t+\"=\"+e),this}getRegisters(){return this.cmdj(\"drj\")}r"\
  "esizeFile(t){return this.cmd(`r ${t}`),this}insertNullBytes(t"\
  ",e){return void 0===e&&(e=\"$$\"),this.cmd(`r+${t}@${e}`),this}"\
  "removeBytes(t,e){return void 0===e&&(e=\"$$\"),this.cmd(`r-${t}"\
  "@${e}`),this}seek(t){return this.cmd(`s ${t}`),this}currentSe"\
  "ek(){return new NativePointer(\"$$\")}seekToRelativeOpcode(t){r"\
  "eturn this.cmd(`so ${t}`),this.currentSeek()}getBlockSize(){r"\
  "eturn+this.cmd(\"b\")}setBlockSize(t){return this.cmd(`b ${t}`)"\
  ",this}countFlags(){return Number(this.cmd(\"f~?\"))}countFuncti"\
  "ons(){return Number(this.cmd(\"aflc\"))}analyzeProgram(t){switc"\
  "h(void 0===t&&(t=0),t){case 0:this.cmd(\"aa\");break;case 1:thi"\
  "s.cmd(\"aaa\");break;case 2:this.cmd(\"aaaa\");break;case 3:this."\
  "cmd(\"aaaaa\")}return this}enumerateThreads(){return[{context:t"\
  "his.cmdj(\"drj\"),id:0,state:\"waiting\",selected:!0}]}currentThr"\
  "eadId(){return+this.cmd(\"e cfg.debug\")?+this.cmd(\"dpt.\"):this"\
  ".id()}setRegisters(t){for(let e of Object.keys(t)){const s=t["\
  "e];this.r2.cmd(\"dr \"+e+\"=\"+s)}}hex(t){return this.r2.cmd(\"?v "\
  "\"+t).trim()}step(){return this.r2.cmd(\"ds\"),this}stepOver(){r"\
  "eturn this.r2.cmd(\"dso\"),this}math(t){return+this.r2.cmd(\"?v "\
  "\"+t)}stepUntil(t){this.cmd(`dsu ${t}`)}enumerateXrefsTo(t){re"\
  "turn this.call(\"axtq \"+t).trim().split(/\\n/)}findXrefsTo(t,e)"\
  "{e?this.call(\"/r \"+t):this.call(\"/re \"+t)}analyzeFunctionsFro"\
  "mCalls(){return this.call(\"aac\"),this}analyzeFunctionsWithPre"\
  "ludes(){return this.call(\"aap\"),this}analyzeObjCReferences(){"\
  "return this.cmd(\"aao\"),this}analyzeImports(){return this.cmd("\
  "\"af @ sym.imp.*\"),this}searchDisasm(t){return this.callj(\"/ad"\
  " \"+t)}searchString(t){return this.cmdj(\"/j \"+t)}searchBytes(t"\
  "){const e=t.map((function(t){return(255&t).toString(16)})).jo"\
  "in(\"\");return this.cmdj(\"/xj \"+e)}binInfo(){try{return this.c"\
  "mdj(\"ij~{bin}\")}catch(t){return{}}}selectBinary(t){this.call("\
  "`ob ${t}`)}openFile(t){this.call(`o ${t}`)}currentFile(t){ret"\
  "urn this.call(\"o.\").trim()}enumeratePlugins(t){switch(t){case"\
  "\"bin\":return this.callj(\"Lij\");case\"io\":return this.callj(\"Lo"\
  "j\");case\"core\":return this.callj(\"Lcj\");case\"arch\":return thi"\
  "s.callj(\"LAj\");case\"anal\":return this.callj(\"Laj\");case\"lang\""\
  ":return this.callj(\"Llj\")}return[]}enumerateModules(){return "\
  "this.callj(\"dmmj\")}enumerateFiles(){return this.callj(\"oj\")}e"\
  "numerateBinaries(){return this.callj(\"obj\")}enumerateMaps(){r"\
  "eturn this.callj(\"omj\")}enumerateSymbols(){return this.callj("\
  "\"isj\")}enumerateExports(){return this.callj(\"iEj\")}enumerateI"\
  "mports(){return this.callj(\"iij\")}enumerateLibraries(){return"\
  " this.callj(\"ilj\")}enumerateSections(){return this.callj(\"iSj"\
  "\")}enumerateSegments(){return this.callj(\"iSSj\")}enumerateEnt"\
  "rypoints(){return this.callj(\"iej\")}enumerateRelocations(){re"\
  "turn this.callj(\"irj\")}enumerateFunctions(){return this.cmdj("\
  "\"aflj\")}enumerateFlags(){return this.cmdj(\"fj\")}skip(){this.r"\
  "2.cmd(\"dss\")}ptr(t){return new NativePointer(t,this)}call(t){"\
  "return this.r2.call(t)}callj(t){return JSON.parse(this.call(t"\
  "))}cmd(t){return this.r2.cmd(t)}cmdj(t){return JSON.parse(thi"\
  "s.cmd(t))}log(t){return this.r2.log(t)}clippy(t){this.r2.log("\
  "this.r2.cmd(\"?E \"+t))}ascii(t){this.r2.log(this.r2.cmd(\"?ea \""\
  "+t))}}G.R2Papi=R2Papi;class NativePointer{constructor(t,e){th"\
  "is.api=void 0===e?G.R:e,this.addr=(\"\"+t).trim()}hexdump(t){le"\
  "t e=void 0===t?\"\":\"\"+t;return this.api.cmd(`x${e}@${this.addr"\
  "}`)}functionGraph(t){return\"dot\"===t?this.api.cmd(`agfd@ ${th"\
  "is.addr}`):\"json\"===t?this.api.cmd(`agfj@${this.addr}`):\"merm"\
  "aid\"===t?this.api.cmd(`agfm@${this.addr}`):this.api.cmd(`agf@"\
  "${this.addr}`)}readByteArray(t){return JSON.parse(this.api.cm"\
  "d(`p8j ${t}@${this.addr}`))}readHexString(t){return this.api."\
  "cmd(`p8 ${t}@${this.addr}`).trim()}and(t){const e=this.api.ca"\
  "ll(`?v ${this.addr} & ${t}`).trim();return new NativePointer("\
  "e)}or(t){const e=this.api.call(`?v ${this.addr} | ${t}`).trim"\
  "();return new NativePointer(e)}add(t){const e=this.api.call(`"\
  "?v ${this.addr}+${t}`).trim();return new NativePointer(e)}sub"\
  "(t){const e=this.api.call(`?v ${this.addr}-${t}`).trim();retu"\
  "rn new NativePointer(e)}writeByteArray(t){return this.api.cmd"\
  "(\"wx \"+t.join(\"\")),this}writeAssembly(t){return this.api.cmd("\
  "`\"wa ${t} @ ${this.addr}`),this}writeCString(t){return this.a"\
  "pi.call(\"w \"+t),this}isNull(){return 0==+this.addr}compare(t)"\
  "{return\"string\"!=typeof t&&\"number\"!=typeof t||(t=new NativeP"\
  "ointer(t)),t.addr===this.addr}pointsToNull(){return this.read"\
  "Pointer().compare(0)}toString(){return this.addr.trim()}write"\
  "Pointer(t){this.api.cmd(`wvp ${t}@${this}`)}readPointer(){ret"\
  "urn new NativePointer(this.api.call(\"pvp@\"+this.addr))}readU8"\
  "(){return parseInt(this.api.cmd(`pv1d@${this.addr}`))}readU16"\
  "(){return parseInt(this.api.cmd(`pv2d@${this.addr}`))}readU32"\
  "(){return parseInt(this.api.cmd(`pv4d@${this.addr}`))}readU64"\
  "(){return parseInt(this.api.cmd(`pv8d@${this.addr}`))}writeIn"\
  "t(t){return+this.api.cmd(`wv4 ${t}@${this.addr}`)}writeU8(t){"\
  "return this.api.cmd(`wv1 ${t}@${this.addr}`),!0}writeU16(t){r"\
  "eturn this.api.cmd(`wv2 ${t}@${this.addr}`),!0}writeU32(t){re"\
  "turn this.api.cmd(`wv4 ${t}@${this.addr}`),!0}writeU64(t){ret"\
  "urn this.api.cmd(`wv8 ${t}@${this.addr}`),!0}readInt(){return"\
  " this.readU32()}readCString(){return JSON.parse(this.api.cmd("\
  "`pszj@${this.addr}`)).string}instruction(){return this.api.cmd"\
  "j(`aoj@${this.addr}`)[0]}disassemble(t){let e=void 0===t?\"\":\""\
  "\"+t;return this.api.cmd(`pd ${e}@${this.addr}`)}analyzeFuncti"\
  "on(){return this.api.cmd(\"af@\"+this.addr),this}analyzeFunctio"\
  "nRecursively(){return this.api.cmd(\"afr@\"+this.addr),this}nam"\
  "e(){return this.api.cmd(\"fd \"+this.addr).trim()}basicBlock(){"\
  "return this.api.cmdj(\"abj@\"+this.addr)}functionBasicBlocks(){"\
  "return this.api.cmdj(\"afbj@\"+this.addr)}xrefs(){return this.a"\
  "pi.cmdj(\"axtj@\"+this.addr)}}G.NativePointer=NativePointer;cla"\
  "ss Base64{static encode(t){return(0,G.b64)(t)}static decode(t"\
  "){return(0,G.b64)(t,!0)}}G.Base64=Base64,Object.definePropert"\
  "y(G,\"__esModule\",{value:!0}),G.R2PapiShell=void 0;class R2Pap"\
  "iShell{constructor(t){this.rp=t}mkdir(t,e){return!0===e?this."\
  "rp.call(`mkdir -p ${t}`):this.rp.call(`mkdir ${t}`),!0}unlink"\
  "(t){return this.rp.call(`rm ${t}`),!0}chdir(t){return this.rp"\
  ".call(`cd ${t}`),!0}ls(){return this.rp.call(\"ls -q\").trim()."\
  "split(\"\\n\")}fileExists(t){return!1}open(t){this.rp.call(`open"\
  " ${t}`)}system(t){return this.rp.call(`!${t}`),0}run(t){retur"\
  "n this.rp.call(`rm ${t}`),0}mount(t,e){return this.rp.call(`m"\
  " ${t} ${e}`),!0}umount(t){this.rp.call(`m-${t}`)}chdir2(t){re"\
  "turn void 0===t&&(t=\"/\"),this.rp.call(`mdq ${t}`),!0}ls2(t){r"\
  "eturn void 0===t&&(t=\"/\"),this.rp.call(`mdq ${t}`).trim().spl"\
  "it(\"\\n\")}enumerateMountpoints(){return this.rp.cmdj(\"mlj\")}is"\
  "Symlink(t){return!1}isDirectory(t){return!1}}G.R2PapiShell=R2"\
  "PapiShell,Object.defineProperty(G,\"__esModule\",{value:!0}),G."\
  "EsilParser=G.EsilNode=G.EsilToken=void 0;class EsilToken{cons"\
  "tructor(t=\"\",e=0){this.label=\"\",this.comment=\"\",this.text=\"\","\
  "this.addr=\"0\",this.position=0,this.text=t,this.position=e}toS"\
  "tring(){return this.text}}G.EsilToken=EsilToken;class EsilNod"\
  "e{constructor(t=new EsilToken,e=\"none\"){this.type=\"none\",this"\
  ".token=t,this.children=[]}setSides(t,e){this.lhs=t,this.rhs=e"\
  "}addChildren(t,e){void 0!==t&&this.children.push(t),void 0!=="\
  "e&&this.children.push(e)}toEsil(){if(void 0!==this.lhs&&void "\
  "0!==this.rhs){let t=this.lhs.toEsil();return\"\"!==t&&(t+=\",\"),"\
  "`${this.rhs.toEsil()},${t}${this.token}`}return\"\"}toString(){"\
  "let t=\"\";if(\"\"!==this.token.label&&(t+=this.token.label+\":\\n\""\
  "),this.token.addr,\"\"!==this.token.comment&&(t+=\"/*\"+this.toke"\
  "n.comment+\"*/\\n\"),\"GOTO\"===this.token.toString())if(this.chil"\
  "dren.length>0){t+=\"goto label_\"+this.children[0].token.positi"\
  "on+\";\\n\"}else{t+=`goto label_${0};\\n`}if(this.children.length"\
  ">0){t+=`  (if (${this.rhs})\\n`;for(let e of this.children)if("\
  "null!==e){const s=e.toString();\"\"!=s&&(t+=`  ${s}\\n`)}t+=\"  )"\
  "\\n\"}return void 0!==this.lhs&&void 0!==this.rhs?t+`    ( ${th"\
  "is.lhs} ${this.token} ${this.rhs} )`:t+this.token.toString()}"\
  "}G.EsilNode=EsilNode;class EsilParser{constructor(t){this.cur"\
  "=0,this.r2=t,this.cur=0,this.stack=[],this.nodes=[],this.toke"\
  "ns=[],this.root=new EsilNode(new EsilToken(\"function\",0),\"blo"\
  "ck\")}toJSON(){if(this.stack.length>0)throw new Error(\"The ESI"\
  "L stack is not empty\");return JSON.stringify(this.root,null,2"\
  ")}toEsil(){return this.nodes.map((t=>t.toEsil())).join(\",\")}o"\
  "ptimizeFlags(t){void 0!==t.rhs&&this.optimizeFlags(t.rhs),voi"\
  "d 0!==t.lhs&&this.optimizeFlags(t.lhs);for(let e=0;e<t.childr"\
  "en.length;e++)this.optimizeFlags(t.children[e]);const e=t.toS"\
  "tring();if(+e>4096){const s=r2.cmd(`fd.@ ${e}`).trim().split("\
  "\"\\n\")[0].trim();\"\"!=s&&-1===s.indexOf(\"+\")&&(t.token.text=s)}"\
  "}optimize(t){-1!=t.indexOf(\"flag\")&&this.optimizeFlags(this.r"\
  "oot)}toString(){return this.root.children.map((t=>t.toString("\
  "))).join(\";\\n\")}reset(){this.nodes=[],this.stack=[],this.toke"\
  "ns=[],this.cur=0,this.root=new EsilNode(new EsilToken(\"functi"\
  "on\",0),\"block\")}parseRange(t,e){let s=t;for(;s<this.tokens.le"\
  "ngth&&s<e;){const t=this.peek(s);if(!t)break;this.cur=s,this."\
  "pushToken(t),s=this.cur,s++}}parseFunction(t){var e=this;func"\
  "tion s(t){const s=r2.cmd(\"pie \"+t+\" @e:scr.color=0\").trim().s"\
  "plit(\"\\n\");for(const t of s){if(0===t.length){console.log(\"Em"\
  "pty\");continue}const s=t.split(\" \");s.length>1&&(r2.cmd(`s ${"\
  "s[0]}`),e.parse(s[1],s[0]),e.optimize(\"flags,labels\"))}}const"\
  " i=r2.cmd(\"?v $$\").trim();void 0===t&&(t=i);const r=r2.cmdj(`"\
  "afbj@${t}`);for(let t of r)r2.cmd(`s ${t.addr}`),s(t.ninstr);"\
  "r2.cmd(`s ${i}`)}parse(t,e){const s=t.trim().split(\",\").map(("\
  "t=>t.trim())),i=this.tokens.length;for(let t of s){const s=ne"\
  "w EsilToken(t,this.tokens.length);void 0!==e&&(s.addr=e),this"\
  ".tokens.push(s)}const r=this.tokens.length;this.parseRange(i,"\
  "r)}peek(t){return this.tokens[t]}pushToken(t){if(this.isNumbe"\
  "r(t)){const e=new EsilNode(t,\"number\");this.stack.push(e),thi"\
  "s.nodes.push(e)}else if(this.isInternal(t)){const e=new EsilN"\
  "ode(t,\"flag\");this.stack.push(e),this.nodes.push(e)}else if(t"\
  "his.isOperation(t));else{const e=new EsilNode(t,\"register\");t"\
  "his.stack.push(e),this.nodes.push(e)}}isNumber(t){return!!t.t"\
  "oString().startsWith(\"0\")||+t>0}isInternal(t){const e=t.toStr"\
  "ing();return e.startsWith(\"$\")&&e.length>1}parseUntil(t){cons"\
  "t e=t+1;let s=e;const i=[],r=this.nodes.length;for(this.stack"\
  ".forEach((t=>i.push(t)));s<this.tokens.length;){const t=this."\
  "peek(s);if(!t)break;if(\"}\"===t.toString())break;if(\"}{\"===t.t"\
  "oString())break;s++}this.stack=i;const n=s;this.parseRange(e,"\
  "n);return this.nodes.length==r?null:this.nodes[this.nodes.len"\
  "gth-1]}getNodeFor(t){if(void 0===this.peek(t))return null;for"\
  "(let e of this.nodes)if(e.token.position===t)return e;return "\
  "this.nodes.push(new EsilNode(new EsilToken(\"label\",t),\"label\""\
  ")),null}findNodeFor(t){for(let e of this.nodes)if(e.token.pos"\
  "ition===t)return e;return null}isOperation(t){switch(t.toStri"\
  "ng()){case\"[1]\":case\"[2]\":case\"[4]\":case\"[8]\":if(!(this.stack"\
  ".length>=1))throw new Error(\"Stack needs more items\");{const "\
  "t=this.stack.pop();new EsilNode(t.token,\"operation\");this.sta"\
  "ck.push(t)}return!0;case\"!\":if(!(this.stack.length>=1))throw "\
  "new Error(\"Stack needs more items\");{const e=new EsilNode(new"\
  " EsilToken(\"\",t.position),\"none\"),s=this.stack.pop(),i=new Es"\
  "ilNode(t,\"operation\");i.setSides(e,s),this.stack.push(i)}retu"\
  "rn!0;case\"\":case\"}\":case\"}{\":return!0;case\"DUP\":{if(this.stac"\
  "k.length<1)throw new Error(\"goto cant pop\");const t=this.stac"\
  "k.pop();this.stack.push(t),this.stack.push(t)}return!0;case\"G"\
  "OTO\":if(null!==this.peek(t.position-1)){if(this.stack.length<"\
  "1)throw new Error(\"goto cant pop\");const e=this.stack.pop();i"\
  "f(null!==e){const s=0|+e.toString();if(s>0){const e=this.peek"\
  "(s);if(void 0!==e){e.label=\"label_\"+s,e.comment=\"hehe\";const "\
  "i=new EsilNode(t,\"goto\"),r=this.getNodeFor(e.position);null!="\
  "r&&i.children.push(r),this.root.children.push(i)}else console"\
  ".error(\"Cannot find goto node\")}else console.error(\"Cannot fi"\
  "nd dest node for goto\")}}return!0;case\"?{\":if(!(this.stack.le"\
  "ngth>=1))throw new Error(\"Stack needs more items\");{const e=n"\
  "ew EsilNode(new EsilToken(\"if\",t.position),\"none\"),s=this.sta"\
  "ck.pop(),i=new EsilNode(t,\"operation\");i.setSides(e,s);let r="\
  "this.parseUntil(t.position),n=null;null!==r&&(i.children.push"\
  "(r),this.nodes.push(r),n=this.parseUntil(r.token.position+1),"\
  "null!==n&&(i.children.push(n),this.nodes.push(n))),this.nodes"\
  ".push(i),this.root.children.push(i),null!==n&&(this.cur=n.tok"\
  "en.position)}return!0;case\"-\":if(!(this.stack.length>=2))thro"\
  "w new Error(\"Stack needs more items\");{const e=this.stack.pop"\
  "(),s=this.stack.pop(),i=new EsilNode(t,\"operation\");i.setSide"\
  "s(e,s),this.stack.length,this.stack.push(i),this.nodes.push(i"\
  ")}return!0;case\"<\":case\">\":case\"^\":case\"&\":case\"|\":case\"+\":ca"\
  "se\"*\":case\"/\":case\">>=\":case\"<<=\":case\">>>=\":case\"<<<=\":case\""\
  ">>>>=\":case\"<<<<=\":if(!(this.stack.length>=2))throw new Error"\
  "(\"Stack needs more items\");{const e=this.stack.pop(),s=this.s"\
  "tack.pop(),i=new EsilNode(t,\"operation\");i.setSides(e,s),this"\
  ".stack.length,this.stack.push(i),this.nodes.push(i)}return!0;"\
  "case\"=\":case\":=\":case\"-=\":case\"+=\":case\"==\":case\"=[1]\":case\"="\
  "[2]\":case\"=[4]\":case\"=[8]\":if(!(this.stack.length>=2))throw n"\
  "ew Error(\"Stack needs more items\");{const e=this.stack.pop(),"\
  "s=this.stack.pop(),i=new EsilNode(t,\"operation\");i.setSides(e"\
  ",s),0===this.stack.length&&this.root.children.push(i),this.no"\
  "des.push(i)}return!0}return!1}}G.EsilParser=EsilParser;\n";
