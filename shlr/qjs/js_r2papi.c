static const char *const js_r2papi_qjs = "" \
  "Object.defineProperty(G,\"__esModule\",{value:!0}),G.Base64=G.N"\
  "ativePointer=G.R2Papi=G.Assembler=void 0;const shell_js_1=G;G"\
  ".Assembler=class{constructor(t){this.program=\"\",this.labels={"\
  "},this.endian=!1,this.pc=0,this.r2=null,this.r2=void 0===t?G."\
  "r2:t,this.program=\"\",this.labels={}}setProgramCounter(t){this"\
  ".pc=t}setEndian(t){this.endian=t}toString(){return this.progr"\
  "am}append(t){this.pc+=t.length/2,this.program+=t}label(t){var"\
  " s=this.pc;return this.labels[t]=this.pc,s}asm(t){let s=this."\
  "r2.cmd('\"\"pa '+t).trim();s.length<16||(s=\"____\",console.error"\
  "(\"Invalid instruction: \"+t)),this.append(s)}};G.R2Papi=class{"\
  "constructor(t){this.r2=t}getBaseAddress(){return new NativePo"\
  "inter(this.cmd(\"e bin.baddr\"))}jsonToTypescript(t,s){let e=`i"\
  "nterface ${t} {\n`;s.length&&0<s.length&&(s=s[0]);for(let t of"\
  " Object.keys(s))e+=`    ${t}: ${typeof s[t]};\n`;return e+`}\n`"\
  "}setLogLevel(t){return this.cmd(\"e log.level=\"+t),this}newMap"\
  "(t,s,e,i,r,n=\"\"){this.cmd(`om ${t} ${s} ${e} ${i} ${r} `+n)}a"\
  "t(t){return new NativePointer(t)}getShell(){return new shell_"\
  "js_1.R2PapiShell(this)}version(){return this.r2.cmd(\"?Vq\").tr"\
  "im()}platform(){return this.r2.cmd(\"uname\").trim()}arch(){ret"\
  "urn this.r2.cmd(\"uname -a\").trim()}bits(){return this.r2.cmd("\
  "\"uname -b\").trim()}id(){return+this.r2.cmd(\"?vi:$p\")}printAt("\
  "t,s,e){}clearScreen(){return this.r2.cmd(\"!clear\"),this}getCo"\
  "nfig(t){return this.r2.call(\"e \"+t).trim()}setConfig(t,s){ret"\
  "urn this.r2.call(\"e \"+t+\"=\"+s),this}getRegisters(){return thi"\
  "s.cmdj(\"drj\")}resizeFile(t){return this.cmd(\"r \"+t),this}inse"\
  "rtNullBytes(t,s){return this.cmd(`r+${t}@`+(s=void 0===s?\"$$\""\
  ":s)),this}removeBytes(t,s){return this.cmd(`r-${t}@`+(s=void "\
  "0===s?\"$$\":s)),this}seek(t){return this.cmd(\"s \"+t),this}curr"\
  "entSeek(){return new NativePointer(\"$$\")}seekToRelativeOpcode"\
  "(t){return this.cmd(\"so \"+t),this.currentSeek()}getBlockSize("\
  "){return+this.cmd(\"b\")}setBlockSize(t){return this.cmd(\"b \"+t"\
  "),this}countFlags(){return Number(this.cmd(\"f~?\"))}countFunct"\
  "ions(){return Number(this.cmd(\"aflc\"))}analyzeProgram(t){swit"\
  "ch(t=void 0===t?0:t){case 0:this.cmd(\"aa\");break;case 1:this."\
  "cmd(\"aaa\");break;case 2:this.cmd(\"aaaa\");break;case 3:this.cm"\
  "d(\"aaaaa\")}return this}enumerateThreads(){return[{context:thi"\
  "s.cmdj(\"drj\"),id:0,state:\"waiting\",selected:!0}]}currentThrea"\
  "dId(){return+this.cmd(\"e cfg.debug\")?+this.cmd(\"dpt.\"):this.i"\
  "d()}setRegisters(t){for(var s of Object.keys(t)){var e=t[s];t"\
  "his.r2.cmd(\"dr \"+s+\"=\"+e)}}hex(t){return this.r2.cmd(\"?v \"+t)"\
  ".trim()}step(){return this.r2.cmd(\"ds\"),this}stepOver(){retur"\
  "n this.r2.cmd(\"dso\"),this}math(t){return+this.r2.cmd(\"?v \"+t)"\
  "}stepUntil(t){this.cmd(\"dsu \"+t)}enumerateXrefsTo(t){return t"\
  "his.call(\"axtq \"+t).trim().split(/\\n/)}findXrefsTo(t,s){s?thi"\
  "s.call(\"/r \"+t):this.call(\"/re \"+t)}analyzeFunctionsFromCalls"\
  "(){return this.call(\"aac\"),this}analyzeFunctionsWithPreludes("\
  "){return this.call(\"aap\"),this}analyzeObjCReferences(){return"\
  " this.cmd(\"aao\"),this}analyzeImports(){return this.cmd(\"af @ "\
  "sym.imp.*\"),this}searchDisasm(t){return this.callj(\"/ad \"+t)}"\
  "searchString(t){return this.cmdj(\"/j \"+t)}searchBytes(t){t=t."\
  "map(function(t){return(255&t).toString(16)}).join(\"\");return "\
  "this.cmdj(\"/xj \"+t)}binInfo(){try{return this.cmdj(\"ij~{bin}\""\
  ")}catch(t){return{}}}selectBinary(t){this.call(\"ob \"+t)}openF"\
  "ile(t){this.call(\"o \"+t)}currentFile(t){return this.call(\"o.\""\
  ").trim()}enumeratePlugins(t){switch(t){case\"bin\":return this."\
  "callj(\"Lij\");case\"io\":return this.callj(\"Loj\");case\"core\":ret"\
  "urn this.callj(\"Lcj\");case\"arch\":return this.callj(\"LAj\");cas"\
  "e\"anal\":return this.callj(\"Laj\");case\"lang\":return this.callj"\
  "(\"Llj\")}return[]}enumerateModules(){return this.callj(\"dmmj\")"\
  "}enumerateFiles(){return this.callj(\"oj\")}enumerateBinaries()"\
  "{return this.callj(\"obj\")}enumerateMaps(){return this.callj(\""\
  "omj\")}enumerateSymbols(){return this.callj(\"isj\")}enumerateEx"\
  "ports(){return this.callj(\"iEj\")}enumerateImports(){return th"\
  "is.callj(\"iij\")}enumerateLibraries(){return this.callj(\"ilj\")"\
  "}enumerateSections(){return this.callj(\"iSj\")}enumerateSegmen"\
  "ts(){return this.callj(\"iSSj\")}enumerateEntrypoints(){return "\
  "this.callj(\"iej\")}enumerateRelocations(){return this.callj(\"i"\
  "rj\")}enumerateFunctions(){return this.cmdj(\"aflj\")}enumerateF"\
  "lags(){return this.cmdj(\"fj\")}skip(){this.r2.cmd(\"dss\")}ptr(t"\
  "){return new NativePointer(t,this)}call(t){return this.r2.cal"\
  "l(t)}callj(t){return JSON.parse(this.call(t))}cmd(t){return t"\
  "his.r2.cmd(t)}cmdj(t){return JSON.parse(this.cmd(t))}log(t){r"\
  "eturn this.r2.log(t)}clippy(t){this.r2.log(this.r2.cmd(\"?E \"+"\
  "t))}ascii(t){this.r2.log(this.r2.cmd(\"?ea \"+t))}};class Nativ"\
  "ePointer{constructor(t,s){this.api=void 0===s?G.R:s,this.addr"\
  "=(\"\"+t).trim()}hexdump(t){return this.api.cmd(`x${void 0===t?"\
  "\"\":\"\"+t}@`+this.addr)}functionGraph(t){return\"dot\"===t?this.a"\
  "pi.cmd(\"agfd@ \"+this.addr):\"json\"===t?this.api.cmd(\"agfj@\"+th"\
  "is.addr):\"mermaid\"===t?this.api.cmd(\"agfm@\"+this.addr):this.a"\
  "pi.cmd(\"agf@\"+this.addr)}readByteArray(t){return JSON.parse(t"\
  "his.api.cmd(`p8j ${t}@`+this.addr))}readHexString(t){return t"\
  "his.api.cmd(`p8 ${t}@`+this.addr).trim()}and(t){return this.a"\
  "ddr=this.api.call(`?v ${this.addr} & `+t).trim(),this}or(t){r"\
  "eturn this.addr=this.api.call(`?v ${this.addr} | `+t).trim(),"\
  "this}add(t){return this.addr=this.api.call(`?v ${this.addr}+`"\
  "+t).trim(),this}sub(t){return this.addr=this.api.call(`?v ${t"\
  "his.addr}-`+t).trim(),this}writeByteArray(t){return this.api."\
  "cmd(\"wx \"+t.join(\"\")),this}writeAssembly(t){return this.api.c"\
  "md(`\"wa ${t} @ `+this.addr),this}writeCString(t){return this."\
  "api.call(\"w \"+t),this}isNull(){return 0==+this.addr}compare(t"\
  "){return(t=\"string\"!=typeof t&&\"number\"!=typeof t?t:new Nativ"\
  "ePointer(t)).addr===this.addr}pointsToNull(){return this.read"\
  "Pointer().compare(0)}toString(){return this.addr.trim()}write"\
  "Pointer(t){var s=64==+this.api.getConfig(\"asm.bits\")?\"wv8\":\"w"\
  "v4\";this.api.cmd(s+` ${t}@`+this)}readPointer(){return 64==+t"\
  "his.api.getConfig(\"asm.bits\")?new NativePointer(this.api.call"\
  "(\"pv8@\"+this.addr)):new NativePointer(this.api.call(\"pv4@\"+th"\
  "is.addr))}readU8(){return+this.api.cmd('pv1@\"'+this.addr)}rea"\
  "dU16(){return+this.api.cmd('pv2@\"'+this.addr)}readU32(){retur"\
  "n+this.api.cmd('pv4@\"'+this.addr)}readU64(){return+this.api.c"\
  "md('pv8@\"'+this.addr)}writeInt(t){return+this.api.cmd(`wv4 ${"\
  "t}@`+this.addr)}writeU8(t){return this.api.cmd(`wv1 ${t}@`+th"\
  "is.addr),!0}writeU16(t){return this.api.cmd(`wv2 ${t}@`+this."\
  "addr),!0}writeU32(t){return this.api.cmd(`wv4 ${t}@`+this.add"\
  "r),!0}writeU64(t){return this.api.cmd(`wv8 ${t}@`+this.addr),"\
  "!0}readInt(){return+this.api.cmd('pv4@\"'+this.addr)}readCStri"\
  "ng(){return JSON.parse(this.api.cmd(\"psj@\"+this.addr)).string"\
  "}instruction(){return this.api.cmdj(\"aoj@\"+this.addr)[0]}disa"\
  "ssemble(t){return this.api.cmd(`pd ${void 0===t?\"\":\"\"+t}@`+th"\
  "is.addr)}analyzeFunction(){return this.api.cmd(\"af@\"+this.add"\
  "r),this}analyzeFunctionRecursively(){return this.api.cmd(\"afr"\
  "@\"+this.addr),this}name(){return this.api.cmd(\"fd \"+this.addr"\
  ").trim()}basicBlock(){return this.api.cmdj(\"abj@\"+this.addr)}"\
  "functionBasicBlocks(){return this.api.cmdj(\"afbj@\"+this.addr)"\
  "}xrefs(){return this.api.cmdj(\"axtj@\"+this.addr)}}G.NativePoi"\
  "nter=NativePointer;G.Base64=class{static encode(t){return(0,G"\
  ".b64)(t)}static decode(t){return(0,G.b64)(t,!0)}},Object.defi"\
  "neProperty(G,\"__esModule\",{value:!0}),G.R2PapiShell=void 0;G."\
  "R2PapiShell=class{constructor(t){this.rp=t}mkdir(t,s){return!"\
  "0===s?this.rp.call(\"mkdir -p \"+t):this.rp.call(\"mkdir \"+t),!0"\
  "}unlink(t){return this.rp.call(\"rm \"+t),!0}chdir(t){return th"\
  "is.rp.call(\"cd \"+t),!0}ls(){return this.rp.call(\"ls -q\").trim"\
  "().split(\"\\n\")}fileExists(t){return!1}open(t){this.rp.call(\"o"\
  "pen \"+t)}system(t){return this.rp.call(\"!\"+t),0}run(t){return"\
  " this.rp.call(\"rm \"+t),0}mount(t,s){return this.rp.call(`m ${"\
  "t} `+s),!0}umount(t){this.rp.call(\"m-\"+t)}chdir2(t){return th"\
  "is.rp.call(\"mdq \"+(t=void 0===t?\"/\":t)),!0}ls2(t){return this"\
  ".rp.call(\"mdq \"+(t=void 0===t?\"/\":t)).trim().split(\"\\n\")}enum"\
  "erateMountpoints(){return this.rp.cmdj(\"mlj\")}isSymlink(t){re"\
  "turn!1}isDirectory(t){return!1}},Object.defineProperty(G,\"__e"\
  "sModule\",{value:!0}),G.EsilParser=G.EsilNode=G.EsilToken=void"\
  " 0;class EsilToken{constructor(t=\"\",s=0){this.label=\"\",this.c"\
  "omment=\"\",this.text=\"\",this.addr=\"0\",this.position=0,this.tex"\
  "t=t,this.position=s}toString(){return this.text}}G.EsilToken="\
  "EsilToken;class EsilNode{constructor(t=new EsilToken,s){this."\
  "type=\"none\",this.token=t,this.children=[]}setSides(t,s){this."\
  "lhs=t,this.rhs=s}addChildren(t,s){void 0!==t&&this.children.p"\
  "ush(t),void 0!==s&&this.children.push(s)}toEsil(){if(void 0=="\
  "=this.lhs||void 0===this.rhs)return\"\";{let t=this.lhs.toEsil("\
  ");return\"\"!==t&&(t+=\",\"),this.rhs.toEsil()+\",\"+t+this.token}}"\
  "toString(){let t=\"\";if(\"\"!==this.token.label&&(t+=this.token."\
  "label+\":\\n\"),this.token.addr,\"\"!==this.token.comment&&(t+=\"/*"\
  "\"+this.token.comment+\"*/\\n\"),\"GOTO\"===this.token.toString()&&"\
  "(0<this.children.length?t+=\"goto label_\"+this.children[0].tok"\
  "en.position+\";\\n\":t+=`goto label_0;\n`),0<this.children.length"\
  "){t+=`  (if (${this.rhs})\n`;for(var s of this.children)null!="\
  "=s&&\"\"!=(s=s.toString())&&(t+=`  ${s}\n`);t+=\"  )\\n\"}return vo"\
  "id 0!==this.lhs&&void 0!==this.rhs?t+`    ( ${this.lhs} ${thi"\
  "s.token} ${this.rhs} )`:t+this.token.toString()}}G.EsilNode=E"\
  "silNode;G.EsilParser=class{constructor(t){this.cur=0,this.r2="\
  "t,this.cur=0,this.stack=[],this.nodes=[],this.tokens=[],this."\
  "root=new EsilNode(new EsilToken(\"function\",0),\"block\")}toJSON"\
  "(){if(0<this.stack.length)throw new Error(\"The ESIL stack is "\
  "not empty\");return JSON.stringify(this.root,null,2)}toEsil(){"\
  "return this.nodes.map(t=>t.toEsil()).join(\",\")}optimizeFlags("\
  "t){void 0!==t.rhs&&this.optimizeFlags(t.rhs),void 0!==t.lhs&&"\
  "this.optimizeFlags(t.lhs);for(let s=0;s<t.children.length;s++"\
  ")this.optimizeFlags(t.children[s]);var s=t.toString();4096<+s"\
  "&&\"\"!=(s=r2.cmd(\"fd.@ \"+s).trim().split(\"\\n\")[0].trim())&&-1="\
  "==s.indexOf(\"+\")&&(t.token.text=s)}optimize(t){-1!=t.indexOf("\
  "\"flag\")&&this.optimizeFlags(this.root)}toString(){return this"\
  ".root.children.map(t=>t.toString()).join(\";\\n\")}reset(){this."\
  "nodes=[],this.stack=[],this.tokens=[],this.cur=0,this.root=ne"\
  "w EsilNode(new EsilToken(\"function\",0),\"block\")}parseRange(t,"\
  "s){let e=t;for(;e<this.tokens.length&&e<s;){const t=this.peek"\
  "(e);if(!t)break;this.cur=e,this.pushToken(t),e=this.cur,e++}}"\
  "parseFunction(t){var s=this;var i=r2.cmd(\"?v $$\").trim(),r=(v"\
  "oid 0===t&&(t=i),r2.cmdj(\"afbj@\"+t));for(let t of r)r2.cmd(\"s"\
  " \"+t.addr),function(t){const e=r2.cmd(\"pie \"+t+\" @e:scr.color"\
  "=0\").trim().split(\"\\n\");for(const t of e)if(0===t.length)cons"\
  "ole.log(\"Empty\");else{const e=t.split(\" \");1<e.length&&(r2.cm"\
  "d(\"s \"+e[0]),s.parse(e[1],e[0]),s.optimize(\"flags,labels\"))}}"\
  "(t.ninstr);r2.cmd(\"s \"+i)}parse(t,s){const e=t.trim().split(\""\
  ",\").map(t=>t.trim()),i=this.tokens.length;for(let t of e){con"\
  "st e=new EsilToken(t,this.tokens.length);void 0!==s&&(e.addr="\
  "s),this.tokens.push(e)}t=this.tokens.length;this.parseRange(i"\
  ",t)}peek(t){return this.tokens[t]}pushToken(t){if(this.isNumb"\
  "er(t)){var s=new EsilNode(t,\"number\");this.stack.push(s),this"\
  ".nodes.push(s)}else if(this.isInternal(t)){const s=new EsilNo"\
  "de(t,\"flag\");this.stack.push(s),this.nodes.push(s)}else if(!t"\
  "his.isOperation(t)){const s=new EsilNode(t,\"register\");this.s"\
  "tack.push(s),this.nodes.push(s)}}isNumber(t){return!!t.toStri"\
  "ng().startsWith(\"0\")||0<+t}isInternal(t){t=t.toString();retur"\
  "n t.startsWith(\"$\")&&1<t.length}parseUntil(t){t+=1;let e=t;co"\
  "nst i=[],r=this.nodes.length;for(this.stack.forEach(t=>i.push"\
  "(t));e<this.tokens.length;){const t=this.peek(e);if(!t)break;"\
  "if(\"}\"===t.toString())break;if(\"}{\"===t.toString())break;e++}"\
  "this.stack=i;var n=e;return this.parseRange(t,n),this.nodes.l"\
  "ength==r?null:this.nodes[this.nodes.length-1]}getNodeFor(t){i"\
  "f(void 0!==this.peek(t)){for(var s of this.nodes)if(s.token.p"\
  "osition===t)return s;this.nodes.push(new EsilNode(new EsilTok"\
  "en(\"label\",t),\"label\"))}return null}findNodeFor(t){for(var s "\
  "of this.nodes)if(s.token.position===t)return s;return null}is"\
  "Operation(t){switch(t.toString()){case\"[1]\":case\"[2]\":case\"[4"\
  "]\":case\"[8]\":if(!(1<=this.stack.length))throw new Error(\"Stac"\
  "k needs more items\");{const t=this.stack.pop();new EsilNode(t"\
  ".token,\"operation\"),this.stack.push(t)}return!0;case\"!\":var s"\
  ",e,i;if(1<=this.stack.length)return s=new EsilNode(new EsilTo"\
  "ken(\"\",t.position),\"none\"),e=this.stack.pop(),(i=new EsilNode"\
  "(t,\"operation\")).setSides(s,e),this.stack.push(i),!0;throw ne"\
  "w Error(\"Stack needs more items\");case\"\":case\"}\":case\"}{\":ret"\
  "urn!0;case\"DUP\":{if(this.stack.length<1)throw new Error(\"goto"\
  " cant pop\");const t=this.stack.pop();this.stack.push(t),this."\
  "stack.push(t)}return!0;case\"GOTO\":if(null!==this.peek(t.posit"\
  "ion-1)){if(this.stack.length<1)throw new Error(\"goto cant pop"\
  "\");const s=this.stack.pop();if(null!==s){const e=0|+s.toStrin"\
  "g();if(0<e){const s=this.peek(e);if(void 0!==s){s.label=\"labe"\
  "l_\"+e,s.comment=\"hehe\";const i=new EsilNode(t,\"goto\"),r=this."\
  "getNodeFor(s.position);null!=r&&i.children.push(r),this.root."\
  "children.push(i)}else console.error(\"Cannot find goto node\")}"\
  "else console.error(\"Cannot find dest node for goto\")}}return!"\
  "0;case\"?{\":if(!(1<=this.stack.length))throw new Error(\"Stack "\
  "needs more items\");{const s=new EsilNode(new EsilToken(\"if\",t"\
  ".position),\"none\"),e=this.stack.pop(),i=new EsilNode(t,\"opera"\
  "tion\");i.setSides(s,e);let r=this.parseUntil(t.position),n=nu"\
  "ll;null!==r&&(i.children.push(r),this.nodes.push(r),null!==(n"\
  "=this.parseUntil(r.token.position+1)))&&(i.children.push(n),t"\
  "his.nodes.push(n)),this.nodes.push(i),this.root.children.push"\
  "(i),null!==n&&(this.cur=n.token.position)}return!0;case\"-\":if"\
  "(!(2<=this.stack.length))throw new Error(\"Stack needs more it"\
  "ems\");{const s=this.stack.pop(),e=this.stack.pop(),i=new Esil"\
  "Node(t,\"operation\");i.setSides(s,e),this.stack.length,this.st"\
  "ack.push(i),this.nodes.push(i)}return!0;case\"<\":case\">\":case\""\
  "^\":case\"&\":case\"|\":case\"+\":case\"*\":case\"/\":case\">>=\":case\"<<="\
  "\":case\">>>=\":case\"<<<=\":case\">>>>=\":case\"<<<<=\":if(!(2<=this."\
  "stack.length))throw new Error(\"Stack needs more items\");{cons"\
  "t s=this.stack.pop(),e=this.stack.pop(),i=new EsilNode(t,\"ope"\
  "ration\");i.setSides(s,e),this.stack.length,this.stack.push(i)"\
  ",this.nodes.push(i)}return!0;case\"=\":case\":=\":case\"-=\":case\"+"\
  "=\":case\"==\":case\"=[1]\":case\"=[2]\":case\"=[4]\":case\"=[8]\":if(!("\
  "2<=this.stack.length))throw new Error(\"Stack needs more items"\
  "\");{const s=this.stack.pop(),e=this.stack.pop(),i=new EsilNod"\
  "e(t,\"operation\");i.setSides(s,e),0===this.stack.length&&this."\
  "root.children.push(i),this.nodes.push(i)}return!0}return!1}};"\
  "\n";
