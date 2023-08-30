static const char *const js_r2papi_qjs = "" \
  "Object.defineProperty(G,\"__esModule\",{value:!0}),G.Base64=G.N"\
  "ativePointer=G.R2Papi=G.Assembler=void 0;var shell_js_1=G;fun"\
  "ction t(t){this.program=\"\",this.labels={},this.endian=!1,this"\
  ".pc=0,this.r2=null,this.r2=void 0===t?G.r2:t,this.program=\"\","\
  "this.labels={}}t.prototype.setProgramCounter=function(t){this"\
  ".pc=t},t.prototype.setEndian=function(t){this.endian=t},t.pro"\
  "totype.toString=function(){return this.program},t.prototype.a"\
  "ppend=function(t){this.pc+=t.length/2,this.program+=t},t.prot"\
  "otype.label=function(t){var n=this.pc;return this.labels[t]=t"\
  "his.pc,n},t.prototype.asm=function(t){t=this.r2.cmd('\"\"pa '+t"\
  ").trim();t.length<16||(t=\"____\"),this.append(t)},G.Assembler="\
  "t;var R2Papi=function(){function t(t){this.r2=t}return t.prot"\
  "otype.getBaseAddress=function(){return new NativePointer(this"\
  ".cmd(\"e bin.baddr\"))},t.prototype.jsonToTypescript=function(t"\
  ",n){var e=\"interface \".concat(t,\" {\\n\");n.length&&0<n.length&"\
  "&(n=n[0]);for(var i=0,o=Object.keys(n);i<o.length;i++){var r="\
  "o[i],s=typeof n[r];e+=\"    \".concat(r,\": \").concat(s,\";\\n\")}r"\
  "eturn\"\".concat(e,\"}\\n\")},t.prototype.setLogLevel=function(t){"\
  "return this.cmd(\"e log.level=\"+t),this},t.prototype.newMap=fu"\
  "nction(t,n,e,i,o,r){void 0===r&&(r=\"\"),this.cmd(\"om \".concat("\
  "t,\" \").concat(n,\" \").concat(e,\" \").concat(i,\" \").concat(o,\" \""\
  ").concat(r))},t.prototype.at=function(t){return new NativePoi"\
  "nter(t)},t.prototype.getShell=function(){return new shell_js_"\
  "1.R2PapiShell(this)},t.prototype.version=function(){return th"\
  "is.r2.cmd(\"?Vq\").trim()},t.prototype.platform=function(){retu"\
  "rn this.r2.cmd(\"uname\").trim()},t.prototype.arch=function(){r"\
  "eturn this.r2.cmd(\"uname -a\").trim()},t.prototype.bits=functi"\
  "on(){return this.r2.cmd(\"uname -b\").trim()},t.prototype.id=fu"\
  "nction(){return+this.r2.cmd(\"?vi:$p\")},t.prototype.printAt=fu"\
  "nction(t,n,e){},t.prototype.clearScreen=function(){return thi"\
  "s.r2.cmd(\"!clear\"),this},t.prototype.getConfig=function(t){re"\
  "turn this.r2.call(\"e \"+t).trim()},t.prototype.setConfig=funct"\
  "ion(t,n){return this.r2.call(\"e \"+t+\"=\"+n),this},t.prototype."\
  "getRegisters=function(){return this.cmdj(\"drj\")},t.prototype."\
  "resizeFile=function(t){return this.cmd(\"r \".concat(t)),this},"\
  "t.prototype.insertNullBytes=function(t,n){return void 0===n&&"\
  "(n=\"$$\"),this.cmd(\"r+\".concat(t,\"@\").concat(n)),this},t.proto"\
  "type.removeBytes=function(t,n){return void 0===n&&(n=\"$$\"),th"\
  "is.cmd(\"r-\".concat(t,\"@\").concat(n)),this},t.prototype.seek=f"\
  "unction(t){return this.cmd(\"s \".concat(t)),this},t.prototype."\
  "currentSeek=function(){return new NativePointer(\"$$\")},t.prot"\
  "otype.seekToRelativeOpcode=function(t){return this.cmd(\"so \"."\
  "concat(t)),this.currentSeek()},t.prototype.getBlockSize=funct"\
  "ion(){return+this.cmd(\"b\")},t.prototype.setBlockSize=function"\
  "(t){return this.cmd(\"b \".concat(t)),this},t.prototype.countFl"\
  "ags=function(){return Number(this.cmd(\"f~?\"))},t.prototype.co"\
  "untFunctions=function(){return Number(this.cmd(\"aflc\"))},t.pr"\
  "ototype.analyzeProgram=function(t){switch(t=void 0===t?0:t){c"\
  "ase 0:this.cmd(\"aa\");break;case 1:this.cmd(\"aaa\");break;case "\
  "2:this.cmd(\"aaaa\");break;case 3:this.cmd(\"aaaaa\")}return this"\
  "},t.prototype.enumerateThreads=function(){return[{context:thi"\
  "s.cmdj(\"drj\"),id:0,state:\"waiting\",selected:!0}]},t.prototype"\
  ".currentThreadId=function(){return+this.cmd(\"e cfg.debug\")?+t"\
  "his.cmd(\"dpt.\"):this.id()},t.prototype.setRegisters=function("\
  "t){for(var n=0,e=Object.keys(t);n<e.length;n++){var i=e[n],o="\
  "t[i];this.r2.cmd(\"dr \"+i+\"=\"+o)}},t.prototype.hex=function(t)"\
  "{return this.r2.cmd(\"?v \"+t).trim()},t.prototype.step=functio"\
  "n(){return this.r2.cmd(\"ds\"),this},t.prototype.stepOver=funct"\
  "ion(){return this.r2.cmd(\"dso\"),this},t.prototype.math=functi"\
  "on(t){return+this.r2.cmd(\"?v \"+t)},t.prototype.stepUntil=func"\
  "tion(t){this.cmd(\"dsu \".concat(t))},t.prototype.enumerateXref"\
  "sTo=function(t){return this.call(\"axtq \"+t).trim().split(/\\n/"\
  ")},t.prototype.findXrefsTo=function(t,n){n?this.call(\"/r \"+t)"\
  ":this.call(\"/re \"+t)},t.prototype.analyzeFunctionsFromCalls=f"\
  "unction(){return this.call(\"aac\"),this},t.prototype.analyzeFu"\
  "nctionsWithPreludes=function(){return this.call(\"aap\"),this},"\
  "t.prototype.analyzeObjCReferences=function(){return this.cmd("\
  "\"aao\"),this},t.prototype.analyzeImports=function(){return thi"\
  "s.cmd(\"af @ sym.imp.*\"),this},t.prototype.searchDisasm=functi"\
  "on(t){return this.callj(\"/ad \"+t)},t.prototype.searchString=f"\
  "unction(t){return this.cmdj(\"/j \"+t)},t.prototype.searchBytes"\
  "=function(t){t=t.map(function(t){return(255&t).toString(16)})"\
  ".join(\"\");return this.cmdj(\"/xj \"+t)},t.prototype.binInfo=fun"\
  "ction(){try{return this.cmdj(\"ij~{bin}\")}catch(t){return{}}},"\
  "t.prototype.selectBinary=function(t){this.call(\"ob \".concat(t"\
  "))},t.prototype.openFile=function(t){this.call(\"o \".concat(t)"\
  ")},t.prototype.currentFile=function(t){return this.call(\"o.\")"\
  ".trim()},t.prototype.enumeratePlugins=function(t){switch(t){c"\
  "ase\"bin\":return this.callj(\"Lij\");case\"io\":return this.callj("\
  "\"Loj\");case\"core\":return this.callj(\"Lcj\");case\"arch\":return "\
  "this.callj(\"LAj\");case\"anal\":return this.callj(\"Laj\");case\"la"\
  "ng\":return this.callj(\"Llj\")}return[]},t.prototype.enumerateM"\
  "odules=function(){return this.callj(\"dmmj\")},t.prototype.enum"\
  "erateFiles=function(){return this.callj(\"oj\")},t.prototype.en"\
  "umerateBinaries=function(){return this.callj(\"obj\")},t.protot"\
  "ype.enumerateMaps=function(){return this.callj(\"omj\")},t.prot"\
  "otype.enumerateSymbols=function(){return this.callj(\"isj\")},t"\
  ".prototype.enumerateExports=function(){return this.callj(\"iEj"\
  "\")},t.prototype.enumerateImports=function(){return this.callj"\
  "(\"iij\")},t.prototype.enumerateLibraries=function(){return thi"\
  "s.callj(\"ilj\")},t.prototype.enumerateSections=function(){retu"\
  "rn this.callj(\"iSj\")},t.prototype.enumerateSegments=function("\
  "){return this.callj(\"iSSj\")},t.prototype.enumerateEntrypoints"\
  "=function(){return this.callj(\"iej\")},t.prototype.enumerateRe"\
  "locations=function(){return this.callj(\"irj\")},t.prototype.en"\
  "umerateFunctions=function(){return this.cmdj(\"aflj\")},t.proto"\
  "type.enumerateFlags=function(){return this.cmdj(\"fj\")},t.prot"\
  "otype.skip=function(){this.r2.cmd(\"dss\")},t.prototype.ptr=fun"\
  "ction(t){return new NativePointer(t,this)},t.prototype.call=f"\
  "unction(t){return this.r2.call(t)},t.prototype.callj=function"\
  "(t){return JSON.parse(this.call(t))},t.prototype.cmd=function"\
  "(t){return this.r2.cmd(t)},t.prototype.cmdj=function(t){retur"\
  "n JSON.parse(this.cmd(t))},t.prototype.log=function(t){return"\
  " this.r2.log(t)},t.prototype.clippy=function(t){this.r2.log(t"\
  "his.r2.cmd(\"?E \"+t))},t.prototype.ascii=function(t){this.r2.l"\
  "og(this.r2.cmd(\"?ea \"+t))},t}(),NativePointer=(G.R2Papi=R2Pap"\
  "i,function(){function t(t,n){this.api=void 0===n?G.R:n,this.a"\
  "ddr=(\"\"+t).trim()}return t.prototype.hexdump=function(t){retu"\
  "rn this.api.cmd(\"x\".concat(void 0===t?\"\":\"\"+t,\"@\").concat(thi"\
  "s.addr))},t.prototype.functionGraph=function(t){return\"dot\"=="\
  "=t?this.api.cmd(\"agfd@ \".concat(this.addr)):\"json\"===t?this.a"\
  "pi.cmd(\"agfj@\".concat(this.addr)):\"mermaid\"===t?this.api.cmd("\
  "\"agfm@\".concat(this.addr)):this.api.cmd(\"agf@\".concat(this.ad"\
  "dr))},t.prototype.readByteArray=function(t){return JSON.parse"\
  "(this.api.cmd(\"p8j \".concat(t,\"@\").concat(this.addr)))},t.pro"\
  "totype.readHexString=function(t){return this.api.cmd(\"p8 \".co"\
  "ncat(t,\"@\").concat(this.addr)).trim()},t.prototype.and=functi"\
  "on(t){return this.addr=this.api.call(\"?v \".concat(this.addr,\""\
  " & \").concat(t)).trim(),this},t.prototype.or=function(t){retu"\
  "rn this.addr=this.api.call(\"?v \".concat(this.addr,\" | \").conc"\
  "at(t)).trim(),this},t.prototype.add=function(t){return this.a"\
  "ddr=this.api.call(\"?v \".concat(this.addr,\"+\").concat(t)).trim"\
  "(),this},t.prototype.sub=function(t){return this.addr=this.ap"\
  "i.call(\"?v \".concat(this.addr,\"-\").concat(t)).trim(),this},t."\
  "prototype.writeByteArray=function(t){return this.api.cmd(\"wx "\
  "\"+t.join(\"\")),this},t.prototype.writeAssembly=function(t){ret"\
  "urn this.api.cmd('\"wa '.concat(t,\" @ \").concat(this.addr)),th"\
  "is},t.prototype.writeCString=function(t){return this.api.call"\
  "(\"w \"+t),this},t.prototype.isNull=function(){return 0==+this."\
  "addr},t.prototype.compare=function(n){return(n=\"string\"!=type"\
  "of n&&\"number\"!=typeof n?n:new t(n)).addr===this.addr},t.prot"\
  "otype.pointsToNull=function(){return this.readPointer().compa"\
  "re(0)},t.prototype.toString=function(){return this.addr.trim("\
  ")},t.prototype.writePointer=function(t){var n=64==+this.api.g"\
  "etConfig(\"asm.bits\")?\"wv8\":\"wv4\";this.api.cmd(\"\".concat(n,\" \""\
  ").concat(t,\"@\").concat(this))},t.prototype.readPointer=functi"\
  "on(){return 64==+this.api.getConfig(\"asm.bits\")?new t(this.ap"\
  "i.call(\"pv8@\"+this.addr)):new t(this.api.call(\"pv4@\"+this.add"\
  "r))},t.prototype.readU8=function(){return+this.api.cmd('pv1@\""\
  "'.concat(this.addr))},t.prototype.readU16=function(){return+t"\
  "his.api.cmd('pv2@\"'.concat(this.addr))},t.prototype.readU32=f"\
  "unction(){return this.api.cmd('pv4@\"'.concat(this.addr))},t.p"\
  "rototype.readU64=function(){return+this.api.cmd('pv8@\"'.conca"\
  "t(this.addr))},t.prototype.writeInt=function(t){return+this.a"\
  "pi.cmd(\"wv4 \".concat(t,\"@\").concat(this.addr))},t.prototype.w"\
  "riteU8=function(t){return this.api.cmd(\"wv1 \".concat(t,\"@\").c"\
  "oncat(this.addr)),!0},t.prototype.writeU16=function(t){return"\
  " this.api.cmd(\"wv2 \".concat(t,\"@\").concat(this.addr)),!0},t.p"\
  "rototype.writeU32=function(t){return this.api.cmd(\"wv4 \".conc"\
  "at(t,\"@\").concat(this.addr)),!0},t.prototype.writeU64=functio"\
  "n(t){return this.api.cmd(\"wv8 \".concat(t,\"@\").concat(this.add"\
  "r)),!0},t.prototype.readInt=function(){return+this.api.cmd('p"\
  "v4@\"'.concat(this.addr))},t.prototype.readCString=function(){"\
  "return JSON.parse(this.api.cmd(\"psj@\".concat(this.addr))).str"\
  "ing},t.prototype.instruction=function(){return this.api.cmdj("\
  "\"aoj@\".concat(this.addr))[0]},t.prototype.disassemble=functio"\
  "n(t){return this.api.cmd(\"pd \".concat(void 0===t?\"\":\"\"+t,\"@\")"\
  ".concat(this.addr))},t.prototype.analyzeFunction=function(){r"\
  "eturn this.api.cmd(\"af@\"+this.addr),this},t.prototype.analyze"\
  "FunctionRecursively=function(){return this.api.cmd(\"afr@\"+thi"\
  "s.addr),this},t.prototype.name=function(){return this.api.cmd"\
  "(\"fd \"+this.addr).trim()},t.prototype.basicBlock=function(){r"\
  "eturn this.api.cmdj(\"abj@\"+this.addr)},t.prototype.functionBa"\
  "sicBlocks=function(){return this.api.cmdj(\"afbj@\"+this.addr)}"\
  ",t.prototype.xrefs=function(){return this.api.cmdj(\"axtj@\"+th"\
  "is.addr)},t}()),R2Papi=(G.NativePointer=NativePointer,functio"\
  "n(){function t(){}return t.encode=function(t){return(0,G.b64)"\
  "(t)},t.decode=function(t){return(0,G.b64)(t,!0)},t}()),R2Papi"\
  "=(G.Base64=R2Papi,Object.defineProperty(G,\"__esModule\",{value"\
  ":!0}),G.R2PapiShell=void 0,function(){function t(t){this.rp=t"\
  "}return t.prototype.mkdir=function(t,n){return!0===n?this.rp."\
  "call(\"mkdir -p \".concat(t)):this.rp.call(\"mkdir \".concat(t)),"\
  "!0},t.prototype.unlink=function(t){return this.rp.call(\"rm \"."\
  "concat(t)),!0},t.prototype.chdir=function(t){return this.rp.c"\
  "all(\"cd \".concat(t)),!0},t.prototype.ls=function(){return thi"\
  "s.rp.call(\"ls -q\").trim().split(\"\\n\")},t.prototype.fileExists"\
  "=function(t){return!1},t.prototype.open=function(t){this.rp.c"\
  "all(\"open \".concat(t))},t.prototype.system=function(t){return"\
  " this.rp.call(\"!\".concat(t)),0},t.prototype.run=function(t){r"\
  "eturn this.rp.call(\"rm \".concat(t)),0},t.prototype.mount=func"\
  "tion(t,n){return this.rp.call(\"m \".concat(t,\" \").concat(n)),!"\
  "0},t.prototype.umount=function(t){this.rp.call(\"m-\".concat(t)"\
  ")},t.prototype.chdir2=function(t){return this.rp.call(\"mdq \"."\
  "concat(t=void 0===t?\"/\":t)),!0},t.prototype.ls2=function(t){r"\
  "eturn this.rp.call(\"mdq \".concat(t=void 0===t?\"/\":t)).trim()."\
  "split(\"\\n\")},t.prototype.enumerateMountpoints=function(){retu"\
  "rn this.rp.cmdj(\"mlj\")},t.prototype.isSymlink=function(t){ret"\
  "urn!1},t.prototype.isDirectory=function(t){return!1},t}());G."\
  "R2PapiShell=R2Papi,Object.defineProperty(G,\"__esModule\",{valu"\
  "e:!0}),G.EsilParser=G.EsilNode=G.EsilToken=void 0;class EsilT"\
  "oken{constructor(t=\"\",n=0){this.label=\"\",this.comment=\"\",this"\
  ".text=\"\",this.addr=\"0\",this.position=0,this.text=t,this.posit"\
  "ion=n}toString(){return this.text}}G.EsilToken=EsilToken;clas"\
  "s EsilNode{constructor(t=new EsilToken,n){this.type=\"none\",th"\
  "is.token=t,this.children=[]}setSides(t,n){this.lhs=t,this.rhs"\
  "=n}addChildren(t,n){void 0!==t&&this.children.push(t),void 0!"\
  "==n&&this.children.push(n)}toEsil(){if(void 0===this.lhs||voi"\
  "d 0===this.rhs)return\"\";{let t=this.lhs.toEsil();return\"\"!==t"\
  "&&(t+=\",\"),this.rhs.toEsil()+\",\"+t+this.token}}toString(){let"\
  " t=\"\";if(\"\"!==this.token.label&&(t+=this.token.label+\":\\n\"),t"\
  "his.token.addr,\"\"!==this.token.comment&&(t+=\"/*\"+this.token.c"\
  "omment+\"*/\\n\"),\"GOTO\"===this.token.toString()&&(0<this.childr"\
  "en.length?t+=\"goto label_\"+this.children[0].token.position+\";"\
  "\\n\":t+=`goto label_0;\n`),0<this.children.length){t+=`  (if ($"\
  "{this.rhs})\n`;for(var n of this.children)null!==n&&\"\"!=(n=n.t"\
  "oString())&&(t+=`  ${n}\n`);t+=\"  )\\n\"}return void 0!==this.lh"\
  "s&&void 0!==this.rhs?t+`    ( ${this.lhs} ${this.token} ${thi"\
  "s.rhs} )`:t+this.token.toString()}}G.EsilNode=EsilNode;G.Esil"\
  "Parser=class{constructor(t){this.cur=0,this.r2=t,this.cur=0,t"\
  "his.stack=[],this.nodes=[],this.tokens=[],this.root=new EsilN"\
  "ode(new EsilToken(\"function\",0),\"block\")}toJSON(){if(0<this.s"\
  "tack.length)throw new Error(\"The ESIL stack is not empty\");re"\
  "turn JSON.stringify(this.root,null,2)}toEsil(){return this.no"\
  "des.map(t=>t.toEsil()).join(\",\")}optimizeFlags(t){void 0!==t."\
  "rhs&&this.optimizeFlags(t.rhs),void 0!==t.lhs&&this.optimizeF"\
  "lags(t.lhs);for(let n=0;n<t.children.length;n++)this.optimize"\
  "Flags(t.children[n]);var n=t.toString();4096<+n&&\"\"!=(n=r2.cm"\
  "d(\"fd.@ \"+n).trim().split(\"\\n\")[0].trim())&&-1===n.indexOf(\"+"\
  "\")&&(t.token.text=n)}optimize(t){-1!=t.indexOf(\"flag\")&&this."\
  "optimizeFlags(this.root)}toString(){return this.root.children"\
  ".map(t=>t.toString()).join(\";\\n\")}reset(){this.nodes=[],this."\
  "stack=[],this.tokens=[],this.cur=0,this.root=new EsilNode(new"\
  " EsilToken(\"function\",0),\"block\")}parseRange(t,n){let e=t;for"\
  "(;e<this.tokens.length&&e<n;){const t=this.peek(e);if(!t)brea"\
  "k;this.cur=e,this.pushToken(t),e=this.cur,e++}}parseFunction("\
  "t){var n=this;var i=r2.cmd(\"?v $$\").trim(),o=(void 0===t&&(t="\
  "i),r2.cmdj(\"afbj@\"+t));for(let t of o)r2.cmd(\"s \"+t.addr),fun"\
  "ction(t){const e=r2.cmd(\"pie \"+t+\" @e:scr.color=0\").trim().sp"\
  "lit(\"\\n\");for(const t of e)if(0===t.length)console.log(\"Empty"\
  "\");else{const e=t.split(\" \");1<e.length&&(r2.cmd(\"s \"+e[0]),n"\
  ".parse(e[1],e[0]),n.optimize(\"flags,labels\"))}}(t.ninstr);r2."\
  "cmd(\"s \"+i)}parse(t,n){const e=t.trim().split(\",\").map(t=>t.t"\
  "rim()),i=this.tokens.length;for(let t of e){const e=new EsilT"\
  "oken(t,this.tokens.length);void 0!==n&&(e.addr=n),this.tokens"\
  ".push(e)}t=this.tokens.length;this.parseRange(i,t)}peek(t){re"\
  "turn this.tokens[t]}pushToken(t){if(this.isNumber(t)){var n=n"\
  "ew EsilNode(t,\"number\");this.stack.push(n),this.nodes.push(n)"\
  "}else if(this.isInternal(t)){const n=new EsilNode(t,\"flag\");t"\
  "his.stack.push(n),this.nodes.push(n)}else if(!this.isOperatio"\
  "n(t)){const n=new EsilNode(t,\"register\");this.stack.push(n),t"\
  "his.nodes.push(n)}}isNumber(t){return!!t.toString().startsWit"\
  "h(\"0\")||0<+t}isInternal(t){t=t.toString();return t.startsWith"\
  "(\"$\")&&1<t.length}parseUntil(t){t+=1;let e=t;const i=[],o=thi"\
  "s.nodes.length;for(this.stack.forEach(t=>i.push(t));e<this.to"\
  "kens.length;){const t=this.peek(e);if(!t)break;if(\"}\"===t.toS"\
  "tring())break;if(\"}{\"===t.toString())break;e++}this.stack=i;v"\
  "ar r=e;return this.parseRange(t,r),this.nodes.length==o?null:"\
  "this.nodes[this.nodes.length-1]}getNodeFor(t){if(void 0!==thi"\
  "s.peek(t)){for(var n of this.nodes)if(n.token.position===t)re"\
  "turn n;this.nodes.push(new EsilNode(new EsilToken(\"label\",t),"\
  "\"label\"))}return null}findNodeFor(t){for(var n of this.nodes)"\
  "if(n.token.position===t)return n;return null}isOperation(t){s"\
  "witch(t.toString()){case\"[1]\":case\"[2]\":case\"[4]\":case\"[8]\":i"\
  "f(!(1<=this.stack.length))throw new Error(\"Stack needs more i"\
  "tems\");{const t=this.stack.pop();new EsilNode(t.token,\"operat"\
  "ion\"),this.stack.push(t)}return!0;case\"!\":var n,e,i;if(1<=thi"\
  "s.stack.length)return n=new EsilNode(new EsilToken(\"\",t.posit"\
  "ion),\"none\"),e=this.stack.pop(),(i=new EsilNode(t,\"operation\""\
  ")).setSides(n,e),this.stack.push(i),!0;throw new Error(\"Stack"\
  " needs more items\");case\"\":case\"}\":case\"}{\":return!0;case\"DUP"\
  "\":{if(this.stack.length<1)throw new Error(\"goto cant pop\");co"\
  "nst t=this.stack.pop();this.stack.push(t),this.stack.push(t)}"\
  "return!0;case\"GOTO\":if(null!==this.peek(t.position-1)){if(thi"\
  "s.stack.length<1)throw new Error(\"goto cant pop\");const n=thi"\
  "s.stack.pop();if(null!==n){const e=0|+n.toString();if(0<e){co"\
  "nst n=this.peek(e);if(void 0!==n){n.label=\"label_\"+e,n.commen"\
  "t=\"hehe\";const i=new EsilNode(t,\"goto\"),o=this.getNodeFor(n.p"\
  "osition);null!=o&&i.children.push(o),this.root.children.push("\
  "i)}else console.error(\"Cannot find goto node\")}else console.e"\
  "rror(\"Cannot find dest node for goto\")}}return!0;case\"?{\":if("\
  "!(1<=this.stack.length))throw new Error(\"Stack needs more ite"\
  "ms\");{const n=new EsilNode(new EsilToken(\"if\",t.position),\"no"\
  "ne\"),e=this.stack.pop(),i=new EsilNode(t,\"operation\");i.setSi"\
  "des(n,e);let o=this.parseUntil(t.position),r=null;null!==o&&("\
  "i.children.push(o),this.nodes.push(o),null!==(r=this.parseUnt"\
  "il(o.token.position+1)))&&(i.children.push(r),this.nodes.push"\
  "(r)),this.nodes.push(i),this.root.children.push(i),null!==r&&"\
  "(this.cur=r.token.position)}return!0;case\"-\":if(!(2<=this.sta"\
  "ck.length))throw new Error(\"Stack needs more items\");{const n"\
  "=this.stack.pop(),e=this.stack.pop(),i=new EsilNode(t,\"operat"\
  "ion\");i.setSides(n,e),this.stack.length,this.stack.push(i),th"\
  "is.nodes.push(i)}return!0;case\"<\":case\">\":case\"^\":case\"&\":cas"\
  "e\"|\":case\"+\":case\"*\":case\"/\":case\">>=\":case\"<<=\":case\">>>=\":c"\
  "ase\"<<<=\":case\">>>>=\":case\"<<<<=\":if(!(2<=this.stack.length))"\
  "throw new Error(\"Stack needs more items\");{const n=this.stack"\
  ".pop(),e=this.stack.pop(),i=new EsilNode(t,\"operation\");i.set"\
  "Sides(n,e),this.stack.length,this.stack.push(i),this.nodes.pu"\
  "sh(i)}return!0;case\"=\":case\":=\":case\"-=\":case\"+=\":case\"==\":ca"\
  "se\"=[1]\":case\"=[2]\":case\"=[4]\":case\"=[8]\":if(!(2<=this.stack."\
  "length))throw new Error(\"Stack needs more items\");{const n=th"\
  "is.stack.pop(),e=this.stack.pop(),i=new EsilNode(t,\"operation"\
  "\");i.setSides(n,e),0===this.stack.length&&this.root.children."\
  "push(i),this.nodes.push(i)}return!0}return!1}};\n";
