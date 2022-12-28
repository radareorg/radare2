static const char *const js_r2papi_qjs = "" \
  "Object.defineProperty(G,\"__esModule\",{value:!0}),G.Base64=G.N"\
  "ativePointer=G.R2Papi=void 0;const shell_js_1=G;G.R2Papi=clas"\
  "s{constructor(t){this.r2=t}getShell(){return new shell_js_1.R"\
  "2PapiShell(this)}printAt(t,s,i){}clearScreen(){this.r2.cmd(\"!"\
  "clear\")}getConfig(t){return this.r2.call(\"e \"+t).trim()}setCo"\
  "nfig(t,s){this.r2.call(\"e \"+t+\"=\"+s)}getRegisters(){return th"\
  "is.cmdj(\"drj\")}enumerateThreads(){return[{context:this.cmdj(\""\
  "drj\"),id:0,state:\"waiting\",selected:!0}]}setRegisters(t){for("\
  "var s of Object.keys(t)){var i=t[s];this.r2.cmd(\"dr \"+s+\"=\"+i"\
  ")}}analyzeProgram(){this.r2.cmd(\"aa\")}hex(t){return this.r2.c"\
  "md(\"?v \"+t).trim()}step(){return this.r2.cmd(\"ds\"),this}funct"\
  "ionGraph(t){return\"dot\"===t?this.r2.cmd(\"agfd\"):\"json\"===t?th"\
  "is.r2.cmd(\"agfj\"):\"mermaid\"===t?this.r2.cmd(\"agfm\"):this.r2.c"\
  "md(\"agf\")}stepOver(){return this.r2.cmd(\"dso\"),this}math(t){r"\
  "eturn+this.r2.cmd(\"?v \"+t)}searchString(t){return this.cmdj(\""\
  "/j \"+t)}searchBytes(t){t=t.map(function(t){return(255&t).toSt"\
  "ring(16)}).join(\"\");return this.cmdj(\"/xj \"+t)}binInfo(){try{"\
  "return this.cmdj(\"ij~{bin}\")}catch(t){return{}}}enumerateModu"\
  "les(){return this.callj(\"dmmj\")}enumerateSymbols(){return thi"\
  "s.callj(\"isj\")}enumerateImports(){return this.callj(\"iij\")}en"\
  "umerateLibraries(){return this.callj(\"ilj\")}skip(){this.r2.cm"\
  "d(\"dss\")}ptr(t){return new NativePointer(t,this)}call(t){retu"\
  "rn this.r2.call(t)}callj(t){return JSON.parse(this.call(t))}c"\
  "md(t){return this.r2.cmd(t)}cmdj(t){return JSON.parse(this.cm"\
  "d(t))}log(t){return this.r2.log(t)}clippy(t){this.r2.log(this"\
  ".r2.cmd(\"?E \"+t))}ascii(t){this.r2.log(this.r2.cmd(\"?ea \"+t))"\
  "}enumerateFunctions(){return this.cmdj(\"aflj\")}enumerateFlags"\
  "(){return this.cmdj(\"fj\")}};class NativePointer{constructor(t"\
  ",s){this.api=void 0===s?G.R:s,this.addr=(\"\"+t).trim()}readByt"\
  "eArray(t){return JSON.parse(this.api.cmd(`p8j ${t}@`+this.add"\
  "r))}and(t){return this.addr=this.api.call(`?v ${this.addr} & "\
  "`+t).trim(),this}or(t){return this.addr=this.api.call(`?v ${t"\
  "his.addr} | `+t).trim(),this}add(t){return this.addr=this.api"\
  ".call(`?v ${this.addr}+`+t).trim(),this}sub(t){return this.ad"\
  "dr=this.api.call(`?v ${this.addr}-`+t).trim(),this}writeByteA"\
  "rray(t){return this.api.cmd(\"wx \"+t.join(\"\")),this}writeAssem"\
  "bly(t){return this.api.cmd(`\"wa ${t} @ `+this.addr),this}writ"\
  "eCString(t){return this.api.cmd('\"w '+t+'\"'),this}isNull(){re"\
  "turn 0==+this.addr}compare(t){return(t=\"string\"!=typeof t&&\"n"\
  "umber\"!=typeof t?t:new NativePointer(t)).addr===this.addr}poi"\
  "ntsToNull(){return this.readPointer().compare(0)}toString(){r"\
  "eturn this.addr.trim()}writePointer(t){var s=64==+this.api.ge"\
  "tConfig(\"asm.bits\")?\"wv8\":\"wv4\";this.api.cmd(s+` ${t}@`+this)"\
  "}readPointer(){return 64==+this.api.getConfig(\"asm.bits\")?new"\
  " NativePointer(this.api.call(\"pv8@\"+this.addr)):new NativePoi"\
  "nter(this.api.call(\"pv4@\"+this.addr))}readU8(){return+this.ap"\
  "i.cmd('pv1@\"'+this.addr)}readU16(){return+this.api.cmd('pv2@\""\
  "'+this.addr)}readU32(){return+this.api.cmd('pv4@\"'+this.addr)"\
  "}readU64(){return+this.api.cmd('pv8@\"'+this.addr)}writeInt(t)"\
  "{return+this.api.cmd(`wv4 ${t}@`+this.addr)}writeU8(t){return"\
  " this.api.cmd(`wv1 ${t}@`+this.addr),!0}writeU16(t){return th"\
  "is.api.cmd(`wv2 ${t}@`+this.addr),!0}writeU32(t){return this."\
  "api.cmd(`wv4 ${t}@`+this.addr),!0}writeU64(t){return this.api"\
  ".cmd(`wv8 ${t}@`+this.addr),!0}readInt(){return+this.api.cmd("\
  "'pv4@\"'+this.addr)}readCString(){return JSON.parse(this.api.c"\
  "md(\"psj@\"+this.addr)).string}instruction(){return this.api.cm"\
  "dj(\"aoj@\"+this.addr)[0]}analyzeFunction(){this.api.cmd(\"af@\"+"\
  "this.addr)}name(){return this.api.cmd(\"fd \"+this.addr).trim()"\
  "}basicBlock(){return this.api.cmdj(\"abj@\"+this.addr)}function"\
  "BasicBlocks(){return this.api.cmdj(\"afbj@\"+this.addr)}xrefs()"\
  "{return this.api.cmdj(\"axtj@\"+this.addr)}}G.NativePointer=Nat"\
  "ivePointer;G.Base64=class{static encode(t){return(0,G.b64)(t)"\
  "}static decode(t){return(0,G.b64)(t,!0)}},Object.defineProper"\
  "ty(G,\"__esModule\",{value:!0}),G.R2PapiShell=void 0;G.R2PapiSh"\
  "ell=class{constructor(t){this.rp=t}mkdir(t,s){return!0===s?th"\
  "is.rp.call(\"mkdir -p \"+t):this.rp.call(\"mkdir \"+t),!0}unlink("\
  "t){return this.rp.call(\"rm \"+t),!0}chdir(t){return this.rp.ca"\
  "ll(\"cd \"+t),!0}ls(){return this.rp.call(\"ls -q\").trim().split"\
  "(\"\\n\")}fileExists(t){return!1}open(t){this.rp.call(\"open \"+t)"\
  "}system(t){return this.rp.call(\"!\"+t),0}run(t){return this.rp"\
  ".call(\"rm \"+t),0}mount(t,s){return this.rp.call(`m ${t} `+s),"\
  "!0}umount(t){this.rp.call(\"m-\"+t)}chdir2(t){return this.rp.ca"\
  "ll(\"mdq \"+(t=void 0===t?\"/\":t)),!0}ls2(t){return this.rp.call"\
  "(\"mdq \"+(t=void 0===t?\"/\":t)).trim().split(\"\\n\")}enumerateMou"\
  "ntpoints(){return this.rp.cmdj(\"mlj\")}isSymlink(t){return!1}i"\
  "sDirectory(t){return!1}},Object.defineProperty(G,\"__esModule\""\
  ",{value:!0}),G.EsilParser=G.EsilNode=G.EsilToken=void 0;class"\
  " EsilToken{constructor(t,s){this.label=\"\",this.comment=\"\",thi"\
  "s.text=\"\",this.addr=\"0\",this.position=0,this.text=t,this.posi"\
  "tion=s}toString(){return this.text}}G.EsilToken=EsilToken;cla"\
  "ss EsilNode{constructor(t,s){this.token=t,this.type=s,this.ch"\
  "ildren=[]}setSides(t,s){this.lhs=t,this.rhs=s}addChildren(t,s"\
  "){void 0!==t&&this.children.push(t),void 0!==s&&this.children"\
  ".push(s)}toEsil(){if(void 0===this.lhs||void 0===this.rhs)ret"\
  "urn this.token.text;{let t=this.lhs.toEsil();return\"\"!==t&&(t"\
  "+=\",\"),this.rhs.toEsil()+\",\"+t+this.token}}toString(){let t=\""\
  "\";if(\"\"!==this.token.label&&(t+=this.token.label+\":\\n\"),this."\
  "token.addr,\"\"!==this.token.comment&&(t+=\"/*\"+this.token.comme"\
  "nt+\"*/\\n\"),\"GOTO\"===this.token.toString()&&(0<this.children.l"\
  "ength?t+=\"goto label_\"+this.children[0].token.position+\";\\n\":"\
  "t+=`goto label_0;\n`),0<this.children.length){t+=`  (if (${thi"\
  "s.rhs})\n`;for(var s of this.children)null!==s&&\"\"!=(s=s.toStr"\
  "ing())&&(t+=`  ${s}\n`);t+=\"  )\\n\"}return void 0!==this.lhs&&v"\
  "oid 0!==this.rhs?t+`    ( ${this.lhs} ${this.token} ${this.rh"\
  "s} )`:t+this.token.toString()}}G.EsilNode=EsilNode;G.EsilPars"\
  "er=class{constructor(t){this.cur=0,this.r2=t,this.cur=0,this."\
  "stack=[],this.nodes=[],this.tokens=[],this.root=new EsilNode("\
  "new EsilToken(\"function\",0),\"block\")}toJSON(){if(0<this.stack"\
  ".length)throw new Error(\"The ESIL stack is not empty\");return"\
  " JSON.stringify(this.root,null,2)}toEsil(){return this.nodes."\
  "map(t=>t.toEsil()).join(\",\")}optimizeFlags(t){void 0!==t.rhs&"\
  "&this.optimizeFlags(t.rhs),void 0!==t.lhs&&this.optimizeFlags"\
  "(t.lhs);for(let s=0;s<t.children.length;s++)this.optimizeFlag"\
  "s(t.children[s]);var s=t.toString();4096<+s&&\"\"!=(s=r2.cmd(\"f"\
  "d.@ \"+s).trim().split(\"\\n\")[0].trim())&&-1===s.indexOf(\"+\")&&"\
  "(t.token.text=s)}optimize(t){-1!=t.indexOf(\"flag\")&&this.opti"\
  "mizeFlags(this.root)}toString(){return this.root.children.map"\
  "(t=>t.toString()).join(\";\\n\")}reset(){this.nodes=[],this.stac"\
  "k=[],this.tokens=[],this.cur=0,this.root=new EsilNode(new Esi"\
  "lToken(\"function\",0),\"block\")}parseRange(t,s){let i=t;for(;i<"\
  "this.tokens.length&&i<s;){const t=this.peek(i);if(!t)break;th"\
  "is.cur=i,this.pushToken(t),i=this.cur,i++}}parse(t,s){const i"\
  "=t.trim().split(\",\").map(t=>t.trim()),e=this.tokens.length;fo"\
  "r(let t of i){const i=new EsilToken(t,this.tokens.length);voi"\
  "d 0!==s&&(i.addr=s),this.tokens.push(i)}t=this.tokens.length;"\
  "this.parseRange(e,t)}peek(t){return this.tokens[t]}pushToken("\
  "t){if(this.isNumber(t)){var s=new EsilNode(t,\"number\");this.s"\
  "tack.push(s),this.nodes.push(s)}else if(this.isInternal(t)){c"\
  "onst s=new EsilNode(t,\"flag\");this.stack.push(s),this.nodes.p"\
  "ush(s)}else if(!this.isOperation(t)){const s=new EsilNode(t,\""\
  "register\");this.stack.push(s),this.nodes.push(s)}}isNumber(t)"\
  "{return!!t.toString().startsWith(\"0\")||0<+t}isInternal(t){t=t"\
  ".toString();return t&&t.startsWith(\"$\")&&1<t.length}parseUnti"\
  "l(t){t+=1;let i=t;const e=[],r=this.nodes.length;for(this.sta"\
  "ck.forEach(t=>e.push(t));i<this.tokens.length;){const t=this."\
  "peek(i);if(!t)break;if(\"}\"===t.toString())break;if(\"}{\"===t.t"\
  "oString())break;i++}this.stack=e;var n=i;return this.parseRan"\
  "ge(t,n),this.nodes.length==r?null:this.nodes[this.nodes.lengt"\
  "h-1]}getNodeFor(t){if(void 0!==this.peek(t)){for(var s of thi"\
  "s.nodes)if(s.token.position===t)return s;this.nodes.push(new "\
  "EsilNode(new EsilToken(\"label\",t),\"label\"))}return null}findN"\
  "odeFor(t){for(var s of this.nodes)if(s.token.position===t)ret"\
  "urn s;return null}isOperation(t){switch(t.toString()){case\"[1"\
  "]\":case\"[2]\":case\"[4]\":case\"[8]\":if(!(1<=this.stack.length))t"\
  "hrow new Error(\"Stack needs more items\");{const t=this.stack."\
  "pop();new EsilNode(t.token,\"operation\"),this.stack.push(t)}re"\
  "turn!0;case\"!\":var s,i,e;if(1<=this.stack.length)return s=new"\
  " EsilNode(new EsilToken(\"\",t.position),\"none\"),i=this.stack.p"\
  "op(),(e=new EsilNode(t,\"operation\")).setSides(s,i),this.stack"\
  ".push(e),!0;throw new Error(\"Stack needs more items\");case\"\":"\
  "case\"}\":case\"}{\":return!0;case\"DUP\":{if(this.stack.length<1)t"\
  "hrow new Error(\"goto cant pop\");const t=this.stack.pop();this"\
  ".stack.push(t),this.stack.push(t)}return!0;case\"GOTO\":if(null"\
  "!==this.peek(t.position-1)){if(this.stack.length<1)throw new "\
  "Error(\"goto cant pop\");const s=this.stack.pop();if(null!==s){"\
  "const i=0|+s.toString();if(0<i){const s=this.peek(i);if(null!"\
  "==s){s.label=\"label_\"+i,s.comment=\"hehe\";const e=new EsilNode"\
  "(t,\"goto\"),r=this.getNodeFor(s.position);null!=r&&e.children."\
  "push(r),this.root.children.push(e)}else console.error(\"Cannot"\
  " find goto node\")}else console.error(\"Cannot find dest node f"\
  "or goto\")}}return!0;case\"?{\":if(!(1<=this.stack.length))throw"\
  " new Error(\"Stack needs more items\");{const s=new EsilNode(ne"\
  "w EsilToken(\"if\",t.position),\"none\"),i=this.stack.pop(),e=new"\
  " EsilNode(t,\"operation\");e.setSides(s,i);let r=this.parseUnti"\
  "l(t.position),n=null;null!==r&&(e.children.push(r),this.nodes"\
  ".push(r),null!==(n=this.parseUntil(r.token.position+1)))&&(e."\
  "children.push(n),this.nodes.push(n)),this.nodes.push(e),this."\
  "root.children.push(e),null!==n&&(this.cur=n.token.position)}r"\
  "eturn!0;case\"-\":if(!(2<=this.stack.length))throw new Error(\"S"\
  "tack needs more items\");{const s=this.stack.pop(),i=this.stac"\
  "k.pop(),e=new EsilNode(t,\"operation\");e.setSides(s,i),this.st"\
  "ack.length,this.stack.push(e),this.nodes.push(e)}return!0;cas"\
  "e\"<\":case\">\":case\"^\":case\"&\":case\"|\":case\"+\":case\"*\":case\"/\":"\
  "case\">>=\":case\"<<=\":case\">>>=\":case\"<<<=\":case\">>>>=\":case\"<<"\
  "<<=\":if(!(2<=this.stack.length))throw new Error(\"Stack needs "\
  "more items\");{const s=this.stack.pop(),i=this.stack.pop(),e=n"\
  "ew EsilNode(t,\"operation\");e.setSides(s,i),this.stack.length,"\
  "this.stack.push(e),this.nodes.push(e)}return!0;case\"=\":case\":"\
  "=\":case\"-=\":case\"+=\":case\"==\":case\"=[1]\":case\"=[2]\":case\"=[4]"\
  "\":case\"=[8]\":if(!(2<=this.stack.length))throw new Error(\"Stac"\
  "k needs more items\");{const s=this.stack.pop(),i=this.stack.p"\
  "op(),e=new EsilNode(t,\"operation\");e.setSides(s,i),0===this.s"\
  "tack.length&&this.root.children.push(e),this.nodes.push(e)}re"\
  "turn!0}return!1}};\n";
