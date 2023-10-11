static const char *const js_r2papi_qjs = "" \
  "var a=a=>typeof a=='number',b=a=>typeof a=='string',{keys:c,d"\
  "efineProperty:d}=Object,e=a=>typeof a=='undefined',f=G;d(G,'_"\
  "_esModule',{value:!0});G.Base64=G.NativePointer=G.R2Papi=G.As"\
  "sembler=void 0;;;;;;;;;class Assembler{constructor(A){this.pr"\
  "ogram='';this.labels={};this.endian=!1;this.pc=0;this.r2=null"\
  ";this.r2=e(A)?G.r2:A;this.program='';this.labels={}}setProgra"\
  "mCounter(A){this.pc=A}setEndian(A){this.endian=A}toString(){r"\
  "eturn this.program}append(x){this.pc+=x.length/2;this.program"\
  "+=x}label(s){var A=this.pc;this.labels[s]=this.pc;return A}as"\
  "m(s){let A=this.r2.cmd(`\"\"pa ${s}`).trim();!A.length<16&&(A='"\
  "____');this.append(A)}}G.Assembler=Assembler;class R2Papi{con"\
  "structor(A){this.r2=A}getBaseAddress(){return new NativePoint"\
  "er(this.cmd('e bin.baddr'))}jsonToTypescript(A,a){let _=`inte"\
  "rface ${A} {\\n`;a.length&&a.length>0&&(a=a[0]);for(let k of c"\
  "(a)){var B=typeof a[k],C=k;_+=`    ${C}: ${B};\\n`}return`${_}"\
  "}\\n`}getBits(){return this.cmd('-b')}getArch(){return this.cm"\
  "d('-a')}getCpu(){return this.cmd('-e asm.cpu')}setArch(A,_){t"\
  "his.cmd(`-a ${A}`);_!==void 0&&this.cmd(`-b ${_}`)}setFlagSpa"\
  "ce(A){this.cmd(`fs ${A}`)}setLogLevel(A){this.cmd(`e log.leve"\
  "l=${A}`);return this}newMap(A,_,B,D,E,F=''){this.cmd(`om ${A}"\
  " ${_} ${B} ${D} ${E} ${F}`)}at(a){return new NativePointer(a)"\
  "}getShell(){return new f.R2PapiShell(this)}version(){return t"\
  "his.r2.cmd('?Vq').trim()}platform(){return this.r2.cmd('uname"\
  "').trim()}arch(){return this.r2.cmd('uname -a').trim()}bits()"\
  "{return this.r2.cmd('uname -b').trim()}id(){return +this.r2.c"\
  "md('?vi:$p')}printAt(){}clearScreen(){this.r2.cmd('!clear');r"\
  "eturn this}getConfig(A){if(A=='')throw Error('Invalid key');r"\
  "eturn this.r2.call(`e ${A}`).trim()}setConfig(A,_){this.r2.ca"\
  "ll('e '+A+'='+_);return this}getRegisterStateForEsil(){return"\
  " this.cmdj('dre').trim()}getRegisters(){return this.cmdj('drj"\
  "')}resizeFile(A){this.cmd(`r ${A}`);return this}insertNullByt"\
  "es(A,_){_==void 0&&(_='$$');this.cmd(`r+${A}@${_}`);return th"\
  "is}removeBytes(A,_){_==void 0&&(_='$$');this.cmd(`r-${A}@${_}"\
  "`);return this}seek(A){this.cmd(`s ${A}`);return this}current"\
  "Seek(){return new NativePointer('$$')}seekToRelativeOpcode(A)"\
  "{this.cmd(`so ${A}`);return this.currentSeek()}getBlockSize()"\
  "{return +this.cmd('b')}setBlockSize(a){this.cmd(`b ${a}`);ret"\
  "urn this}countFlags(){return +this.cmd('f~?')}countFunctions("\
  "){return +this.cmd('aflc')}analyzeFunctionsWithEsil(){this.cm"\
  "d('aaef')}analyzeProgramWithEsil(){this.cmd('aae')}analyzePro"\
  "gram(A){A==void 0&&(A=0);switch(A) {case 0:this.cmd('aa');bre"\
  "ak;case 1:this.cmd('aaa');break;case 2:this.cmd('aaaa');break"\
  ";case 3:this.cmd('aaaaa');break}return this}enumerateThreads("\
  "){var A=this.cmdj('drj'),_={context:A,id:0,state:'waiting',se"\
  "lected:!0};return[_]}currentThreadId(){if(+this.cmd('e cfg.de"\
  "bug'))return +this.cmd('dpt.');return this.id()}setRegisters("\
  "A){for(let r of c(A)){var v=A[r];this.r2.cmd('dr '+r+'='+v)}}"\
  "hex(s){return this.r2.cmd(`?v ${s}`).trim()}step(){this.r2.cm"\
  "d('ds');return this}stepOver(){this.r2.cmd('dso');return this"\
  "}math(A){return +this.r2.cmd(`?v ${A}`)}stepUntil(A){this.cmd"\
  "(`dsu ${A}`)}enumerateXrefsTo(s){return this.call(`axtq ${s}`"\
  ").trim().split(/\\n/)}findXrefsTo(s,A){A?this.call(`/r ${s}`):"\
  "this.call(`/re ${s}`)}analyzeFunctionsFromCalls(){this.call('"\
  "aac');return this}analyzeFunctionsWithPreludes(){this.call('a"\
  "ap');return this}analyzeObjCReferences(){this.cmd('aao');retu"\
  "rn this}analyzeImports(){this.cmd('af @ sym.imp.*');return th"\
  "is}searchDisasm(s){return this.callj(`/ad ${s}`)}searchString"\
  "(s){return this.cmdj(`/j ${s}`)}searchBytes(A){function _(B){"\
  "return (B&0xff).toString(16)}var s=A.map(_).join('');return t"\
  "his.cmdj(`/xj ${s}`)}binInfo(){try {return this.cmdj('ij~{bin"\
  "}')} catch {return{}}}selectBinary(A){this.call(`ob ${A}`)}op"\
  "enFile(A){var _=this.call('oqq').trim(),B=this.call('oqq').tr"\
  "im();this.call(`o ${A}`);if(_==B)return Error('Cannot open fi"\
  "le');return parseInt(B)}currentFile(){return this.call('o.')."\
  "trim()}enumeratePlugins(A){switch(A) {case 'bin':return this."\
  "callj('Lij');case 'io':return this.callj('Loj');case 'core':r"\
  "eturn this.callj('Lcj');case 'arch':return this.callj('LAj');"\
  "case 'anal':return this.callj('Laj');case 'lang':return this."\
  "callj('Llj')}return[]}enumerateModules(){return this.callj('d"\
  "mmj')}enumerateFiles(){return this.callj('oj')}enumerateBinar"\
  "ies(){return this.callj('obj')}enumerateMaps(){return this.ca"\
  "llj('omj')}enumerateClasses(){return this.callj('icj')}enumer"\
  "ateSymbols(){return this.callj('isj')}enumerateExports(){retu"\
  "rn this.callj('iEj')}enumerateImports(){return this.callj('ii"\
  "j')}enumerateLibraries(){return this.callj('ilj')}enumerateSe"\
  "ctions(){return this.callj('iSj')}enumerateSegments(){return "\
  "this.callj('iSSj')}enumerateEntrypoints(){return this.callj('"\
  "iej')}enumerateRelocations(){return this.callj('irj')}enumera"\
  "teFunctions(){return this.cmdj('aflj')}enumerateFlags(){retur"\
  "n this.cmdj('fj')}skip(){this.r2.cmd('dss')}ptr(s){return new"\
  " NativePointer(s, this)}call(s){return this.r2.call(s)}callj("\
  "s){return JSON.parse(this.call(s))}cmd(s){return this.r2.cmd("\
  "s)}cmdj(s){return JSON.parse(this.cmd(s))}log(s){return this."\
  "r2.log(s)}clippy(A){this.r2.log(this.r2.cmd(`?E ${A}`))}ascii"\
  "(A){this.r2.log(this.r2.cmd(`?ea ${A}`))}}G.R2Papi=R2Papi;cla"\
  "ss NativePointer{constructor(s,A){A==void 0?this.api=G.R:this"\
  ".api=A;this.addr=`${s}`.trim()}setFlag(A){this.api.call(`f ${"\
  "A}=${this.addr}`)}unsetFlag(){this.api.call(`f-${this.addr}`)"\
  "}hexdump(A){let _=A==void 0?'':`${A}`;return this.api.cmd(`x$"\
  "{_}@${this.addr}`)}functionGraph(A){if(A=='dot')return this.a"\
  "pi.cmd(`agfd@ ${this.addr}`);if(A=='json')return this.api.cmd"\
  "(`agfj@${this.addr}`);if(A=='mermaid')return this.api.cmd(`ag"\
  "fm@${this.addr}`);return this.api.cmd(`agf@${this.addr}`)}rea"\
  "dByteArray(A){return JSON.parse(this.api.cmd(`p8j ${A}@${this"\
  ".addr}`))}readHexString(A){return this.api.cmd(`p8 ${A}@${thi"\
  "s.addr}`).trim()}and(a){var A=this.api.call(`?v ${this.addr} "\
  "& ${a}`).trim();return new NativePointer(A)}or(a){var A=this."\
  "api.call(`?v ${this.addr} | ${a}`).trim();return new NativePo"\
  "inter(A)}add(a){var A=this.api.call(`?v ${this.addr}+${a}`).t"\
  "rim();return new NativePointer(A)}sub(a){var A=this.api.call("\
  "`?v ${this.addr}-${a}`).trim();return new NativePointer(A)}wr"\
  "iteByteArray(A){this.api.cmd('wx '+A.join(''));return this}wr"\
  "iteAssembly(A){this.api.cmd(`wa ${A} @ ${this.addr}`);return "\
  "this}writeCString(s){this.api.call(`w ${s}`);return this}writ"\
  "eWideString(s){this.api.call(`ww ${s}`);return this}asNumber("\
  "){return parseInt(this.api.call('?vi '+this.addr))}isNull(){r"\
  "eturn!this.asNumber()}compare(a){b(a)||a(a)&&(a=new NativePoi"\
  "nter(a));return a.addr==this.addr||new NativePointer(a.addr)."\
  "asNumber()==this.asNumber()}pointsToNull(){return this.readPo"\
  "inter().compare(0)}toString(){return this.addr.trim()}writePo"\
  "inter(p){this.api.cmd(`wvp ${p}@${this}`)}readPointer(){retur"\
  "n new NativePointer(this.api.call('pvp@'+this.addr))}readU8()"\
  "{return parseInt(this.api.cmd(`pv1d@${this.addr}`))}readU16()"\
  "{return parseInt(this.api.cmd(`pv2d@${this.addr}`))}readU16le"\
  "(){return parseInt(this.api.cmd(`pv2d@${this.addr}@e:cfg.bige"\
  "ndian=false`))}readU16be(){return parseInt(this.api.cmd(`pv2d"\
  "@${this.addr}@e:cfg.bigendian=true`))}readS16(){return parseI"\
  "nt(this.api.cmd(`pv2d@${this.addr}`))}readS16le(){return pars"\
  "eInt(this.api.cmd(`pv2d@${this.addr}@e:cfg.bigendian=false`))"\
  "}readS16be(){return parseInt(this.api.cmd(`pv2d@${this.addr}@"\
  "e:cfg.bigendian=true`))}readS32(){return parseInt(this.api.cm"\
  "d(`pv4d@${this.addr}`))}readU32(){return parseInt(this.api.cm"\
  "d(`pv4u@${this.addr}`))}readU32le(){return parseInt(this.api."\
  "cmd(`pv4u@${this.addr}@e:cfg.bigendian=false`))}readU32be(){r"\
  "eturn parseInt(this.api.cmd(`pv4u@${this.addr}@e:cfg.bigendia"\
  "n=true`))}readU64(){return parseInt(this.api.cmd(`pv8u@${this"\
  ".addr}`))}readU64le(){return parseInt(this.api.cmd(`pv8u@${th"\
  "is.addr}@e:cfg.bigendian=false`))}readU64be(){return parseInt"\
  "(this.api.cmd(`pv8u@${this.addr}@e:cfg.bigendian=true`))}writ"\
  "eInt(n){return this.writeU32(n)}writeU8(n){this.api.cmd(`wv1 "\
  "${n}@${this.addr}`);return!0}writeU16(n){this.api.cmd(`wv2 ${"\
  "n}@${this.addr}`);return!0}writeU16be(n){this.api.cmd(`wv2 ${"\
  "n}@${this.addr}@e:cfg.bigendian=true`);return!0}writeU16le(n)"\
  "{this.api.cmd(`wv2 ${n}@${this.addr}@e:cfg.bigendian=false`);"\
  "return!0}writeU32(n){this.api.cmd(`wv4 ${n}@${this.addr}`);re"\
  "turn!0}writeU32be(n){this.api.cmd(`wv4 ${n}@${this.addr}@e:cf"\
  "g.bigendian=true`);return!0}writeU32le(n){this.api.cmd(`wv4 $"\
  "{n}@${this.addr}@e:cfg.bigendian=false`);return!0}writeU64(n)"\
  "{this.api.cmd(`wv8 ${n}@${this.addr}`);return!0}writeU64be(n)"\
  "{this.api.cmd(`wv8 ${n}@${this.addr}@e:cfg.bigendian=true`);r"\
  "eturn!0}writeU64le(n){this.api.cmd(`wv8 ${n}@${this.addr}@e:c"\
  "fg.bigendian=false`);return!0}readInt(){return this.readU32()"\
  "}readCString(){return JSON.parse(this.api.cmd(`pszj@${this.ad"\
  "dr}`)).string}readWideString(){return JSON.parse(this.api.cmd"\
  "(`pswj@${this.addr}`)).string}readPascalString(){return JSON."\
  "parse(this.api.cmd(`pspj@${this.addr}`)).string}instruction()"\
  "{return this.api.cmdj(`aoj@${this.addr}`)[0]}disassemble(A){l"\
  "et _=A==void 0?'':`${A}`;return this.api.cmd(`pd ${_}@${this."\
  "addr}`)}analyzeFunction(){this.api.cmd('af@'+this.addr);retur"\
  "n this}analyzeFunctionRecursively(){this.api.cmd('afr@'+this."\
  "addr);return this}name(){return this.api.cmd('fd '+this.addr)"\
  ".trim()}methodName(){return this.api.cmd('ic.@'+this.addr).tr"\
  "im()}symbolName(){return this.api.cmd('isj.@'+this.addr).trim"\
  "()}getFunction(){return this.api.cmdj('afij@'+this.addr)}basi"\
  "cBlock(){return this.api.cmdj('abj@'+this.addr)}functionBasic"\
  "Blocks(){return this.api.cmdj('afbj@'+this.addr)}xrefs(){retu"\
  "rn this.api.cmdj('axtj@'+this.addr)}}G.NativePointer=NativePo"\
  "inter;class Base64{static encode(x){return (0,G.b64)(x)}stati"\
  "c decode(x){return (0,G.b64)(x,!0)}}G.Base64=Base64;d(G,'__es"\
  "Module',{value:!0});G.R2PapiShell=void 0;class R2PapiShell{co"\
  "nstructor(A){this.rp=A}mkdir(A,_){_?this.rp.call(`mkdir -p ${"\
  "A}`):this.rp.call(`mkdir ${A}`);return!0}unlink(A){this.rp.ca"\
  "ll(`rm ${A}`);return!0}chdir(A){this.rp.call(`cd ${A}`);retur"\
  "n!0}ls(){return this.rp.call(`ls -q`).trim().split('\\n')}file"\
  "Exists(){return!1}open(A){this.rp.call(`open ${A}`)}system(A)"\
  "{this.rp.call(`!${A}`);return 0}run(A){this.rp.call(`rm ${A}`"\
  ");return 0}mount(A,_){this.rp.call(`m ${A} ${_}`);return!0}um"\
  "ount(A){this.rp.call(`m-${A}`)}chdir2(A){A==void 0&&(A='/');t"\
  "his.rp.call(`mdq ${A}`);return!0}ls2(A){A==void 0&&(A='/');re"\
  "turn this.rp.call(`mdq ${A}`).trim().split('\\n')}enumerateMou"\
  "ntpoints(){return this.rp.cmdj('mlj')}isSymlink(){return!1}is"\
  "Directory(){return!1}}G.R2PapiShell=R2PapiShell;d(G,'__esModu"\
  "le',{value:!0});G.EsilParser=G.EsilNode=G.EsilToken=void 0;cl"\
  "ass EsilToken{constructor(A='',_=0){this.label='';this.commen"\
  "t='';this.text='';this.addr='0';this.position=0;this.text=A;t"\
  "his.position=_}toString(){return this.text}}G.EsilToken=EsilT"\
  "oken;class EsilNode{constructor(A=new EsilToken()){this.type="\
  "'none';this.token=A;this.children=[]}setSides(A,_){this.lhs=A"\
  ";this.rhs=_}addChildren(A,_){A!==void 0&&this.children.push(A"\
  ");_!==void 0&&this.children.push(_)}toEsil(){if(this.lhs!==vo"\
  "id 0&&this.rhs!==void 0){let A=this.lhs.toEsil();A!==''&&(A+="\
  "',');let _=this.rhs.toEsil();return`${_},${A}${this.token}`}r"\
  "eturn''}toString(){let A='';this.token.label!==''&&(A+=this.t"\
  "oken.label+':\\n');this.token.addr!=='0';this.token.comment!=="\
  "''&&(A+='/*'+this.token.comment+'*/\\n');if(`${this.token}`=='"\
  "GOTO')if(this.children.length>0){var _=this.children[0];A+='g"\
  "oto label_'+_.token.position+';\\n'}else{let B=0;A+=`goto labe"\
  "l_${B};\\n`}if(this.children.length>0){A+=`  (if (${this.rhs})"\
  "\\n`;for(let B of this.children)if(B!==null){var x=`${B}`;x!='"\
  "'&&(A+=`  ${x}\\n`)}A+='  )\\n'}if(this.lhs!==void 0&&this.rhs!"\
  "==void 0)return A+`    ( ${this.lhs} ${this.token} ${this.rhs"\
  "} )`;return A+`${this.token}`}}G.EsilNode=EsilNode;class Esil"\
  "Parser{constructor(A){this.cur=0;this.r2=A;this.cur=0;this.st"\
  "ack=[];this.nodes=[];this.tokens=[];this.root=new EsilNode(ne"\
  "w EsilToken('function', 0), 'block')}toJSON(){if(this.stack.l"\
  "ength>0)throw Error('The ESIL stack is not empty');return JSO"\
  "N.stringify(this.root,null,2)}toEsil(){return this.nodes.map("\
  "x=>x.toEsil()).join(',')}optimizeFlags(A){A.rhs!==void 0&&thi"\
  "s.optimizeFlags(A.rhs);A.lhs!==void 0&&this.optimizeFlags(A.l"\
  "hs);for(let i=0;i<A.children.length;i++)this.optimizeFlags(A."\
  "children[i]);var _=`${A}`;if(+_>4096){var B=r2.cmd(`fd.@ ${_}"\
  "`).trim().split('\\n')[0].trim();B!=''&&B.indexOf('+')==-1&&(A"\
  ".token.text=B)}}optimize(A){A.indexOf('flag')!=-1&&this.optim"\
  "izeFlags(this.root)}toString(){return this.root.children.map("\
  "x=>`${x}`).join(';\\n')}reset(){this.nodes=[];this.stack=[];th"\
  "is.tokens=[];this.cur=0;this.root=new EsilNode(new EsilToken("\
  "'function', 0), 'block')}parseRange(A,_){let B=A;while (B<thi"\
  "s.tokens.length&&B<_) {var C=this.peek(B);if(!C)break;this.cu"\
  "r=B;this.pushToken(C);B=this.cur;B++}}parseFunction(A){var _="\
  "this,D=r2.cmd('?v $$').trim(),E=r2.cmdj(`afbj@${A}`);function"\
  " B(n){var C=r2.cmd(`pie ${n} @e:scr.color=0`).trim().split('\\"\
  "n');for(const _a of C){if(!_a.length){console.log('Empty');co"\
  "ntinue}var _A=_a.split(' ');_A.length>1&&(r2.cmd(`s ${_A[0]}`"\
  "),_.parse(_A[1],_A[0]),_.optimize('flags,labels'))}}A==void 0"\
  "&&(A=D);for(let C of E){r2.cmd(`s ${C.addr}`);B(C.ninstr)}r2."\
  "cmd(`s ${D}`)}parse(A,_){var B=A.trim().split(',').map(x=>x.t"\
  "rim());for(let C of B){var _a=new EsilToken(C, this.tokens.le"\
  "ngth);_!==void 0&&(_a.addr=_);this.tokens.push(_a)}this.parse"\
  "Range(this.tokens.length,this.tokens.length)}peek(a){return t"\
  "his.tokens[a]}pushToken(A){if(this.isNumber(A)){var _=new Esi"\
  "lNode(A, 'number');this.stack.push(_);this.nodes.push(_)} els"\
  "e if(this.isInternal(A)){var B=new EsilNode(A, 'flag');this.s"\
  "tack.push(B);this.nodes.push(B)} else if(this.isOperation(A))"\
  "{}else{var C=new EsilNode(A, 'register');this.stack.push(C);t"\
  "his.nodes.push(C)}}isNumber(A){if(`${A}`.startsWith('0'))retu"\
  "rn!0;return +A>0}isInternal(A){var _=`${A}`;return _.startsWi"\
  "th('$')&&_.length>1}parseUntil(A){var _=A+1,D=[],E=this.nodes"\
  ".length,g=this.nodes.length==E;let B=_;for(const x of this.st"\
  "ack)D.push(x);while (B<this.tokens.length) {var C=this.peek(B"\
  ");if(!C)break;if(`${C}`=='}')break;if(`${C}`=='}{')break;B++}"\
  "this.stack=D;this.parseRange(_,B);if(g)return null;return thi"\
  "s.nodes[this.nodes.length-1]}getNodeFor(A){var _=this.peek(A)"\
  ";if(_==void 0)return null;for(let B of this.nodes)if(B.token."\
  "position==A)return B;this.nodes.push(new EsilNode(new EsilTok"\
  "en('label', A), 'label'));return null}findNodeFor(A){for(let "\
  "_ of this.nodes)if(_.token.position==A)return _;return null}i"\
  "sOperation(A){switch(`${A}`) {case '[1]':case '[2]':case '[4]"\
  "':case '[8]':if(this.stack.length>=1){var B=this.stack.pop();"\
  "this.stack.push(B)}else throw Error('Stack needs more items')"\
  ";return!0;case '!':if(this.stack.length>=1){var C=new EsilNod"\
  "e(new EsilToken('', A.position), 'none'),_b=this.stack.pop(),"\
  "_c=new EsilNode(A, 'operation');_c.setSides(C,_b);this.stack."\
  "push(_c)}else throw Error('Stack needs more items');return!0;"\
  "case '':case '}':case '}{':return!0;case 'DUP':{if(this.stack"\
  ".length<1)throw Error('goto cant pop');var _a=this.stack.pop("\
  ");this.stack.push(_a);this.stack.push(_a)}return!0;case 'GOTO"\
  "':var _=this.peek(A.position-1);if(_!==null){if(this.stack.le"\
  "ngth<1)throw Error('goto cant pop');var D=this.stack.pop();if"\
  "(D!==null){var _A=0| +`${D}`;if(_A>0){var E=this.peek(_A);if("\
  "E!==void 0){E.label=`label_${_A}`;E.comment='hehe';var aA=new"\
  " EsilNode(A, 'goto'),_B=this.getNodeFor(E.position);_B!=null&"\
  "&aA.children.push(_B);this.root.children.push(aA)}else consol"\
  "e.error('Cannot find goto node')}else console.error('Cannot f"\
  "ind dest node for goto')}}return!0;case '?{':if(this.stack.le"\
  "ngth>=1){var aB=new EsilNode(new EsilToken('if', A.position),"\
  " 'none'),aC=this.stack.pop(),_C=new EsilNode(A, 'operation');"\
  "_C.setSides(aB,aC);let _d=this.parseUntil(A.position);let _e="\
  "null;_d!==null&&(_C.children.push(_d),this.nodes.push(_d),_e="\
  "this.parseUntil(_d.token.position+1),_e!==null&&(_C.children."\
  "push(_e),this.nodes.push(_e)));this.nodes.push(_C);this.root."\
  "children.push(_C);_e!==null&&(this.cur=_e.token.position)}els"\
  "e throw Error('Stack needs more items');return!0;case '-':if("\
  "this.stack.length>=2){var aD=this.stack.pop(),aE=this.stack.p"\
  "op(),aF=new EsilNode(A, 'operation');aF.setSides(aD,aE);!this"\
  ".stack.length;this.stack.push(aF);this.nodes.push(aF)}else th"\
  "row Error('Stack needs more items');return!0;case '<':case '>"\
  "':case '^':case '&':case '|':case '+':case '*':case '/':case "\
  "'>>=':case '<<=':case '>>>=':case '<<<=':case '>>>>=':case '<"\
  "<<<=':if(this.stack.length>=2){var aG=this.stack.pop(),aH=thi"\
  "s.stack.pop(),aI=new EsilNode(A, 'operation');aI.setSides(aG,"\
  "aH);!this.stack.length;this.stack.push(aI);this.nodes.push(aI"\
  ")}else throw Error('Stack needs more items');return!0;case '="\
  "':case ':=':case '-=':case '+=':case '==':case '=[1]':case '="\
  "[2]':case '=[4]':case '=[8]':if(this.stack.length>=2){var aJ="\
  "this.stack.pop(),aK=this.stack.pop(),aL=new EsilNode(A, 'oper"\
  "ation');aL.setSides(aJ,aK);!this.stack.length&&this.root.chil"\
  "dren.push(aL);this.nodes.push(aL)}else throw Error('Stack nee"\
  "ds more items');return!0}return!1}}G.EsilParser=EsilParser;\n";
