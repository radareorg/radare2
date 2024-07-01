static const char *const js_r2papi_qjs = "" \
  "\"use strict\";var A=a=>typeof a==='number';var b=a=>typeof a=="\
  "='string';const{keys:c}=Object;const{defineProperty:d}=Object"\
  ";d(exports,'__esModule',{value:!0});exports.R2Shell=void 0;cl"\
  "ass R2Shell{constructor(B){this.rp=B}mkdir(C,_b){_b===!0?this"\
  ".rp.call(`mkdir -p ${C}`):this.rp.call(`mkdir ${C}`);return!0"\
  "}unlink(_a){this.rp.call(`rm ${_a}`);return!0}chdir(D){this.r"\
  "p.call(`cd ${D}`);return!0}ls(){var _A=this.rp.call(`ls -q`);"\
  "return _A.trim().split('\\n')}fileExists(e){return!1}open(E){t"\
  "his.rp.call(`open ${E}`)}system(aA){this.rp.call(`!${aA}`);re"\
  "turn 0}mount(aB,_B,_c){!_c&&(_c=0);this.rp.call(`m ${aB} ${_B"\
  "} ${_c}`);return!0}umount(aC){this.rp.call(`m-${aC}`)}chdir2("\
  "aD){this.rp.call(`mdq ${aD}`)}ls2(aE){var aF=this.rp.call(`md"\
  "q ${aE}`);return aF.trim().split('\\n')}enumerateFilesystemTyp"\
  "es(){return this.rp.cmdj('mLj')}enumerateMountpoints(){var aG"\
  "=this.rp.cmdj('mj');return aG['mountpoints']}isSymlink(aH){re"\
  "turn!1}isDirectory(aI){return!1}}exports.R2Shell=R2Shell;d(ex"\
  "ports,'__esModule',{value:!0});exports.EsilParser=exports.Esi"\
  "lNode=exports.EsilToken=void 0;class EsilToken{constructor(aJ"\
  "='',aK=0){this.label=this.comment=this.text='';this.addr='0';"\
  "this.position=0;this.text=aJ;this.position=aK}toString(){retu"\
  "rn this.text}}exports.EsilToken=EsilToken;class EsilNode{cons"\
  "tructor(aL=new EsilToken(),aM='none'){this.type='none';this.t"\
  "oken=aL;this.children=[]}setSides(aN,aO){this.lhs=aN;this.rhs"\
  "=aO}addChildren(aP,aQ){aP!==void 0&&this.children.push(aP);aQ"\
  "!==void 0&&this.children.push(aQ)}toEsil(){if(this.lhs!==void"\
  " 0&&this.rhs!==void 0){let aS=this.lhs.toEsil();aS!==''&&(aS+"\
  "=',');var aR=this.rhs.toEsil();return`${aR},${aS}${this.token"\
  "}`}return''}toString(){let aT='';this.token.label!==''&&(aT+="\
  "this.token.label+':\\n');this.token.addr!=='0';this.token.comm"\
  "ent!==''&&(aT+='/*'+this.token.comment+'*/\\n');if(`${this.tok"\
  "en}`==='GOTO')if(this.children.length>0){var aU=this.children"\
  "[0];aT+='goto label_'+aU.token.position+';\\n'}else{var _C=0;a"\
  "T+=`goto label_${_C};\\n`}if(this.children.length>0){aT+=`  (i"\
  "f (${this.rhs})\\n`;for(const aV of this.children)if(aV!==null"\
  "){var x=`${aV}`;x!=''&&(aT+=`  ${x}\\n`)}aT+='  )\\n'}if(this.l"\
  "hs!==void 0&&this.rhs!==void 0)return aT+`    ( ${this.lhs} $"\
  "{this.token} ${this.rhs} )`;return aT+`${this.token}`}}export"\
  "s.EsilNode=EsilNode;class EsilParser{constructor(aW){this.cur"\
  "=0;this.r2=aW;this.cur=0;this.stack=this.nodes=this.tokens=[]"\
  ";this.root=new EsilNode(new EsilToken('function', 0), 'block'"\
  ")}toJSON(){if(this.stack.length>0)throw Error('The ESIL stack"\
  " is not empty');return JSON.stringify(this.root,null,2)}toEsi"\
  "l(){return this.nodes.map(x=>x.toEsil()).join(',')}optimizeFl"\
  "ags(aX){aX.rhs!==void 0&&this.optimizeFlags(aX.rhs);aX.lhs!=="\
  "void 0&&this.optimizeFlags(aX.lhs);for(let i=0;i<aX.children."\
  "length;i++)this.optimizeFlags(aX.children[i]);var aY=`${aX}`;"\
  "if(+aY>4096){var aZ=r2.cmd(`fd.@ ${aY}`),_d=aZ.trim().split('"\
  "\\n')[0].trim();(_d!=''&&_d.indexOf('+')===-1)&&(aX.token.text"\
  "=_d)}}optimize(bA){bA.indexOf('flag')!=-1&&this.optimizeFlags"\
  "(this.root)}toString(){return this.root.children.map(x=>`${x}"\
  "`).join(';\\n')}reset(){this.nodes=this.stack=this.tokens=[];t"\
  "his.cur=0;this.root=new EsilNode(new EsilToken('function', 0)"\
  ", 'block')}parseRange(bB,bC){let bD=bB;while (bD<this.tokens."\
  "length&&bD<bC) {var _D=this.peek(bD);if(!_D)break;this.cur=bD"\
  ";this.pushToken(_D);bD=this.cur;bD++}}parseFunction(bE){var b"\
  "F=this,_e=r2.cmdj(`afbj@${bE}`);function bG(n){var bI=r2.cmd("\
  "`pie ${n} @e:scr.color=0`),bJ=bI.trim().split('\\n');for(const"\
  " bL of bJ){if(bL.length===0){console.log('Empty');continue}va"\
  "r bK=bL.split(' ');bK.length>1&&(r2.cmd(`s ${bK[0]}`),bF.pars"\
  "e(bK[1],bK[0]),bF.optimize('flags,labels'))}}var bH=r2.cmd('?"\
  "v $$').trim();bE===void 0&&(bE=bH);for(const bb of _e){r2.cmd"\
  "(`s ${bb.addr}`);bG(bb.ninstr)}r2.cmd(`s ${bH}`)}parse(bM,bN)"\
  "{var bO=bM.trim().split(',').map(x=>x.trim());for(const bQ of"\
  " bO){var bP=new EsilToken(bQ, this.tokens.length);bN!==void 0"\
  "&&(bP.addr=bN);this.tokens.push(bP)}this.parseRange(this.toke"\
  "ns.length,this.tokens.length)}peek(a){return this.tokens[a]}p"\
  "ushToken(bR){if(this.isNumber(bR)){var bS=new EsilNode(bR, 'n"\
  "umber');this.stack.push(bS);this.nodes.push(bS)}else if(this."\
  "isInternal(bR)){const bT=new EsilNode(bR, 'flag');this.stack."\
  "push(bT);this.nodes.push(bT)}else if(this.isOperation(bR)){}e"\
  "lse{const bU=new EsilNode(bR, 'register');this.stack.push(bU)"\
  ";this.nodes.push(bU)}}isNumber(bV){if(`${bV}`.startsWith('0')"\
  ")return!0;return +bV>0}isInternal(bW){var bX=`${bW}`;return b"\
  "X.startsWith('$')&&bX.length>1}parseUntil(bY){var bZ=bY+1,cB="\
  "[],_E=this.nodes.length;let cA=bZ;for(const x of this.stack)c"\
  "B.push(x);while (cA<this.tokens.length) {var f=this.peek(cA);"\
  "if(!f)break;if(`${f}`==='}')break;if(`${f}`==='}{')break;cA++"\
  "}this.stack=cB;this.parseRange(bZ,cA);var g=this.nodes.length"\
  "==_E;if(g)return null;return this.nodes[this.nodes.length-1]}"\
  "getNodeFor(cC){var cD=this.peek(cC);if(cD===void 0)return nul"\
  "l;for(const cE of this.nodes)if(cE.token.position===cC)return"\
  " cE;this.nodes.push(new EsilNode(new EsilToken('label', cC), "\
  "'label'));return null}findNodeFor(cF){for(const cG of this.no"\
  "des)if(cG.token.position===cF)return cG;return null}isOperati"\
  "on(cH){switch(`${cH}`) {case '[1]':case '[2]':case '[4]':case"\
  " '[8]':if(this.stack.length>=1){var cI=this.stack.pop();var c"\
  "J=new EsilNode(cI.token, 'operation');this.stack.push(cI)}els"\
  "e throw Error('Stack needs more items');return!0;case '!':if("\
  "this.stack.length>=1){var cK=new EsilNode(new EsilToken('', c"\
  "H.position), 'none');var cL=new EsilNode(cH, 'operation');cL."\
  "setSides(cK,this.stack.pop());this.stack.push(cL)}else throw "\
  "Error('Stack needs more items');return!0;case '':case '}':cas"\
  "e '}{':return!0;case 'DUP':if(this.stack.length<1)throw Error"\
  "('goto cant pop');else{var F=this.stack.pop();this.stack.push"\
  "(F);this.stack.push(F)}return!0;case 'GOTO':{var G=this.peek("\
  "cH.position-1);if(G!==null){if(this.stack.length<1)throw Erro"\
  "r('goto cant pop');const cM=this.stack.pop();if(cM!==null){va"\
  "r h=0| +`${cM}`;if(h>0){var I=this.peek(h);if(I!==void 0){I.l"\
  "abel=`label_${h}`;I.comment='hehe';const cN=new EsilNode(cH, "\
  "'goto');var j=this.getNodeFor(I.position);j!=null&&cN.childre"\
  "n.push(j);this.root.children.push(cN)}else console.error('Can"\
  "not find goto node')}else console.error('Cannot find dest nod"\
  "e for goto')}}}return!0;case '?{':if(this.stack.length>=1){co"\
  "nst cO=new EsilNode(cH, 'operation');cO.setSides(new EsilNode"\
  "(new EsilToken('if', cH.position), 'none'),this.stack.pop());"\
  "var K=this.parseUntil(cH.position);let cP=null;if(K!==null){c"\
  "O.children.push(K);this.nodes.push(K);cP=this.parseUntil(K.to"\
  "ken.position+1);cP!==null&&(cO.children.push(cP),this.nodes.p"\
  "ush(cP))}this.nodes.push(cO);this.root.children.push(cO);cP!="\
  "=null&&(this.cur=cP.token.position)}else throw Error('Stack n"\
  "eeds more items');return!0;case '-':if(this.stack.length>=2){"\
  "const cQ=new EsilNode(cH, 'operation');cQ.setSides(this.stack"\
  ".pop(),this.stack.pop());this.stack.length===0;this.stack.pus"\
  "h(cQ);this.nodes.push(cQ)}else throw Error('Stack needs more "\
  "items');return!0;case '<':case '>':case '^':case '&':case '|'"\
  ":case '+':case '*':case '/':case '>>=':case '<<=':case '>>>='"\
  ":case '<<<=':case '>>>>=':case '<<<<=':if(this.stack.length>="\
  "2){const cR=new EsilNode(cH, 'operation');cR.setSides(this.st"\
  "ack.pop(),this.stack.pop());this.stack.length===0;this.stack."\
  "push(cR);this.nodes.push(cR)}else throw Error('Stack needs mo"\
  "re items');return!0;case '=':case ':=':case '-=':case '+=':ca"\
  "se '==':case '=[1]':case '=[2]':case '=[4]':case '=[8]':if(th"\
  "is.stack.length>=2){const cS=new EsilNode(cH, 'operation');cS"\
  ".setSides(this.stack.pop(),this.stack.pop());this.stack.lengt"\
  "h===0&&this.root.children.push(cS);this.nodes.push(cS)}else t"\
  "hrow Error('Stack needs more items');return!0}return!1}}expor"\
  "ts.EsilParser=EsilParser;d(exports,'__esModule',{value:!0});e"\
  "xports.Base64=void 0;class Base64{static encode(cT){return 0,"\
  "exports.b64(cT)}static decode(cU){return 0,exports.b64(cU,!0)"\
  "}}exports.Base64=Base64;d(exports,'__esModule',{value:!0});ex"\
  "ports.newAsyncR2PipeFromSync=exports.R2PipeSyncFromSync=void "\
  "0;class R2PipeSyncFromSync{constructor(cV){this.r2p=cV}cmd(cW"\
  "){return this.r2p.cmd(cW)}cmdAt(cX,cY){return this.r2p.cmdAt("\
  "cX,cY)}cmdj(cZ){return this.r2p.cmdj(cZ)}call(dA){return this"\
  ".r2p.call(dA)}callj(dB){return this.r2p.cmdj(dB)}callAt(dC,dD"\
  "){return this.r2p.cmdAt(dC,dD)}log(dE){return this.r2p.log(dE"\
  ")}plugin(dF,dG){return this.r2p.plugin(dF,dG)}unload(dH,dI){r"\
  "eturn this.r2p.unload(dH,dI)}}exports.R2PipeSyncFromSync=R2Pi"\
  "peSyncFromSync;function _(dJ){return new R2PipeSyncFromSync(d"\
  "J)}exports.newAsyncR2PipeFromSync=_;d(exports,'__esModule',{v"\
  "alue:!0});exports.R2AI=void 0;class R2AI{constructor(dK,dL,dM"\
  "){this.available=!1;this.model='';this.r2=dK;this.available=!"\
  "1}checkAvailability(){if(this.available)return!0;this.availab"\
  "le=r2pipe_js_1.r2.cmd('r2ai -h').trim()!=='';return this.avai"\
  "lable}reset(){this.checkAvailability();this.available&&r2pipe"\
  "_js_1.r2.call('r2ai -R')}setRole(dN){if(this.available){r2pip"\
  "e_js_1.r2.call(`r2ai -r ${dN}`);return!0}return!1}setModel(dO"\
  "){if(this.available){r2pipe_js_1.r2.call(`r2ai -m ${this.mode"\
  "l}`);return!0}return!1}getModel(){this.available&&(this.model"\
  "=r2pipe_js_1.r2.call('r2ai -m').trim());return this.model}lis"\
  "tModels(){if(this.available){var models=r2pipe_js_1.r2.call('"\
  "r2ai -M');return models.replace('-m ','').trim().split(/\\n/g)"\
  ".filter(x=>x.indexOf(':')!==-1)}return[]}query(dP){if(!this.a"\
  "vailable||dP=='')return'';var dQ=dP.trim().replace(/\\n/g,'.')"\
  ",dR=r2pipe_js_1.r2.call(`r2ai ${dQ}`);return dR.trim()}}expor"\
  "ts.R2AI=R2AI;d(exports,'__esModule',{value:!0});exports.Nativ"\
  "ePointer=exports.NativeCallback=exports.NativeFunction=export"\
  "s.R2PapiSync=exports.Assembler=exports.ProcessClass=exports.M"\
  "oduleClass=exports.ThreadClass=void 0;class ThreadClass{const"\
  "ructor(r2){this.api=null;this.api=r2}backtrace(){return r2pip"\
  "e_js_1.r2.call('dbtj')}sleep(dS){return r2pipe_js_1.r2.call(`"\
  "sleep ${dS}`)}}exports.ThreadClass=ThreadClass;class ModuleCl"\
  "ass{constructor(r2){this.api=null;this.api=r2}fileName(){retu"\
  "rn this.api.call('dpe').trim()}name(){return'Module'}findBase"\
  "Address(){return'TODO'}getBaseAddress(dT){return'TODO'}getExp"\
  "ortByName(dU){return ptr(r2pipe_js_1.r2.call(`iE,name/eq/${dU"\
  "},vaddr/cols,:quiet`))}findExportByName(dV){return this.getEx"\
  "portByName(dV)}enumerateExports(){return r2pipe_js_1.r2.callj"\
  "('iEj')}enumerateImports(){return r2pipe_js_1.r2.callj('iij')"\
  "}enumerateSymbols(){return r2pipe_js_1.r2.callj('isj')}enumer"\
  "ateEntrypoints(){return r2pipe_js_1.r2.callj('iej')}enumerate"\
  "Ranges(){return r2pipe_js_1.r2.callj('omj')}}exports.ModuleCl"\
  "ass=ModuleClass;class ProcessClass{constructor(r2){this.r2=nu"\
  "ll;this.r2=r2}enumerateMallocRanges(){}enumerateSystemRanges("\
  "){}enumerateRanges(){}enumerateThreads(){return r2pipe_js_1.r"\
  "2.callj('dptj')}enumerateModules(){r2pipe_js_1.r2.call('cfg.j"\
  "son.num=string');if(r2pipe_js_1.r2.callj('e cfg.debug')){var "\
  "dW=r2pipe_js_1.r2.callj('dmmj'),dX=[];for(const eB of dW){var"\
  " _f={base:new NativePointer(eB.addr),size:new NativePointer(e"\
  "B.addr_end).sub(eB.addr),path:eB.file,name:eB.name};dX.push(_"\
  "f)}return dX}{var dY=x=>{const y=x.split('/');return y[y.leng"\
  "th-1]},dZ=r2pipe_js_1.r2.callj('obj'),eC=[];for(const eD of d"\
  "Z){eC.push({base:new NativePointer(eD.addr),size:eD.size,path"\
  ":eD.file,name:dY(eD.file)})}var eA=r2pipe_js_1.r2.callj('ilj'"\
  ");for(const lib of eA){eC.push({base:0,size:0,path:lib,name:d"\
  "Y(lib)})}return eC}}getModuleByAddress(eE){}getModuleByName(e"\
  "F){}codeSigningPolicy(){return'optional'}getTmpDir(){return t"\
  "his.r2.call('e dir.tmp').trim()}getHomeDir(){return this.r2.c"\
  "all('e dir.home').trim()}platform(){return this.r2.call('e as"\
  "m.os').trim()}getCurrentDir(){return this.r2.call('pwd').trim"\
  "()}getCurrentThreadId(){return +this.r2.call('dpq')}pageSize("\
  "){if(this.r2.callj('e asm.bits')===64&&this.r2.call('e asm.ar"\
  "ch').startsWith('arm'))return 16384;return 4096}isDebuggerAtt"\
  "ached(){return this.r2.callj('e cfg.debug')}setExceptionHandl"\
  "er(){}id(){return this.r2.callj('dpq').trim()}pointerSize(){r"\
  "eturn r2pipe_js_1.r2.callj('e asm.bits')/8}}exports.ProcessCl"\
  "ass=ProcessClass;class Assembler{constructor(eG){this.program"\
  "='';this.labels={};this.endian=!1;this.pc=ptr(0);eG===void 0?"\
  "this.r2=0,r2pipe_js_1.newAsyncR2PipeFromSync(r2pipe_js_1.r2):"\
  "this.r2=eG;this.program='';this.labels={}}setProgramCounter(p"\
  "c){this.pc=pc}setEndian(eH){this.endian=eH}toString(){return "\
  "this.program}append(x){this.pc=this.pc.add(x.length/2);this.p"\
  "rogram+=x}label(s){var eI=this.pc;this.labels[s]=this.pc;retu"\
  "rn eI}encode(s){var eJ=this.r2.call(`pa ${s}`);return eJ.trim"\
  "()}decode(s){var eK=this.r2.call(`pad ${s}`);return eK.trim()"\
  "}}exports.Assembler=Assembler;class R2PapiSync{constructor(r2"\
  "){this.r2=r2}toString(){return'[object R2Papi]'}toJSON(){retu"\
  "rn`${this}`}getBaseAddress(){return new NativePointer(this.cm"\
  "d('e bin.baddr'))}jsonToTypescript(eL,a){let eM=`interface ${"\
  "eL} {\\n`;(a.length&&a.length>0)&&(a=a[0]);for(const k of c(a)"\
  "){var eN=typeof a[k],eO=k;eM+=`    ${eO}: ${eN};\\n`}return`${"\
  "eM}}\\n`}getBits(){return +this.cmd('-b')}getArch(){return thi"\
  "s.cmdTrim('-a')}callTrim(x){var eP=this.call(x);return eP.tri"\
  "m()}cmdTrim(x){var eQ=this.cmd(x);return eQ.trim()}getCpu(){r"\
  "eturn this.cmdTrim('-e asm.cpu')}setArch(eR,eS){this.cmd(`-a "\
  "${eR}`);eS!==void 0&&this.cmd(`-b ${eS}`)}setFlagSpace(eT){th"\
  "is.cmd(`fs ${eT}`)}demangleSymbol(eU,eV){return this.cmdTrim("\
  "'iD '+eU+' '+eV)}setLogLevel(eW){this.cmd(`e log.level=${eW}`"\
  ")}newMap(eX,eY,eZ,fA,fB,_F=''){this.cmd(`om ${eX} ${eY} ${eZ}"\
  " ${fA} ${fB} ${_F}`)}at(a){return new NativePointer(a)}getShe"\
  "ll(){return new shell_js_1.R2Shell(this)}version(){var v=this"\
  ".r2.cmd('?Vq');return v.trim()}platform(){var fC=this.r2.cmd("\
  "'uname');return fC.trim()}arch(){var fD=this.r2.cmd('uname -a"\
  "');return fD.trim()}bits(){var fE=this.r2.cmd('uname -b');ret"\
  "urn fE.trim()}id(){return +this.r2.cmd('?vi:$p')}printAt(fF,x"\
  ",y){}clearScreen(){this.r2.cmd('!clear');return this}getConfi"\
  "g(fG){if(fG==='')return Error('Empty key');var fH=this.r2.cmd"\
  "(`e~^${fG} =`);if(fH.trim()==='')return Error('Config key doe"\
  "s not exist');var fI=this.r2.call(`e ${fG}`);return fI.trim()"\
  "}setConfig(fJ,fK){this.r2.call('e '+fJ+'='+fK);return this}ge"\
  "tRegisterStateForEsil(){var fL=this.cmdj('dre');return this.c"\
  "mdj('dre')}getRegisters(){return this.cmdj('drj')}resizeFile("\
  "fM){this.cmd(`r ${fM}`);return this}insertNullBytes(fN,fO){fO"\
  "===void 0&&(fO='$$');this.cmd(`r+${fN}@${fO}`);return this}re"\
  "moveBytes(fP,fQ){fQ===void 0&&(fQ='$$');this.cmd(`r-${fP}@${f"\
  "Q}`);return this}seek(fR){this.cmd(`s ${fR}`);return this}cur"\
  "rentSeek(){return new NativePointer('$$')}seekToRelativeOpcod"\
  "e(fS){this.cmd(`so ${fS}`);return this.currentSeek()}getBlock"\
  "Size(){return +this.cmd('b')}setBlockSize(a){this.cmd(`b ${a}"\
  "`);return this}countFlags(){return +this.cmd('f~?')}countFunc"\
  "tions(){return +this.cmd('aflc')}analyzeFunctionsWithEsil(fT)"\
  "{this.cmd('aaef')}analyzeProgramWithEsil(fU){this.cmd('aae')}"\
  "analyzeProgram(fV){fV===void 0&&(fV=0);switch(fV) {case 0:thi"\
  "s.cmd('aa');break;case 1:this.cmd('aaa');break;case 2:this.cm"\
  "d('aaaa');break;case 3:this.cmd('aaaaa');break}return this}en"\
  "umerateThreads(){var fW=this.cmdj('drj'),fX={context:fW,id:0,"\
  "state:'waiting',selected:!0};return[fX]}currentThreadId(){if("\
  "+this.cmd('e cfg.debug'))return +this.cmd('dpt.');return this"\
  ".id()}setRegisters(fY){for(const r of c(fY)){var v=fY[r];this"\
  ".r2.cmd('dr '+r+'='+v)}}hex(s){var fZ=this.r2.cmd(`?v ${s}`);"\
  "return fZ.trim()}step(){this.r2.cmd('ds');return this}stepOve"\
  "r(){this.r2.cmd('dso');return this}math(gA){return +this.r2.c"\
  "md(`?v ${gA}`)}stepUntil(gB){this.cmd(`dsu ${gB}`)}enumerateX"\
  "refsTo(s){var gC=this.call(`axtq ${s}`);return gC.trim().spli"\
  "t(/\\n/)}findXrefsTo(s,gD){gD?this.call(`/r ${s}`):this.call(`"\
  "/re ${s}`)}analyzeFunctionsFromCalls(){this.call('aac');retur"\
  "n this}autonameAllFunctions(){this.call('aan');return this}an"\
  "alyzeFunctionsWithPreludes(){this.call('aap');return this}ana"\
  "lyzeObjCReferences(){this.cmd('aao');return this}analyzeImpor"\
  "ts(){this.cmd('af @ sym.imp.*');return this}searchDisasm(s){r"\
  "eturn this.callj(`/ad ${s}`)}searchString(s){return this.cmdj"\
  "(`/j ${s}`)}searchBytes(gE){function gF(gG){return (gG&0xff)."\
  "toString(16)}var s=gE.map(gF).join('');return this.cmdj(`/xj "\
  "${s}`)}binInfo(){try{return this.cmdj('ij~{bin}')}catch(e){re"\
  "turn{}}}selectBinary(id){this.call(`ob ${id}`)}openFile(gH){v"\
  "ar gI=this.call('oqq');this.call(`o ${gH}`);var gJ=this.call("\
  "'oqq');if(gI.trim()===gJ.trim())return Error('Cannot open fil"\
  "e');return parseInt(gJ)}openFileNomap(gK){var gL=this.call('o"\
  "qq');this.call(`of ${gK}`);var gM=this.call('oqq');if(gL.trim"\
  "()===gM.trim())return Error('Cannot open file');return parseI"\
  "nt(gM)}currentFile(gN){return this.call('o.').trim()}enumerat"\
  "ePlugins(gO){switch(gO) {case 'bin':return this.callj('Lij');"\
  "case 'io':return this.callj('Loj');case 'core':return this.ca"\
  "llj('Lcj');case 'arch':return this.callj('LAj');case 'anal':r"\
  "eturn this.callj('Laj');case 'lang':return this.callj('Llj')}"\
  "return[]}enumerateModules(){return this.callj('dmmj')}enumera"\
  "teFiles(){return this.callj('oj')}enumerateBinaries(){return "\
  "this.callj('obj')}enumerateMaps(){return this.callj('omj')}en"\
  "umerateClasses(){return this.callj('icj')}enumerateSymbols(){"\
  "return this.callj('isj')}enumerateExports(){return this.callj"\
  "('iEj')}enumerateImports(){return this.callj('iij')}enumerate"\
  "Libraries(){return this.callj('ilj')}enumerateSections(){retu"\
  "rn this.callj('iSj')}enumerateSegments(){return this.callj('i"\
  "SSj')}enumerateEntrypoints(){return this.callj('iej')}enumera"\
  "teRelocations(){return this.callj('irj')}enumerateFunctions()"\
  "{return this.cmdj('aflj')}enumerateFlags(){return this.cmdj('"\
  "fj')}skip(){this.r2.cmd('dss')}ptr(s){return new NativePointe"\
  "r(s, this)}call(s){return this.r2.call(s)}callj(s){return JSO"\
  "N.parse(this.call(s))}cmd(s){return this.r2.cmd(s)}cmdj(s){re"\
  "turn JSON.parse(this.cmd(s))}log(s){return this.r2.log(s)}cli"\
  "ppy(gP){this.r2.log(this.r2.cmd(`?E ${gP}`))}ascii(gQ){this.r"\
  "2.log(this.r2.cmd(`?ea ${gQ}`))}}exports.R2PapiSync=R2PapiSyn"\
  "c;class NativeFunction{constructor(){}}exports.NativeFunction"\
  "=NativeFunction;class NativeCallback{constructor(){}}exports."\
  "NativeCallback=NativeCallback;class NativePointer{constructor"\
  "(s,gR){this.api=gR??exports.R;this.addr=`${s}`.trim()}filterF"\
  "lag(gS){return this.api.call(`fD ${gS}`)}setFlag(gT){this.api"\
  ".call(`f ${gT}=${this.addr}`)}unsetFlag(){this.api.call(`f-${"\
  "this.addr}`)}hexdump(gU){var gV=gU===void 0?'':`${gU}`;return"\
  " this.api.cmd(`x${gV}@${this.addr}`)}functionGraph(gW){if(gW="\
  "=='dot')return this.api.cmd(`agfd@ ${this.addr}`);if(gW==='js"\
  "on')return this.api.cmd(`agfj@${this.addr}`);if(gW==='mermaid"\
  "')return this.api.cmd(`agfm@${this.addr}`);return this.api.cm"\
  "d(`agf@${this.addr}`)}readByteArray(gX){return JSON.parse(thi"\
  "s.api.cmd(`p8j ${gX}@${this.addr}`))}readHexString(gY){return"\
  " this.api.cmd(`p8 ${gY}@${this.addr}`).trim()}and(a){var gZ=t"\
  "his.api.call(`?v ${this.addr} & ${a}`);return new NativePoint"\
  "er(gZ.trim())}or(a){var hA=this.api.call(`?v ${this.addr} | $"\
  "{a}`);return new NativePointer(hA.trim())}add(a){var hB=this."\
  "api.call(`?v ${this.addr}+${a}`);return new NativePointer(hB)"\
  "}sub(a){var hC=this.api.call(`?v ${this.addr}-${a}`);return n"\
  "ew NativePointer(hC)}writeByteArray(hD){this.api.cmd('wx '+hD"\
  ".join(''));return this}writeAssembly(hE){this.api.cmd(`wa ${h"\
  "E} @ ${this.addr}`);return this}writeCString(s){this.api.call"\
  "(`w ${s}`);return this}writeWideString(s){this.api.call(`ww $"\
  "{s}`);return this}isNull(){return this.toNumber()==0}compare("\
  "a){var hF=b(a)||A(a)?new NativePointer(a):a,hG=r2pipe_js_1.r2"\
  ".call(`?vi ${this.addr} - ${hF.addr}`);if(hG[0]==='-')return "\
  "-1;if(hG[0]==='0')return 0;return 1}pointsToNull(){var hH=thi"\
  "s.readPointer();return hH.compare(0)==0}toJSON(){var hI=this."\
  "api.cmd('?vi '+this.addr.trim());return hI.trim()}toString(){"\
  "return this.api.cmd('?v '+this.addr.trim()).trim()}toNumber()"\
  "{return parseInt(`${this}`)}writePointer(p){}readRelativePoin"\
  "ter(){return this.add(this.readS32())}readPointer(){var hJ=th"\
  "is.api.call('pvp@'+this.addr);return new NativePointer(hJ)}re"\
  "adS8(){return parseInt(this.api.cmd(`pv1d@${this.addr}`))}rea"\
  "dU8(){return parseInt(this.api.cmd(`pv1u@${this.addr}`))}read"\
  "U16(){return parseInt(this.api.cmd(`pv2d@${this.addr}`))}read"\
  "U16le(){}readU16be(){}readS16(){}readS16le(){}readS16be(){}re"\
  "adS32(){}readU32(){}readU32le(){}readU32be(){}readU64(){retur"\
  "n parseInt(this.api.cmd(`pv8u@${this.addr}`))}readU64le(){}re"\
  "adU64be(){}writeInt(n){return this.writeU32(n)}writeU8(n){thi"\
  "s.api.cmd(`wv1 ${n}@${this.addr}`);return!0}writeU16(n){this."\
  "api.cmd(`wv2 ${n}@${this.addr}`);return!0}writeU16be(n){this."\
  "api.cmd(`wv2 ${n}@${this.addr}@e:cfg.bigendian=true`);return!"\
  "0}writeU16le(n){this.api.cmd(`wv2 ${n}@${this.addr}@e:cfg.big"\
  "endian=false`);return!0}writeU32(n){this.api.cmd(`wv4 ${n}@${"\
  "this.addr}`);return!0}writeU32be(n){this.api.cmd(`wv4 ${n}@${"\
  "this.addr}@e:cfg.bigendian=true`);return!0}writeU32le(n){this"\
  ".api.cmd(`wv4 ${n}@${this.addr}@e:cfg.bigendian=false`);retur"\
  "n!0}writeU64(n){this.api.cmd(`wv8 ${n}@${this.addr}`);return!"\
  "0}writeU64be(n){this.api.cmd(`wv8 ${n}@${this.addr}@e:cfg.big"\
  "endian=true`);return!0}writeU64le(n){this.api.cmd(`wv8 ${n}@$"\
  "{this.addr}@e:cfg.bigendian=false`);return!0}readInt32(){retu"\
  "rn this.readU32()}readCString(){return JSON.parse(this.api.cm"\
  "d(`pszj@${this.addr}`)).string}readWideString(){return JSON.p"\
  "arse(this.api.cmd(`pswj@${this.addr}`)).string}readPascalStri"\
  "ng(){return JSON.parse(this.api.cmd(`pspj@${this.addr}`)).str"\
  "ing}instruction(){var hK=this.api.cmdj(`aoj@${this.addr}`);re"\
  "turn hK[0]}disassemble(hL){var hM=hL===void 0?'':`${hL}`;retu"\
  "rn this.api.cmd(`pd ${hM}@${this.addr}`)}analyzeFunction(){th"\
  "is.api.cmd('af@'+this.addr);return this}analyzeFunctionRecurs"\
  "ively(){this.api.cmd('afr@'+this.addr);return this}name(){ret"\
  "urn this.api.cmd('fd '+this.addr).trim()}methodName(){return "\
  "this.api.cmd('ic.@'+this.addr).trim()}symbolName(){var hN=thi"\
  "s.api.cmd('isj.@'+this.addr);return hN.trim()}getFunction(){r"\
  "eturn this.api.cmdj('afij@'+this.addr)}basicBlock(){return th"\
  "is.api.cmdj('abj@'+this.addr)}functionBasicBlocks(){return th"\
  "is.api.cmdj('afbj@'+this.addr)}xrefs(){return this.api.cmdj('"\
  "axtj@'+this.addr)}}exports.NativePointer=NativePointer;var u="\
  "R2PapiSync;\n";
