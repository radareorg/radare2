const char *const js_r2papi_qjs = "" \
  "G.__esModule=!0,G.Base64=G.NativePointer=G.R2Papi=void 0;var "\
  "shell_js_1=G;function t(t){this.r2=t}t.prototype.getShell=fun"\
  "ction(){return new shell_js_1.R2PapiShell(this)},t.prototype."\
  "printAt=function(t,r,n){},t.prototype.clearScreen=function(){"\
  "this.r2.cmd(\"!clear\")},t.prototype.getConfig=function(t){retu"\
  "rn this.r2.call(\"e \"+t).trim()},t.prototype.setConfig=functio"\
  "n(t,r){this.r2.call(\"e \"+t+\"=\"+r)},t.prototype.getRegisters=f"\
  "unction(){return this.cmdj(\"drj\")},t.prototype.enumerateThrea"\
  "ds=function(){return[{context:this.cmdj(\"drj\"),id:0,state:\"wa"\
  "iting\",selected:!0}]},t.prototype.setRegisters=function(t){fo"\
  "r(var r=0,n=Object.keys(t);r<n.length;r++){var i=n[r],o=t[i];"\
  "this.r2.cmd(\"dr \"+i+\"=\"+o)}},t.prototype.analyzeProgram=funct"\
  "ion(){this.r2.cmd(\"aa\")},t.prototype.hex=function(t){return t"\
  "his.r2.cmd(\"?v \"+t).trim()},t.prototype.step=function(){retur"\
  "n this.r2.cmd(\"ds\"),this},t.prototype.stepOver=function(){ret"\
  "urn this.r2.cmd(\"dso\"),this},t.prototype.math=function(t){ret"\
  "urn+this.r2.cmd(\"?v \"+t)},t.prototype.searchString=function(t"\
  "){return this.cmdj(\"/j \"+t)},t.prototype.searchBytes=function"\
  "(t){t=t.map(function(t){return(255&t).toString(16)}).join(\"\")"\
  ";return this.cmdj(\"/xj \"+t)},t.prototype.binInfo=function(){t"\
  "ry{return this.cmdj(\"ij~{bin}\")}catch(t){return{}}},t.prototy"\
  "pe.enumerateModules=function(){return this.callj(\"dmmj\")},t.p"\
  "rototype.skip=function(){this.r2.cmd(\"dss\")},t.prototype.ptr="\
  "function(t){return new NativePointer(t,this)},t.prototype.cal"\
  "l=function(t){return this.r2.call(t)},t.prototype.callj=funct"\
  "ion(t){return JSON.parse(this.call(t))},t.prototype.cmd=funct"\
  "ion(t){return this.r2.cmd(t)},t.prototype.cmdj=function(t){re"\
  "turn JSON.parse(this.cmd(t))},t.prototype.log=function(t){ret"\
  "urn this.r2.log(t)},t.prototype.clippy=function(t){this.r2.lo"\
  "g(this.r2.cmd(\"?E \"+t))},t.prototype.ascii=function(t){this.r"\
  "2.log(this.r2.cmd(\"?ea \"+t))},t.prototype.listFunctions=funct"\
  "ion(){return this.cmdj(\"aflj\")},t.prototype.listFlags=functio"\
  "n(){return this.cmdj(\"fj\")},G.R2Papi=t;var NativePointer=func"\
  "tion(){function t(t,r){this.api=void 0===r?G.R:r,this.addr=(\""\
  "\"+t).trim()}return t.prototype.readByteArray=function(t){retu"\
  "rn JSON.parse(this.api.cmd(\"p8j \".concat(t,\"@\").concat(this.a"\
  "ddr)))},t.prototype.and=function(t){return this.addr=this.api"\
  ".call(\"?v \".concat(this.addr,\" & \").concat(t)).trim(),this},t"\
  ".prototype.or=function(t){return this.addr=this.api.call(\"?v "\
  "\".concat(this.addr,\" | \").concat(t)).trim(),this},t.prototype"\
  ".add=function(t){return this.addr=this.api.call(\"?v \".concat("\
  "this.addr,\"+\").concat(t)).trim(),this},t.prototype.sub=functi"\
  "on(t){return this.addr=this.api.call(\"?v \".concat(this.addr,\""\
  "-\").concat(t)).trim(),this},t.prototype.writeByteArray=functi"\
  "on(t){return this.api.cmd(\"wx \"+t.join(\"\")),this},t.prototype"\
  ".writeAssembly=function(t){return this.api.cmd('\"wa '.concat("\
  "t,\" @ \").concat(this.addr)),this},t.prototype.writeCString=fu"\
  "nction(t){return this.api.cmd('\"w '+t+'\"'),this},t.prototype."\
  "isNull=function(){return 0==+this.addr},t.prototype.compare=f"\
  "unction(r){return(r=\"string\"!=typeof r&&\"number\"!=typeof r?r:"\
  "new t(r)).addr===this.addr},t.prototype.pointsToNull=function"\
  "(){return this.readPointer().compare(0)},t.prototype.toString"\
  "=function(){return this.addr.trim()},t.prototype.writePointer"\
  "=function(t){var r=64==+this.api.getConfig(\"asm.bits\")?\"wv8\":"\
  "\"wv4\";this.api.cmd(\"\".concat(r,\" \").concat(t,\"@\").concat(this"\
  "))},t.prototype.readPointer=function(){return 64==+this.api.g"\
  "etConfig(\"asm.bits\")?new t(this.api.call(\"pv8@\"+this.addr)):n"\
  "ew t(this.api.call(\"pv4@\"+this.addr))},t.prototype.readU8=fun"\
  "ction(){return+this.api.cmd('pv1@\"'.concat(this.addr))},t.pro"\
  "totype.readU16=function(){return+this.api.cmd('pv2@\"'.concat("\
  "this.addr))},t.prototype.readU32=function(){return+this.api.c"\
  "md('pv4@\"'.concat(this.addr))},t.prototype.readU64=function()"\
  "{return+this.api.cmd('pv8@\"'.concat(this.addr))},t.prototype."\
  "writeInt=function(t){return+this.api.cmd(\"wv4 \".concat(t,\"@\")"\
  ".concat(this.addr))},t.prototype.writeU8=function(t){return t"\
  "his.api.cmd(\"wv1 \".concat(t,\"@\").concat(this.addr)),!0},t.pro"\
  "totype.writeU16=function(t){return this.api.cmd(\"wv2 \".concat"\
  "(t,\"@\").concat(this.addr)),!0},t.prototype.writeU32=function("\
  "t){return this.api.cmd(\"wv4 \".concat(t,\"@\").concat(this.addr)"\
  "),!0},t.prototype.writeU64=function(t){return this.api.cmd(\"w"\
  "v8 \".concat(t,\"@\").concat(this.addr)),!0},t.prototype.readInt"\
  "=function(){return+this.api.cmd('pv4@\"'.concat(this.addr))},t"\
  ".prototype.readCString=function(){return JSON.parse(this.api."\
  "cmd(\"psj@\".concat(this.addr))).string},t.prototype.instructio"\
  "n=function(){return this.api.cmdj(\"aoj@\".concat(this.addr))[0"\
  "]},t.prototype.analyzeFunction=function(){this.api.cmd(\"af@\"+"\
  "this.addr)},t.prototype.name=function(){return this.api.cmd(\""\
  "fd \"+this.addr).trim()},t.prototype.basicBlock=function(){ret"\
  "urn this.api.cmdj(\"abj@\"+this.addr)},t.prototype.functionBasi"\
  "cBlocks=function(){return this.api.cmdj(\"afbj@\"+this.addr)},t"\
  ".prototype.xrefs=function(){return this.api.cmdj(\"axtj@\"+this"\
  ".addr)},t}(),Base64=(G.NativePointer=NativePointer,function()"\
  "{function t(){}return t.encode=function(t){return(0,G.b64)(t)"\
  "},t.decode=function(t){return(0,G.b64)(t,!0)},t}()),Base64=(G"\
  ".Base64=Base64,G.__esModule=!0,G.R2PapiShell=void 0,function("\
  "){function t(t){this.rp=t}return t.prototype.mkdir=function(t"\
  ",r){return!0===r?this.rp.call(\"mkdir -p \".concat(t)):this.rp."\
  "call(\"mkdir \".concat(t)),!0},t.prototype.unlink=function(t){r"\
  "eturn this.rp.call(\"rm \".concat(t)),!0},t.prototype.chdir=fun"\
  "ction(t){return this.rp.call(\"cd \".concat(t)),!0},t.prototype"\
  ".ls=function(){return this.rp.call(\"ls -q\").trim().split(\"\\n\""\
  ")},t.prototype.fileExists=function(t){return!1},t.prototype.o"\
  "pen=function(t){this.rp.call(\"open \".concat(t))},t.prototype."\
  "system=function(t){return this.rp.call(\"!\".concat(t)),0},t.pr"\
  "ototype.run=function(t){return this.rp.call(\"rm \".concat(t)),"\
  "0},t.prototype.mount=function(t,r){return this.rp.call(\"m \".c"\
  "oncat(t,\" \").concat(r)),!0},t.prototype.umount=function(t){th"\
  "is.rp.call(\"m-\".concat(t))},t.prototype.chdir2=function(t){re"\
  "turn this.rp.call(\"mdq \".concat(t=void 0===t?\"/\":t)),!0},t.pr"\
  "ototype.ls2=function(t){return this.rp.call(\"mdq \".concat(t=v"\
  "oid 0===t?\"/\":t)).trim().split(\"\\n\")},t.prototype.enumerateMo"\
  "untpoints=function(){return this.rp.cmdj(\"mlj\")},t}());G.R2Pa"\
  "piShell=Base64;\n";
