const char *const r2papi_qjs = "" \
  "function t(t){this.r2=t}G.__esModule=!0,G.NativePointer=G.R2A"\
  "pi=void 0,t.prototype.clearScreen=function(){this.r2.cmd(\"!cl"\
  "ear\")},t.prototype.getRegisters=function(){return this.cmdj(\""\
  "drj\")},t.prototype.setRegisters=function(t){for(var r=0,i=Obj"\
  "ect.keys(t);r<i.length;r++){var n=i[r],o=t[n];this.r2.cmd(\"dr"\
  " \"+n+\"=\"+o)}},t.prototype.analyzeProgram=function(){this.r2.c"\
  "md(\"aa\")},t.prototype.hex=function(t){return this.r2.cmd(\"?v "\
  "\"+t).trim()},t.prototype.step=function(){return this.r2.cmd(\""\
  "ds\"),this},t.prototype.stepOver=function(){return this.r2.cmd"\
  "(\"dso\"),this},t.prototype.math=function(t){return+this.r2.cmd"\
  "(\"?v \"+t)},t.prototype.searchString=function(t){return this.c"\
  "mdj(\"/j \"+t)},t.prototype.binInfo=function(){try{return this."\
  "cmdj(\"ij~{bin}\")}catch(t){return{}}},t.prototype.skip=functio"\
  "n(){this.r2.cmd(\"dss\")},t.prototype.ptr=function(t){return ne"\
  "w NativePointer(this,t)},t.prototype.cmd=function(t){return t"\
  "his.r2.cmd(t)},t.prototype.cmdj=function(t){return JSON.parse"\
  "(this.cmd(t))},t.prototype.log=function(t){return this.r2.log"\
  "(t)},t.prototype.clippy=function(t){this.r2.log(this.r2.cmd(\""\
  "?E \"+t))},t.prototype.ascii=function(t){this.r2.log(this.r2.c"\
  "md(\"?ea \"+t))},t.prototype.listFunctions=function(){return th"\
  "is.cmdj(\"aflj\")},t.prototype.listFlags=function(){return this"\
  ".cmdj(\"fj\")},G.R2Api=t;var NativePointer=function(){function "\
  "t(t,r){this.api=t,this.addr=\"\"+r}return t.prototype.readByteA"\
  "rray=function(t){return JSON.parse(this.api.cmd(\"p8j \".concat"\
  "(t,\"@\").concat(this.addr)))},t.prototype.add=function(t){retu"\
  "rn this.addr=this.api.cmd(\"?v \".concat(this.addr,\" + \").conca"\
  "t(t)),this},t.prototype.sub=function(t){return this.addr=this"\
  ".api.cmd(\"?v \".concat(this.addr,\" - \").concat(t)),this},t.pro"\
  "totype.writeCString=function(t){return this.api.cmd('\"w '+t+'"\
  "\"'),this},t.prototype.readCString=function(){return JSON.pars"\
  "e(this.api.cmd(\"psj@\".concat(this.addr))).string},t.prototype"\
  ".instruction=function(){return this.api.cmdj(\"aoj@\".concat(th"\
  "is.addr))[0]},t.prototype.analyzeFunction=function(){this.api"\
  ".cmd(\"af@\"+this.addr)},t.prototype.name=function(){return thi"\
  "s.api.cmd(\"fd \"+this.addr).trim()},t.prototype.basicBlock=fun"\
  "ction(){return this.api.cmdj(\"abj@\"+this.addr)},t.prototype.f"\
  "unctionBasicBlocks=function(){return this.api.cmdj(\"afbj@\"+th"\
  "is.addr)},t.prototype.xrefs=function(){return this.api.cmdj(\""\
  "axtj@\"+this.addr)},t}();G.NativePointer=NativePointer;\n";
