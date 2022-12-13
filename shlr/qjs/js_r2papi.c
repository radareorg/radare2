const char *const js_r2papi_qjs = "" \
  "function t(t){this.r2=t}G.__esModule=!0,G.Base64=G.NativePoin"\
  "ter=G.R2Papi=void 0,t.prototype.clearScreen=function(){this.r"\
  "2.cmd(\"!clear\")},t.prototype.getRegisters=function(){return t"\
  "his.cmdj(\"drj\")},t.prototype.setRegisters=function(t){for(var"\
  " r=0,i=Object.keys(t);r<i.length;r++){var n=i[r],o=t[n];this."\
  "r2.cmd(\"dr \"+n+\"=\"+o)}},t.prototype.analyzeProgram=function()"\
  "{this.r2.cmd(\"aa\")},t.prototype.hex=function(t){return this.r"\
  "2.cmd(\"?v \"+t).trim()},t.prototype.step=function(){return thi"\
  "s.r2.cmd(\"ds\"),this},t.prototype.stepOver=function(){return t"\
  "his.r2.cmd(\"dso\"),this},t.prototype.math=function(t){return+t"\
  "his.r2.cmd(\"?v \"+t)},t.prototype.searchString=function(t){ret"\
  "urn this.cmdj(\"/j \"+t)},t.prototype.binInfo=function(){try{re"\
  "turn this.cmdj(\"ij~{bin}\")}catch(t){return{}}},t.prototype.sk"\
  "ip=function(){this.r2.cmd(\"dss\")},t.prototype.ptr=function(t)"\
  "{return new NativePointer(this,t)},t.prototype.cmd=function(t"\
  "){return this.r2.cmd(t)},t.prototype.cmdj=function(t){return "\
  "JSON.parse(this.cmd(t))},t.prototype.log=function(t){return t"\
  "his.r2.log(t)},t.prototype.clippy=function(t){this.r2.log(thi"\
  "s.r2.cmd(\"?E \"+t))},t.prototype.ascii=function(t){this.r2.log"\
  "(this.r2.cmd(\"?ea \"+t))},t.prototype.listFunctions=function()"\
  "{return this.cmdj(\"aflj\")},t.prototype.listFlags=function(){r"\
  "eturn this.cmdj(\"fj\")},G.R2Papi=t;var NativePointer=function("\
  "){function t(t,r){this.api=t,this.addr=\"\"+r}return t.prototyp"\
  "e.readByteArray=function(t){return JSON.parse(this.api.cmd(\"p"\
  "8j \".concat(t,\"@\").concat(this.addr)))},t.prototype.add=funct"\
  "ion(t){return this.addr=this.api.cmd(\"?v \".concat(this.addr,\""\
  " + \").concat(t)),this},t.prototype.sub=function(t){return thi"\
  "s.addr=this.api.cmd(\"?v \".concat(this.addr,\" - \").concat(t)),"\
  "this},t.prototype.writeCString=function(t){return this.api.cm"\
  "d('\"w '+t+'\"'),this},t.prototype.readCString=function(){retur"\
  "n JSON.parse(this.api.cmd(\"psj@\".concat(this.addr))).string},"\
  "t.prototype.instruction=function(){return this.api.cmdj(\"aoj@"\
  "\".concat(this.addr))[0]},t.prototype.analyzeFunction=function"\
  "(){this.api.cmd(\"af@\"+this.addr)},t.prototype.name=function()"\
  "{return this.api.cmd(\"fd \"+this.addr).trim()},t.prototype.bas"\
  "icBlock=function(){return this.api.cmdj(\"abj@\"+this.addr)},t."\
  "prototype.functionBasicBlocks=function(){return this.api.cmdj"\
  "(\"afbj@\"+this.addr)},t.prototype.xrefs=function(){return this"\
  ".api.cmdj(\"axtj@\"+this.addr)},t}(),Base64=(G.NativePointer=Na"\
  "tivePointer,function(){function t(){}return t.encode=function"\
  "(t){return(0,G.b64)(t)},t.decode=function(t){return(0,G.b64)("\
  "t,!0)},t}());G.Base64=Base64;\n";
