static const char *const js_require_qjs = "" \
  "var requirejs,require,define;!function(global,setTimeout){var"\
  " req,s,head,baseElement,dataMain,src,interactiveScript,curren"\
  "tlyAddingScript,mainScript,subPath,version=\"2.3.6\",commentReg"\
  "Exp=/\\/\\*[\\s\\S]*?\\*\\/|([^:\"'=]|^)\\/\\/.*$/gm,cjsRequireRegExp="\
  "/[^.]\\s*require\\s*\\(\\s*[\"']([^'\"\\s]+)[\"']\\s*\\)/g,jsSuffixRegE"\
  "xp=/\\.js$/,currDirRegExp=/^\\.\\//,op=Object.prototype,ostring="\
  "op.toString,hasOwn=op.hasOwnProperty,isBrowser=!(\"undefined\"="\
  "=typeof window||\"undefined\"==typeof navigator||!window.docume"\
  "nt),isWebWorker=!isBrowser&&\"undefined\"!=typeof importScripts"\
  ",readyRegExp=isBrowser&&\"PLAYSTATION 3\"===navigator.platform?"\
  "/^complete$/:/^(complete|loaded)$/,defContextName=\"_\",isOpera"\
  "=\"undefined\"!=typeof opera&&\"[object Opera]\"===opera.toString"\
  "(),contexts={},cfg={},globalDefQueue=[],useInteractive=!1;fun"\
  "ction commentReplace(e,t){return t||\"\"}function isFunction(e)"\
  "{return\"[object Function]\"===ostring.call(e)}function isArray"\
  "(e){return\"[object Array]\"===ostring.call(e)}function each(e,"\
  "t){var i;if(e)for(i=0;i<e.length&&(!e[i]||!t(e[i],i,e));i+=1)"\
  ";}function eachReverse(e,t){var i;if(e)for(i=e.length-1;-1<i&"\
  "&(!e[i]||!t(e[i],i,e));--i);}function hasProp(e,t){return has"\
  "Own.call(e,t)}function getOwn(e,t){return hasProp(e,t)&&e[t]}"\
  "function eachProp(e,t){for(var i in e)if(hasProp(e,i)&&t(e[i]"\
  ",i))break}function mixin(e,t,i,r){t&&eachProp(t,(function(t,n"\
  "){!i&&hasProp(e,n)||(!r||\"object\"!=typeof t||!t||isArray(t)||"\
  "isFunction(t)||t instanceof RegExp?e[n]=t:(e[n]||(e[n]={}),mi"\
  "xin(e[n],t,i,r)))}))}function bind(e,t){return function(){ret"\
  "urn t.apply(e,arguments)}}function scripts(){return document."\
  "getElementsByTagName(\"script\")}function defaultOnError(e){thr"\
  "ow e}function getGlobal(e){var t;return e&&(t=global,each(e.s"\
  "plit(\".\"),(function(e){t=t[e]})),t)}function makeError(e,t,i,"\
  "r){return(t=new Error(t+\"\\nhttps://requirejs.org/docs/errors."\
  "html#\"+e)).requireType=e,t.requireModules=r,i&&(t.originalErr"\
  "or=i),t}if(void 0===define){if(void 0!==requirejs){if(isFunct"\
  "ion(requirejs))return;cfg=requirejs,requirejs=void 0}void 0=="\
  "=require||isFunction(require)||(cfg=require,require=void 0),r"\
  "eq=requirejs=function(e,t,i,r){var n,o=defContextName;return "\
  "isArray(e)||\"string\"==typeof e||(n=e,isArray(t)?(e=t,t=i,i=r)"\
  ":e=[]),n&&n.context&&(o=n.context),r=(r=getOwn(contexts,o))||"\
  "(contexts[o]=req.s.newContext(o)),n&&r.configure(n),r.require"\
  "(e,t,i)},req.config=function(e){return req(e)},req.nextTick=v"\
  "oid 0!==setTimeout?function(e){setTimeout(e,4)}:function(e){e"\
  "()},require=require||req,req.version=version,req.jsExtRegExp="\
  "/^\\/|:|\\?|\\.js$/,req.isBrowser=isBrowser,s=req.s={contexts:co"\
  "ntexts,newContext:newContext},req({}),each([\"toUrl\",\"undef\",\""\
  "defined\",\"specified\"],(function(e){req[e]=function(){var t=co"\
  "ntexts[defContextName];return t.require[e].apply(t,arguments)"\
  "}})),isBrowser&&(head=s.head=document.getElementsByTagName(\"h"\
  "ead\")[0],baseElement=document.getElementsByTagName(\"base\")[0]"\
  ",baseElement)&&(head=s.head=baseElement.parentNode),req.onErr"\
  "or=defaultOnError,req.createNode=function(e,t,i){var r=e.xhtm"\
  "l?document.createElementNS(\"http://www.w3.org/1999/xhtml\",\"ht"\
  "ml:script\"):document.createElement(\"script\");return r.type=e."\
  "scriptType||\"text/javascript\",r.charset=\"utf-8\",r.async=!0,r}"\
  ",req.load=function(e,t,i){var r,n=e&&e.config||{};if(isBrowse"\
  "r)return(r=req.createNode(n,t,i)).setAttribute(\"data-requirec"\
  "ontext\",e.contextName),r.setAttribute(\"data-requiremodule\",t)"\
  ",!r.attachEvent||r.attachEvent.toString&&r.attachEvent.toStri"\
  "ng().indexOf(\"[native code\")<0||isOpera?(r.addEventListener(\""\
  "load\",e.onScriptLoad,!1),r.addEventListener(\"error\",e.onScrip"\
  "tError,!1)):(useInteractive=!0,r.attachEvent(\"onreadystatecha"\
  "nge\",e.onScriptLoad)),r.src=i,n.onNodeCreated&&n.onNodeCreate"\
  "d(r,n,t,i),currentlyAddingScript=r,baseElement?head.insertBef"\
  "ore(r,baseElement):head.appendChild(r),currentlyAddingScript="\
  "null,r;if(isWebWorker)try{setTimeout((function(){}),0),import"\
  "Scripts(i),e.completeLoad(t)}catch(r){e.onError(makeError(\"im"\
  "portscripts\",\"importScripts failed for \"+t+\" at \"+i,r,[t]))}}"\
  ",isBrowser&&!cfg.skipDataMain&&eachReverse(scripts(),(functio"\
  "n(e){if(head=head||e.parentNode,dataMain=e.getAttribute(\"data"\
  "-main\"))return mainScript=dataMain,cfg.baseUrl||-1!==mainScri"\
  "pt.indexOf(\"!\")||(mainScript=(src=mainScript.split(\"/\")).pop("\
  "),subPath=src.length?src.join(\"/\")+\"/\":\"./\",cfg.baseUrl=subPa"\
  "th),mainScript=mainScript.replace(jsSuffixRegExp,\"\"),req.jsEx"\
  "tRegExp.test(mainScript)&&(mainScript=dataMain),cfg.deps=cfg."\
  "deps?cfg.deps.concat(mainScript):[mainScript],!0})),define=fu"\
  "nction(e,t,i){var r,n;\"string\"!=typeof e&&(i=t,t=e,e=null),is"\
  "Array(t)||(i=t,t=null),!t&&isFunction(i)&&(t=[],i.length)&&(i"\
  ".toString().replace(commentRegExp,commentReplace).replace(cjs"\
  "RequireRegExp,(function(e,i){t.push(i)})),t=(1===i.length?[\"r"\
  "equire\"]:[\"require\",\"exports\",\"module\"]).concat(t)),useIntera"\
  "ctive&&(r=currentlyAddingScript||getInteractiveScript())&&(e="\
  "e||r.getAttribute(\"data-requiremodule\"),n=contexts[r.getAttri"\
  "bute(\"data-requirecontext\")]),n?(n.defQueue.push([e,t,i]),n.d"\
  "efQueueMap[e]=!0):globalDefQueue.push([e,t,i])},define.amd={j"\
  "Query:!0},req.exec=function(text){return eval(text)},req(cfg)"\
  "}function newContext(e){var t,i,r,n,o,a={waitSeconds:7,baseUr"\
  "l:\"./\",paths:{},bundles:{},pkgs:{},shim:{},config:{}},s={},u="\
  "{},c={},d=[],p={},f={},l={},h=1,m=1;function g(e,t,i){var r,n"\
  ",o,s,u,c,d,p,f,l=t&&t.split(\"/\"),h=a.map,m=h&&h[\"*\"];if(e&&(t"\
  "=(e=e.split(\"/\")).length-1,a.nodeIdCompat&&jsSuffixRegExp.tes"\
  "t(e[t])&&(e[t]=e[t].replace(jsSuffixRegExp,\"\")),function(e){f"\
  "or(var t,i=0;i<e.length;i++)if(\".\"===(t=e[i]))e.splice(i,1),-"\
  "-i;else if(\"..\"===t){if(0===i||1===i&&\"..\"===e[2]||\"..\"===e[i"\
  "-1])continue;0<i&&(e.splice(i-1,2),i-=2)}}(e=\".\"===e[0].charA"\
  "t(0)&&l?l.slice(0,l.length-1).concat(e):e),e=e.join(\"/\")),i&&"\
  "h&&(l||m)){e:for(o=(n=e.split(\"/\")).length;0<o;--o){if(u=n.sl"\
  "ice(0,o).join(\"/\"),l)for(s=l.length;0<s;--s)if(r=(r=getOwn(h,"\
  "l.slice(0,s).join(\"/\")))&&getOwn(r,u)){c=r,d=o;break e}!p&&m&"\
  "&getOwn(m,u)&&(p=getOwn(m,u),f=o)}!c&&p&&(c=p,d=f),c&&(n.spli"\
  "ce(0,d,c),e=n.join(\"/\"))}return getOwn(a.pkgs,e)||e}function "\
  "x(e){isBrowser&&each(scripts(),(function(t){if(t.getAttribute"\
  "(\"data-requiremodule\")===e&&t.getAttribute(\"data-requireconte"\
  "xt\")===r.contextName)return t.parentNode.removeChild(t),!0}))"\
  "}function b(e){var t=getOwn(a.paths,e);return t&&isArray(t)&&"\
  "1<t.length&&(t.shift(),r.require.undef(e),r.makeRequire(null,"\
  "{skipMap:!0})([e]),1)}function v(e){var t,i=e?e.indexOf(\"!\"):"\
  "-1;return-1<i&&(t=e.substring(0,i),e=e.substring(i+1,e.length"\
  ")),[t,e]}function q(e,t,i,n){var o,a,s,u=null,c=t?t.name:null"\
  ",d=e,f=!0,l=\"\";return e||(f=!1,e=\"_@r\"+(h+=1)),u=(s=v(e))[0],"\
  "e=s[1],u&&(u=g(u,c,n),a=getOwn(p,u)),e&&(u?l=i?e:a&&a.normali"\
  "ze?a.normalize(e,(function(e){return g(e,c,n)})):-1===e.index"\
  "Of(\"!\")?g(e,c,n):e:(u=(s=v(l=g(e,c,n)))[0],l=s[1],i=!0,o=r.na"\
  "meToUrl(l))),{prefix:u,name:l,parentMap:t,unnormalized:!!(e=!"\
  "u||a||i?\"\":\"_unnormalized\"+(m+=1)),url:o,originalName:d,isDef"\
  "ine:f,id:(u?u+\"!\"+l:l)+e}}function E(e){var t=e.id;return get"\
  "Own(s,t)||(s[t]=new r.Module(e))}function w(e,t,i){var r=e.id"\
  ",n=getOwn(s,r);!hasProp(p,r)||n&&!n.defineEmitComplete?(n=E(e"\
  ")).error&&\"error\"===t?i(n.error):n.on(t,i):\"defined\"===t&&i(p"\
  "[r])}function y(e,t){var i=e.requireModules,r=!1;t?t(e):(each"\
  "(i,(function(t){(t=getOwn(s,t))&&(t.error=e,t.events.error)&&"\
  "(r=!0,t.emit(\"error\",e))})),r||req.onError(e))}function S(){g"\
  "lobalDefQueue.length&&(each(globalDefQueue,(function(e){var t"\
  "=e[0];\"string\"==typeof t&&(r.defQueueMap[t]=!0),d.push(e)})),"\
  "globalDefQueue=[])}function k(e){delete s[e],delete u[e]}func"\
  "tion M(e,t,i){var r=e.map.id;e.error?e.emit(\"error\",e.error):"\
  "(t[r]=!0,each(e.depMaps,(function(r,n){r=r.id;var o=getOwn(s,"\
  "r);!o||e.depMatched[n]||i[r]||(getOwn(t,r)?(e.defineDep(n,p[r"\
  "]),e.check()):M(o,t,i))})),i[r]=!0)}function O(){var e,i=1e3*"\
  "a.waitSeconds,n=i&&r.startTime+i<(new Date).getTime(),s=[],c="\
  "[],d=!1,p=!0;if(!t){if(t=!0,eachProp(u,(function(t){var i=t.m"\
  "ap,r=i.id;if(t.enabled&&(i.isDefine||c.push(t),!t.error))if(!"\
  "t.inited&&n)b(r)?d=e=!0:(s.push(r),x(r));else if(!t.inited&&t"\
  ".fetched&&i.isDefine&&(d=!0,!i.prefix))return p=!1})),n&&s.le"\
  "ngth)return(i=makeError(\"timeout\",\"Load timeout for modules: "\
  "\"+s,null,s)).contextName=r.contextName,y(i);p&&each(c,(functi"\
  "on(e){M(e,{},{})})),n&&!e||!d||!isBrowser&&!isWebWorker||(o=o"\
  "||setTimeout((function(){o=0,O()}),50)),t=!1}}function j(e){h"\
  "asProp(p,e[0])||E(q(e[0],null,!0)).init(e[1],e[2])}function P"\
  "(e,t,i,r){e.detachEvent&&!isOpera?r&&e.detachEvent(r,t):e.rem"\
  "oveEventListener(i,t,!1)}function R(e){return P(e=e.currentTa"\
  "rget||e.srcElement,r.onScriptLoad,\"load\",\"onreadystatechange\""\
  "),P(e,r.onScriptError,\"error\"),{node:e,id:e&&e.getAttribute(\""\
  "data-requiremodule\")}}function T(){var e;for(S();d.length;){i"\
  "f(null===(e=d.shift())[0])return y(makeError(\"mismatch\",\"Mism"\
  "atched anonymous define() module: \"+e[e.length-1]));j(e)}r.de"\
  "fQueueMap={}}return n={require:function(e){return e.require||"\
  "(e.require=r.makeRequire(e.map))},exports:function(e){if(e.us"\
  "ingExports=!0,e.map.isDefine)return e.exports?p[e.map.id]=e.e"\
  "xports:e.exports=p[e.map.id]={}},module:function(e){return e."\
  "module||(e.module={id:e.map.id,uri:e.map.url,config:function("\
  "){return getOwn(a.config,e.map.id)||{}},exports:e.exports||(e"\
  ".exports={})})}},(i=function(e){this.events=getOwn(c,e.id)||{"\
  "},this.map=e,this.shim=getOwn(a.shim,e.id),this.depExports=[]"\
  ",this.depMaps=[],this.depMatched=[],this.pluginMaps={},this.d"\
  "epCount=0}).prototype={init:function(e,t,i,r){r=r||{},this.in"\
  "ited||(this.factory=t,i?this.on(\"error\",i):this.events.error&"\
  "&(i=bind(this,(function(e){this.emit(\"error\",e)}))),this.depM"\
  "aps=e&&e.slice(0),this.errback=i,this.inited=!0,this.ignore=r"\
  ".ignore,r.enabled||this.enabled?this.enable():this.check())},"\
  "defineDep:function(e,t){this.depMatched[e]||(this.depMatched["\
  "e]=!0,--this.depCount,this.depExports[e]=t)},fetch:function()"\
  "{if(!this.fetched){this.fetched=!0,r.startTime=(new Date).get"\
  "Time();var e=this.map;if(!this.shim)return e.prefix?this.call"\
  "Plugin():this.load();r.makeRequire(this.map,{enableBuildCallb"\
  "ack:!0})(this.shim.deps||[],bind(this,(function(){return e.pr"\
  "efix?this.callPlugin():this.load()})))}},load:function(){var "\
  "e=this.map.url;f[e]||(f[e]=!0,r.load(this.map.id,e))},check:f"\
  "unction(){if(this.enabled&&!this.enabling){var e,t,i,n=this.m"\
  "ap.id,o=this.depExports,a=this.exports,s=this.factory;if(this"\
  ".inited){if(this.error)this.emit(\"error\",this.error);else if("\
  "!this.defining){if(this.defining=!0,this.depCount<1&&!this.de"\
  "fined){if(isFunction(s)){if(this.events.error&&this.map.isDef"\
  "ine||req.onError!==defaultOnError)try{a=r.execCb(n,s,o,a)}cat"\
  "ch(t){e=t}else a=r.execCb(n,s,o,a);if(this.map.isDefine&&void"\
  " 0===a&&((t=this.module)?a=t.exports:this.usingExports&&(a=th"\
  "is.exports)),e)return e.requireMap=this.map,e.requireModules="\
  "this.map.isDefine?[this.map.id]:null,e.requireType=this.map.i"\
  "sDefine?\"define\":\"require\",y(this.error=e)}else a=s;this.expo"\
  "rts=a,this.map.isDefine&&!this.ignore&&(p[n]=a,req.onResource"\
  "Load)&&(i=[],each(this.depMaps,(function(e){i.push(e.normaliz"\
  "edMap||e)})),req.onResourceLoad(r,this.map,i)),k(n),this.defi"\
  "ned=!0}this.defining=!1,this.defined&&!this.defineEmitted&&(t"\
  "his.defineEmitted=!0,this.emit(\"defined\",this.exports),this.d"\
  "efineEmitComplete=!0)}}else hasProp(r.defQueueMap,n)||this.fe"\
  "tch()}},callPlugin:function(){var e=this.map,t=e.id,i=q(e.pre"\
  "fix);this.depMaps.push(i),w(i,\"defined\",bind(this,(function(i"\
  "){var n,o,u=getOwn(l,this.map.id),c=this.map.name,d=this.map."\
  "parentMap?this.map.parentMap.name:null,p=r.makeRequire(e.pare"\
  "ntMap,{enableBuildCallback:!0});return this.map.unnormalized?"\
  "(i.normalize&&(c=i.normalize(c,(function(e){return g(e,d,!0)}"\
  "))||\"\"),w(o=q(e.prefix+\"!\"+c,this.map.parentMap,!0),\"defined\""\
  ",bind(this,(function(e){this.map.normalizedMap=o,this.init([]"\
  ",(function(){return e}),null,{enabled:!0,ignore:!0})}))),void"\
  "((c=getOwn(s,o.id))&&(this.depMaps.push(o),this.events.error&"\
  "&c.on(\"error\",bind(this,(function(e){this.emit(\"error\",e)})))"\
  ",c.enable()))):u?(this.map.url=r.nameToUrl(u),void this.load("\
  ")):((n=bind(this,(function(e){this.init([],(function(){return"\
  " e}),null,{enabled:!0})}))).error=bind(this,(function(e){this"\
  ".inited=!0,(this.error=e).requireModules=[t],eachProp(s,(func"\
  "tion(e){0===e.map.id.indexOf(t+\"_unnormalized\")&&k(e.map.id)}"\
  ")),y(e)})),n.fromText=bind(this,(function(i,o){var s=e.name,u"\
  "=q(s),c=useInteractive;o&&(i=o),c&&(useInteractive=!1),E(u),h"\
  "asProp(a.config,t)&&(a.config[s]=a.config[t]);try{req.exec(i)"\
  "}catch(e){return y(makeError(\"fromtexteval\",\"fromText eval fo"\
  "r \"+t+\" failed: \"+e,e,[t]))}c&&(useInteractive=!0),this.depMa"\
  "ps.push(u),r.completeLoad(s),p([s],n)})),void i.load(e.name,p"\
  ",n,a))}))),r.enable(i,this),this.pluginMaps[i.id]=i},enable:f"\
  "unction(){(u[this.map.id]=this).enabled=!0,this.enabling=!0,e"\
  "ach(this.depMaps,bind(this,(function(e,t){var i,o;if(\"string\""\
  "==typeof e){if(e=q(e,this.map.isDefine?this.map:this.map.pare"\
  "ntMap,!1,!this.skipMap),this.depMaps[t]=e,o=getOwn(n,e.id))re"\
  "turn void(this.depExports[t]=o(this));this.depCount+=1,w(e,\"d"\
  "efined\",bind(this,(function(e){this.undefed||(this.defineDep("\
  "t,e),this.check())}))),this.errback?w(e,\"error\",bind(this,thi"\
  "s.errback)):this.events.error&&w(e,\"error\",bind(this,(functio"\
  "n(e){this.emit(\"error\",e)})))}o=e.id,i=s[o],hasProp(n,o)||!i|"\
  "|i.enabled||r.enable(e,this)}))),eachProp(this.pluginMaps,bin"\
  "d(this,(function(e){var t=getOwn(s,e.id);t&&!t.enabled&&r.ena"\
  "ble(e,this)}))),this.enabling=!1,this.check()},on:function(e,"\
  "t){(this.events[e]||(this.events[e]=[])).push(t)},emit:functi"\
  "on(e,t){each(this.events[e],(function(e){e(t)})),\"error\"===e&"\
  "&delete this.events[e]}},(r={config:a,contextName:e,registry:"\
  "s,defined:p,urlFetched:f,defQueue:d,defQueueMap:{},Module:i,m"\
  "akeModuleMap:q,nextTick:req.nextTick,onError:y,configure:func"\
  "tion(e){e.baseUrl&&\"/\"!==e.baseUrl.charAt(e.baseUrl.length-1)"\
  "&&(e.baseUrl+=\"/\"),\"string\"==typeof e.urlArgs&&(t=e.urlArgs,e"\
  ".urlArgs=function(e,i){return(-1===i.indexOf(\"?\")?\"?\":\"&\")+t}"\
  ");var t,i=a.shim,n={paths:!0,bundles:!0,config:!0,map:!0};eac"\
  "hProp(e,(function(e,t){n[t]?(a[t]||(a[t]={}),mixin(a[t],e,!0,"\
  "!0)):a[t]=e})),e.bundles&&eachProp(e.bundles,(function(e,t){e"\
  "ach(e,(function(e){e!==t&&(l[e]=t)}))})),e.shim&&(eachProp(e."\
  "shim,(function(e,t){!(e=isArray(e)?{deps:e}:e).exports&&!e.in"\
  "it||e.exportsFn||(e.exportsFn=r.makeShimExports(e)),i[t]=e}))"\
  ",a.shim=i),e.packages&&each(e.packages,(function(e){var t=(e="\
  "\"string\"==typeof e?{name:e}:e).name;e.location&&(a.paths[t]=e"\
  ".location),a.pkgs[t]=e.name+\"/\"+(e.main||\"main\").replace(curr"\
  "DirRegExp,\"\").replace(jsSuffixRegExp,\"\")})),eachProp(s,(funct"\
  "ion(e,t){e.inited||e.map.unnormalized||(e.map=q(t,null,!0))})"\
  "),(e.deps||e.callback)&&r.require(e.deps||[],e.callback)},mak"\
  "eShimExports:function(e){return function(){var t;return(t=e.i"\
  "nit?e.init.apply(global,arguments):t)||e.exports&&getGlobal(e"\
  ".exports)}},makeRequire:function(t,i){function o(a,u,c){var d"\
  ",f;return i.enableBuildCallback&&u&&isFunction(u)&&(u.__requi"\
  "reJsBuild=!0),\"string\"==typeof a?isFunction(u)?y(makeError(\"r"\
  "equireargs\",\"Invalid require call\"),c):t&&hasProp(n,a)?n[a](s"\
  "[t.id]):req.get?req.get(r,a,t,o):(d=q(a,t,!1,!0).id,hasProp(p"\
  ",d)?p[d]:y(makeError(\"notloaded\",'Module name \"'+d+'\" has not"\
  " been loaded yet for context: '+e+(t?\"\":\". Use require([])\"))"\
  ")):(T(),r.nextTick((function(){T(),(f=E(q(null,t))).skipMap=i"\
  ".skipMap,f.init(a,u,c,{enabled:!0}),O()})),o)}return i=i||{},"\
  "mixin(o,{isBrowser:isBrowser,toUrl:function(e){var i,n=e.last"\
  "IndexOf(\".\"),o=e.split(\"/\")[0];return-1!==n&&(\".\"!==o&&\"..\"!="\
  "=o||1<n)&&(i=e.substring(n,e.length),e=e.substring(0,n)),r.na"\
  "meToUrl(g(e,t&&t.id,!0),i,!0)},defined:function(e){return has"\
  "Prop(p,q(e,t,!1,!0).id)},specified:function(e){return e=q(e,t"\
  ",!1,!0).id,hasProp(p,e)||hasProp(s,e)}}),t||(o.undef=function"\
  "(e){S();var i=q(e,t,!0),n=getOwn(s,e);n.undefed=!0,x(e),delet"\
  "e p[e],delete f[i.url],delete c[e],eachReverse(d,(function(t,"\
  "i){t[0]===e&&d.splice(i,1)})),delete r.defQueueMap[e],n&&(n.e"\
  "vents.defined&&(c[e]=n.events),k(e))}),o},enable:function(e){"\
  "getOwn(s,e.id)&&E(e).enable()},completeLoad:function(e){var t"\
  ",i,n,o=getOwn(a.shim,e)||{},u=o.exports;for(S();d.length;){if"\
  "(null===(i=d.shift())[0]){if(i[0]=e,t)break;t=!0}else i[0]==="\
  "e&&(t=!0);j(i)}if(r.defQueueMap={},n=getOwn(s,e),!t&&!hasProp"\
  "(p,e)&&n&&!n.inited){if(!(!a.enforceDefine||u&&getGlobal(u)))"\
  "return b(e)?void 0:y(makeError(\"nodefine\",\"No define call for"\
  " \"+e,null,[e]));j([e,o.deps||[],o.exportsFn])}O()},nameToUrl:"\
  "function(e,t,i){var n,o,s,u,c,d=getOwn(a.pkgs,e);if(d=getOwn("\
  "l,e=d||e))return r.nameToUrl(d,t,i);if(req.jsExtRegExp.test(e"\
  "))u=e+(t||\"\");else{for(n=a.paths,s=(o=e.split(\"/\")).length;0<"\
  "s;--s)if(c=getOwn(n,o.slice(0,s).join(\"/\"))){isArray(c)&&(c=c"\
  "[0]),o.splice(0,s,c);break}u=o.join(\"/\"),u=(\"/\"===(u+=t||(/^d"\
  "ata\\:|^blob\\:|\\?/.test(u)||i?\"\":\".js\")).charAt(0)||u.match(/^"\
  "[\\w\\+\\.\\-]+:/)?\"\":a.baseUrl)+u}return a.urlArgs&&!/^blob\\:/.t"\
  "est(u)?u+a.urlArgs(e,u):u},load:function(e,t){req.load(r,e,t)"\
  "},execCb:function(e,t,i,r){return t.apply(r,i)},onScriptLoad:"\
  "function(e){\"load\"!==e.type&&!readyRegExp.test((e.currentTarg"\
  "et||e.srcElement).readyState)||(interactiveScript=null,e=R(e)"\
  ",r.completeLoad(e.id))},onScriptError:function(e){var t,i=R(e"\
  ");if(!b(i.id))return t=[],eachProp(s,(function(e,r){0!==r.ind"\
  "exOf(\"_@r\")&&each(e.depMaps,(function(e){if(e.id===i.id)retur"\
  "n t.push(r),!0}))})),y(makeError(\"scripterror\",'Script error "\
  "for \"'+i.id+(t.length?'\", needed by: '+t.join(\", \"):'\"'),e,[i"\
  ".id]))}}).require=r.makeRequire(),r}function getInteractiveSc"\
  "ript(){return interactiveScript&&\"interactive\"===interactiveS"\
  "cript.readyState||eachReverse(scripts(),(function(e){if(\"inte"\
  "ractive\"===e.readyState)return interactiveScript=e})),interac"\
  "tiveScript}}(this,\"undefined\"==typeof setTimeout?void 0:setTi"\
  "meout);\n";
