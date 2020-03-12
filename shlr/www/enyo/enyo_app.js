
// enyo.js

(function() {
var e = "enyo.js";
enyo = window.enyo || {}, enyo.locateScript = function(e) {
var t = document.getElementsByTagName("script");
for (var n = t.length - 1, r, i, s = e.length; n >= 0 && (r = t[n]); n--) if (!r.located) {
i = r.getAttribute("src") || "";
if (i.slice(-s) == e) return r.located = !0, {
path: i.slice(0, Math.max(0, i.lastIndexOf("/"))),
node: r
};
}
}, enyo.args = enyo.args || {};
var t = enyo.locateScript(e);
if (t) {
enyo.args.root = (enyo.args.root || t.path).replace("/source", "");
for (var n = 0, r = t.node.attributes.length, i; n < r && (i = t.node.attributes.item(n)); n++) enyo.args[i.nodeName] = i.value;
}
})();

// ../../loader.js

(function() {
enyo = window.enyo || {}, enyo.pathResolverFactory = function() {
this.paths = {};
}, enyo.pathResolverFactory.prototype = {
addPath: function(e, t) {
return this.paths[e] = t;
},
addPaths: function(e) {
if (e) for (var t in e) this.addPath(t, e[t]);
},
includeTrailingSlash: function(e) {
return e && e.slice(-1) !== "/" ? e + "/" : e;
},
rewritePattern: /\$([^\/\\]*)(\/)?/g,
rewrite: function(e) {
var t, n = this.includeTrailingSlash, r = this.paths, i = function(e, i) {
return t = !0, n(r[i]) || "";
}, s = e;
do t = !1, s = s.replace(this.rewritePattern, i); while (t);
return s;
}
}, enyo.path = new enyo.pathResolverFactory, enyo.loaderFactory = function(e, t) {
this.machine = e, this.packages = [], this.modules = [], this.sheets = [], this.stack = [], this.pathResolver = t || enyo.path, this.packageName = "", this.packageFolder = "", this.finishCallbacks = {};
}, enyo.loaderFactory.prototype = {
verbose: !1,
loadScript: function(e) {
this.machine.script(e);
},
loadSheet: function(e) {
this.machine.sheet(e);
},
loadPackage: function(e) {
this.machine.script(e);
},
report: function() {},
load: function() {
this.more({
index: 0,
depends: arguments || []
});
},
more: function(e) {
if (e && this.continueBlock(e)) return;
var t = this.stack.pop();
t ? (this.verbose && console.groupEnd("* finish package (" + (t.packageName || "anon") + ")"), this.packageFolder = t.folder, this.packageName = "", this.more(t)) : this.finish();
},
finish: function() {
this.packageFolder = "", this.verbose && console.log("-------------- fini");
for (var e in this.finishCallbacks) this.finishCallbacks[e] && (this.finishCallbacks[e](), this.finishCallbacks[e] = null);
},
continueBlock: function(e) {
while (e.index < e.depends.length) {
var t = e.depends[e.index++];
if (t) if (typeof t == "string") {
if (this.require(t, e)) return !0;
} else this.pathResolver.addPaths(t);
}
},
require: function(e, t) {
var n = this.pathResolver.rewrite(e), r = this.getPathPrefix(e);
n = r + n;
if (n.slice(-4) == ".css" || n.slice(-5) == ".less") this.verbose && console.log("+ stylesheet: [" + r + "][" + e + "]"), this.requireStylesheet(n); else {
if (n.slice(-3) != ".js" || n.slice(-10) == "package.js") return this.requirePackage(n, t), !0;
this.verbose && console.log("+ module: [" + r + "][" + e + "]"), this.requireScript(e, n);
}
},
getPathPrefix: function(e) {
var t = e.slice(0, 1);
return t != "/" && t != "\\" && t != "$" && !/^https?:/i.test(e) ? this.packageFolder : "";
},
requireStylesheet: function(e) {
this.sheets.push(e), this.loadSheet(e);
},
requireScript: function(e, t) {
this.modules.push({
packageName: this.packageName,
rawPath: e,
path: t
}), this.loadScript(t);
},
decodePackagePath: function(e) {
var t = "", n = "", r = "", i = "package.js", s = e.replace(/\\/g, "/").replace(/\/\//g, "/").replace(/:\//, "://").split("/"), o, u;
if (s.length) {
var a = s.pop() || s.pop() || "";
a.slice(-i.length) !== i ? s.push(a) : i = a, r = s.join("/"), r = r ? r + "/" : "", i = r + i;
for (o = s.length - 1; o >= 0; o--) if (s[o] == "source") {
s.splice(o, 1);
break;
}
n = s.join("/");
for (o = s.length - 1; u = s[o]; o--) if (u == "lib" || u == "enyo") {
s = s.slice(o + 1);
break;
}
for (o = s.length - 1; u = s[o]; o--) (u == ".." || u == ".") && s.splice(o, 1);
t = s.join("-");
}
return {
alias: t,
target: n,
folder: r,
manifest: i
};
},
aliasPackage: function(e) {
var t = this.decodePackagePath(e);
this.manifest = t.manifest, t.alias && (this.pathResolver.addPath(t.alias, t.target), this.packageName = t.alias, this.packages.push({
name: t.alias,
folder: t.folder
})), this.packageFolder = t.folder;
},
requirePackage: function(e, t) {
t.folder = this.packageFolder, this.aliasPackage(e), t.packageName = this.packageName, this.stack.push(t), this.report("loading package", this.packageName), this.verbose && console.group("* start package [" + this.packageName + "]"), this.loadPackage(this.manifest);
}
};
})();

// boot.js

enyo.execUnsafeLocalFunction = function(e) {
typeof MSApp == "undefined" ? e() : MSApp.execUnsafeLocalFunction(e);
}, enyo.machine = {
sheet: function(e) {
var t = "text/css", n = "stylesheet", r = e.slice(-5) == ".less";
r && (window.less ? (t = "text/less", n = "stylesheet/less") : e = e.slice(0, e.length - 4) + "css");
var i;
enyo.runtimeLoading || r ? (i = document.createElement("link"), i.href = e, i.media = "screen", i.rel = n, i.type = t, document.getElementsByTagName("head")[0].appendChild(i)) : (i = function() {
document.write('<link href="' + e + '" media="screen" rel="' + n + '" type="' + t + '" />');
}, enyo.execUnsafeLocalFunction(i)), r && window.less && (less.sheets.push(i), enyo.loader.finishCallbacks.lessRefresh || (enyo.loader.finishCallbacks.lessRefresh = function() {
less.refresh(!0);
}));
},
script: function(e, t, n) {
if (!enyo.runtimeLoading) document.write('<script src="' + e + '"' + (t ? ' onload="' + t + '"' : "") + (n ? ' onerror="' + n + '"' : "") + "></scri" + "pt>"); else {
var r = document.createElement("script");
r.src = e, r.onload = t, r.onerror = n, document.getElementsByTagName("head")[0].appendChild(r);
}
},
inject: function(e) {
document.write('<script type="text/javascript">' + e + "</scri" + "pt>");
}
}, enyo.loader = new enyo.loaderFactory(enyo.machine), enyo.depends = function() {
var e = enyo.loader;
if (!e.packageFolder) {
var t = enyo.locateScript("package.js");
t && t.path && (e.aliasPackage(t.path), e.packageFolder = t.path + "/");
}
e.load.apply(e, arguments);
}, function() {
function n(r) {
r && r();
if (t.length) {
var i = t.shift(), s = i[0], o = e.isArray(s) ? s : [ s ], u = i[1];
e.loader.finishCallbacks.runtimeLoader = function() {
n(function() {
u && u(s);
});
}, e.loader.packageFolder = "./", e.depends.apply(this, o);
} else e.runtimeLoading = !1, e.loader.packageFolder = "";
}
var e = window.enyo, t = [];
e.load = function(r, i) {
t.push(arguments), e.runtimeLoading || (e.runtimeLoading = !0, n());
};
}(), enyo.path.addPaths({
enyo: enyo.args.root,
lib: "$enyo/../lib"
});

// log.js

enyo.logging = {
level: 99,
levels: {
log: 20,
warn: 10,
error: 0
},
shouldLog: function(e) {
var t = parseInt(this.levels[e], 0);
return t <= this.level;
},
_log: function(e, t) {
if (typeof console == "undefined") return;
var n = enyo.isArray(t) ? t : enyo.cloneArray(t);
enyo.dumbConsole && (n = [ n.join(" ") ]);
var r = console[e];
r && r.apply ? r.apply(console, n) : console.log.apply ? console.log.apply(console, n) : console.log(n.join(" "));
},
log: function(e, t) {
typeof console != "undefined" && this.shouldLog(e) && this._log(e, t);
}
}, enyo.setLogLevel = function(e) {
var t = parseInt(e, 0);
isFinite(t) && (enyo.logging.level = t);
}, enyo.log = function() {
enyo.logging.log("log", arguments);
}, enyo.warn = function() {
enyo.logging.log("warn", arguments);
}, enyo.error = function() {
enyo.logging.log("error", arguments);
};

// lang.js

(function() {
enyo.global = this, enyo._getProp = function(e, t, n) {
var r = n || enyo.global;
for (var i = 0, s; r && (s = e[i]); i++) r = s in r ? r[s] : t ? r[s] = {} : undefined;
return r;
}, enyo.setObject = function(e, t, n) {
var r = e.split("."), i = r.pop(), s = enyo._getProp(r, !0, n);
return s && i ? s[i] = t : undefined;
}, enyo.getObject = function(e, t, n) {
return enyo._getProp(e.split("."), t, n);
}, enyo.irand = function(e) {
return Math.floor(Math.random() * e);
}, enyo.cap = function(e) {
return e.slice(0, 1).toUpperCase() + e.slice(1);
}, enyo.uncap = function(e) {
return e.slice(0, 1).toLowerCase() + e.slice(1);
}, enyo.format = function(e) {
var t = /\%./g, n = 0, r = e, i = arguments, s = function(e) {
return i[++n];
};
return r.replace(t, s);
};
var e = Object.prototype.toString;
enyo.isString = function(t) {
return e.call(t) === "[object String]";
}, enyo.isFunction = function(t) {
return e.call(t) === "[object Function]";
}, enyo.isArray = Array.isArray || function(t) {
return e.call(t) === "[object Array]";
}, enyo.isTrue = function(e) {
return e !== "false" && e !== !1 && e !== 0 && e !== null && e !== undefined;
}, enyo.indexOf = function(e, t, n) {
if (t.indexOf) return t.indexOf(e, n);
if (n) {
n < 0 && (n = 0);
if (n > t.length) return -1;
}
for (var r = n || 0, i = t.length, s; (s = t[r]) || r < i; r++) if (s == e) return r;
return -1;
}, enyo.remove = function(e, t) {
var n = enyo.indexOf(e, t);
n >= 0 && t.splice(n, 1);
}, enyo.forEach = function(e, t, n) {
if (e) {
var r = n || this;
if (enyo.isArray(e) && e.forEach) e.forEach(t, r); else {
var i = Object(e), s = i.length >>> 0;
for (var o = 0; o < s; o++) o in i && t.call(r, i[o], o, i);
}
}
}, enyo.map = function(e, t, n) {
var r = n || this;
if (enyo.isArray(e) && e.map) return e.map(t, r);
var i = [], s = function(e, n, s) {
i.push(t.call(r, e, n, s));
};
return enyo.forEach(e, s, r), i;
}, enyo.filter = function(e, t, n) {
var r = n || this;
if (enyo.isArray(e) && e.filter) return e.filter(t, r);
var i = [], s = function(e, n, s) {
var o = e;
t.call(r, e, n, s) && i.push(o);
};
return enyo.forEach(e, s, r), i;
}, enyo.keys = Object.keys || function(e) {
var t = [], n = Object.prototype.hasOwnProperty;
for (var r in e) n.call(e, r) && t.push(r);
if (!{
toString: null
}.propertyIsEnumerable("toString")) {
var i = [ "toString", "toLocaleString", "valueOf", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "constructor" ];
for (var s = 0, o; o = i[s]; s++) n.call(e, o) && t.push(o);
}
return t;
}, enyo.cloneArray = function(e, t, n) {
var r = n || [];
for (var i = t || 0, s = e.length; i < s; i++) r.push(e[i]);
return r;
}, enyo.toArray = enyo.cloneArray, enyo.clone = function(e) {
return enyo.isArray(e) ? enyo.cloneArray(e) : enyo.mixin({}, e);
};
var t = {};
enyo.mixin = function(e, n) {
e = e || {};
if (n) {
var r, i, s;
for (r in n) i = n[r], t[r] !== i && (e[r] = i);
}
return e;
}, enyo.bind = function(e, t) {
t || (t = e, e = null), e = e || enyo.global;
if (enyo.isString(t)) {
if (!e[t]) throw [ 'enyo.bind: scope["', t, '"] is null (scope="', e, '")' ].join("");
t = e[t];
}
if (enyo.isFunction(t)) {
var n = enyo.cloneArray(arguments, 2);
return t.bind ? t.bind.apply(t, [ e ].concat(n)) : function() {
var r = enyo.cloneArray(arguments);
return t.apply(e, n.concat(r));
};
}
throw [ 'enyo.bind: scope["', t, '"] is not a function (scope="', e, '")' ].join("");
}, enyo.asyncMethod = function(e, t) {
return setTimeout(enyo.bind.apply(enyo, arguments), 1);
}, enyo.call = function(e, t, n) {
var r = e || this;
if (t) {
var i = r[t] || t;
if (i && i.apply) return i.apply(r, n || []);
}
}, enyo.now = Date.now || function() {
return (new Date).getTime();
}, enyo.nop = function() {}, enyo.nob = {}, enyo.nar = [], enyo.instance = function() {}, enyo.setPrototype || (enyo.setPrototype = function(e, t) {
e.prototype = t;
}), enyo.delegate = function(e) {
return enyo.setPrototype(enyo.instance, e), new enyo.instance;
}, $L = function(e) {
return e;
};
})();

// job.js

enyo.job = function(e, t, n) {
enyo.job.stop(e), enyo.job._jobs[e] = setTimeout(function() {
enyo.job.stop(e), t();
}, n);
}, enyo.job.stop = function(e) {
enyo.job._jobs[e] && (clearTimeout(enyo.job._jobs[e]), delete enyo.job._jobs[e]);
}, enyo.job._jobs = {};

// macroize.js

enyo.macroize = function(e, t, n) {
var r, i, s = e, o = n || enyo.macroize.pattern, u = function(e, n) {
return r = enyo.getObject(n, !1, t), r === undefined || r === null ? "{$" + n + "}" : (i = !0, r);
}, a = 0;
do {
i = !1, s = s.replace(o, u);
if (++a >= 20) throw "enyo.macroize: recursion too deep";
} while (i);
return s;
}, enyo.quickMacroize = function(e, t, n) {
var r, i, s = e, o = n || enyo.macroize.pattern, u = function(e, n) {
return n in t ? r = t[n] : r = enyo.getObject(n, !1, t), r === undefined || r === null ? "{$" + n + "}" : r;
};
return s = s.replace(o, u), s;
}, enyo.macroize.pattern = /\{\$([^{}]*)\}/g;

// Oop.js

enyo.kind = function(e) {
enyo._kindCtors = {};
var t = e.name || "";
delete e.name;
var n = "kind" in e, r = e.kind;
delete e.kind;
var i = enyo.constructorForKind(r), s = i && i.prototype || null;
if (n && r === undefined || i === undefined) {
var o = r === undefined ? "undefined kind" : "unknown kind (" + r + ")";
throw "enyo.kind: Attempt to subclass an " + o + ". Check dependencies for [" + (t || "<unnamed>") + "].";
}
var u = enyo.kind.makeCtor();
return e.hasOwnProperty("constructor") && (e._constructor = e.constructor, delete e.constructor), enyo.setPrototype(u, s ? enyo.delegate(s) : {}), enyo.mixin(u.prototype, e), u.prototype.kindName = t, u.prototype.base = i, u.prototype.ctor = u, enyo.forEach(enyo.kind.features, function(t) {
t(u, e);
}), enyo.setObject(t, u), u;
}, enyo.singleton = function(e, t) {
var n = e.name;
delete e.name;
var r = enyo.kind(e);
enyo.setObject(n, new r, t);
}, enyo.kind.makeCtor = function() {
return function() {
if (!(this instanceof arguments.callee)) throw "enyo.kind: constructor called directly, not using 'new'";
var e;
this._constructor && (e = this._constructor.apply(this, arguments)), this.constructed && this.constructed.apply(this, arguments);
if (e) return e;
};
}, enyo.kind.defaultNamespace = "enyo", enyo.kind.features = [], enyo.kind.features.push(function(e, t) {
var n = e.prototype;
n.inherited || (n.inherited = enyo.kind.inherited);
if (n.base) for (var r in t) {
var i = t[r];
enyo.isFunction(i) && (i._inherited = n.base.prototype[r] || enyo.nop, i.nom = n.kindName + "." + r + "()");
}
}), enyo.kind.inherited = function(e, t) {
return e.callee._inherited.apply(this, t || e);
}, enyo.kind.features.push(function(e, t) {
enyo.mixin(e, enyo.kind.statics), t.statics && (enyo.mixin(e, t.statics), delete e.prototype.statics);
var n = e.prototype.base;
while (n) n.subclass(e, t), n = n.prototype.base;
}), enyo.kind.statics = {
subclass: function(e, t) {},
extend: function(e) {
enyo.mixin(this.prototype, e);
var t = this;
enyo.forEach(enyo.kind.features, function(n) {
n(t, e);
});
}
}, enyo._kindCtors = {}, enyo.constructorForKind = function(e) {
if (e === null || enyo.isFunction(e)) return e;
if (e) {
var t = enyo._kindCtors[e];
return t ? t : enyo._kindCtors[e] = enyo.Theme[e] || enyo[e] || enyo.getObject(e, !1, enyo) || window[e] || enyo.getObject(e);
}
return enyo.defaultCtor;
}, enyo.Theme = {}, enyo.registerTheme = function(e) {
enyo.mixin(enyo.Theme, e);
};

// Object.js

enyo.kind({
name: "enyo.Object",
kind: null,
constructor: function() {
enyo._objectCount++;
},
setPropertyValue: function(e, t, n) {
if (this[n]) {
var r = this[e];
this[e] = t, this[n](r);
} else this[e] = t;
},
_setProperty: function(e, t, n) {
this.setPropertyValue(e, t, this.getProperty(e) !== t && n);
},
destroyObject: function(e) {
this[e] && this[e].destroy && this[e].destroy(), this[e] = null;
},
getProperty: function(e) {
var t = "get" + enyo.cap(e);
return this[t] ? this[t]() : this[e];
},
setProperty: function(e, t) {
var n = "set" + enyo.cap(e);
this[n] ? this[n](t) : this._setProperty(e, t, e + "Changed");
},
log: function() {
var e = arguments.callee.caller, t = ((e ? e.nom : "") || "(instance method)") + ":";
enyo.logging.log("log", [ t ].concat(enyo.cloneArray(arguments)));
},
warn: function() {
this._log("warn", arguments);
},
error: function() {
this._log("error", arguments);
},
_log: function(e, t) {
if (enyo.logging.shouldLog(e)) try {
throw new Error;
} catch (n) {
enyo.logging._log(e, [ t.callee.caller.nom + ": " ].concat(enyo.cloneArray(t))), enyo.log(n.stack);
}
}
}), enyo._objectCount = 0, enyo.Object.subclass = function(e, t) {
this.publish(e, t);
}, enyo.Object.publish = function(e, t) {
var n = t.published;
if (n) {
var r = e.prototype;
for (var i in n) enyo.Object.addGetterSetter(i, n[i], r);
}
}, enyo.Object.addGetterSetter = function(e, t, n) {
var r = e;
n[r] = t;
var i = enyo.cap(r), s = "get" + i;
n[s] || (n[s] = function() {
return this[r];
});
var o = "set" + i, u = r + "Changed";
n[o] || (n[o] = function(e) {
this._setProperty(r, e, u);
});
};

// Component.js

enyo.kind({
name: "enyo.Component",
kind: enyo.Object,
published: {
name: "",
id: "",
owner: null
},
statics: {
_kindPrefixi: {},
_unnamedKindNumber: 0
},
defaultKind: "Component",
handlers: {},
toString: function() {
return this.kindName;
},
constructor: function() {
this._componentNameMap = {}, this.$ = {}, this.inherited(arguments);
},
constructed: function(e) {
this.importProps(e), this.create();
},
importProps: function(e) {
if (e) for (var t in e) this[t] = e[t];
this.handlers = enyo.mixin(enyo.clone(this.kindHandlers), this.handlers);
},
create: function() {
this.ownerChanged(), this.initComponents();
},
initComponents: function() {
this.createChrome(this.kindComponents), this.createClientComponents(this.components);
},
createChrome: function(e) {
this.createComponents(e, {
isChrome: !0
});
},
createClientComponents: function(e) {
this.createComponents(e, {
owner: this.getInstanceOwner()
});
},
getInstanceOwner: function() {
return !this.owner || this.owner.notInstanceOwner ? this : this.owner;
},
destroy: function() {
this.destroyComponents(), this.setOwner(null), this.destroyed = !0;
},
destroyComponents: function() {
enyo.forEach(this.getComponents(), function(e) {
e.destroyed || e.destroy();
});
},
makeId: function() {
var e = "_", t = this.owner && this.owner.getId(), n = this.name || "@@" + ++enyo.Component._unnamedKindNumber;
return (t ? t + e : "") + n;
},
ownerChanged: function(e) {
e && e.removeComponent(this), this.owner && this.owner.addComponent(this), this.id || (this.id = this.makeId());
},
nameComponent: function(e) {
var t = enyo.Component.prefixFromKindName(e.kindName), n, r = this._componentNameMap[t] || 0;
do n = t + (++r > 1 ? String(r) : ""); while (this.$[n]);
return this._componentNameMap[t] = Number(r), e.name = n;
},
addComponent: function(e) {
var t = e.getName();
t || (t = this.nameComponent(e)), this.$[t] && this.warn('Duplicate component name "' + t + '" in owner "' + this.id + '" violates ' + "unique-name-under-owner rule, replacing existing component in the hash and continuing, " + "but this is an error condition and should be fixed."), this.$[t] = e;
},
removeComponent: function(e) {
delete this.$[e.getName()];
},
getComponents: function() {
var e = [];
for (var t in this.$) e.push(this.$[t]);
return e;
},
adjustComponentProps: function(e) {
this.defaultProps && enyo.mixin(e, this.defaultProps), e.kind = e.kind || e.isa || this.defaultKind, e.owner = e.owner || this;
},
_createComponent: function(e, t) {
if (!e.kind && "kind" in e) throw "enyo.create: Attempt to create a null kind. Check dependencies for [" + e.name + "].";
var n = enyo.mixin(enyo.clone(t), e);
return this.adjustComponentProps(n), enyo.Component.create(n);
},
createComponent: function(e, t) {
return this._createComponent(e, t);
},
createComponents: function(e, t) {
if (e) {
var n = [];
for (var r = 0, i; i = e[r]; r++) n.push(this._createComponent(i, t));
return n;
}
},
getBubbleTarget: function() {
return this.owner;
},
bubble: function(e, t, n) {
var r = t || {};
return "originator" in r || (r.originator = n || this), this.dispatchBubble(e, r, n);
},
bubbleUp: function(e, t, n) {
var r = this.getBubbleTarget();
return r ? r.dispatchBubble(e, t, this) : !1;
},
dispatchEvent: function(e, t, n) {
this.decorateEvent(e, t, n);
if (this.handlers[e] && this.dispatch(this.handlers[e], t, n)) return !0;
if (this[e]) return this.bubbleDelegation(this.owner, this[e], e, t, this);
},
dispatchBubble: function(e, t, n) {
return this.dispatchEvent(e, t, n) ? !0 : this.bubbleUp(e, t, n);
},
decorateEvent: function(e, t, n) {},
bubbleDelegation: function(e, t, n, r, i) {
var s = this.getBubbleTarget();
if (s) return s.delegateEvent(e, t, n, r, i);
},
delegateEvent: function(e, t, n, r, i) {
return this.decorateEvent(n, r, i), e == this ? this.dispatch(t, r, i) : this.bubbleDelegation(e, t, n, r, i);
},
dispatch: function(e, t, n) {
var r = e && this[e];
if (r) return r.call(this, n || this, t);
},
waterfall: function(e, t, n) {
if (this.dispatchEvent(e, t, n)) return !0;
this.waterfallDown(e, t, n || this);
},
waterfallDown: function(e, t, n) {
for (var r in this.$) this.$[r].waterfall(e, t, n);
}
}), enyo.defaultCtor = enyo.Component, enyo.create = enyo.Component.create = function(e) {
if (!e.kind && "kind" in e) throw "enyo.create: Attempt to create a null kind. Check dependencies for [" + (e.name || "") + "].";
var t = e.kind || e.isa || enyo.defaultCtor, n = enyo.constructorForKind(t);
return n || (enyo.error('no constructor found for kind "' + t + '"'), n = enyo.Component), new n(e);
}, enyo.Component.subclass = function(e, t) {
var n = e.prototype;
t.components && (n.kindComponents = t.components, delete n.components);
if (t.handlers) {
var r = n.kindHandlers;
n.kindHandlers = enyo.mixin(enyo.clone(r), n.handlers), n.handlers = null;
}
t.events && this.publishEvents(e, t);
}, enyo.Component.publishEvents = function(e, t) {
var n = t.events;
if (n) {
var r = e.prototype;
for (var i in n) this.addEvent(i, n[i], r);
}
}, enyo.Component.addEvent = function(e, t, n) {
var r, i;
enyo.isString(t) ? (e.slice(0, 2) != "on" && (enyo.warn("enyo.Component.addEvent: event names must start with 'on'. " + n.kindName + " event '" + e + "' was auto-corrected to 'on" + e + "'."), e = "on" + e), r = t, i = "do" + enyo.cap(e.slice(2))) : (r = t.value, i = t.caller), n[e] = r, n[i] || (n[i] = function(t) {
return this.bubble(e, t);
});
}, enyo.Component.prefixFromKindName = function(e) {
var t = enyo.Component._kindPrefixi[e];
if (!t) {
var n = e.lastIndexOf(".");
t = n >= 0 ? e.slice(n + 1) : e, t = t.charAt(0).toLowerCase() + t.slice(1), enyo.Component._kindPrefixi[e] = t;
}
return t;
};

// UiComponent.js

enyo.kind({
name: "enyo.UiComponent",
kind: enyo.Component,
published: {
container: null,
parent: null,
controlParentName: "client",
layoutKind: ""
},
handlers: {
onresize: "resizeHandler"
},
addBefore: undefined,
statics: {
_resizeFlags: {
showingOnly: !0
}
},
create: function() {
this.controls = [], this.children = [], this.containerChanged(), this.inherited(arguments), this.layoutKindChanged();
},
destroy: function() {
this.destroyClientControls(), this.setContainer(null), this.inherited(arguments);
},
importProps: function(e) {
this.inherited(arguments), this.owner || (this.owner = enyo.master);
},
createComponents: function() {
var e = this.inherited(arguments);
return this.discoverControlParent(), e;
},
discoverControlParent: function() {
this.controlParent = this.$[this.controlParentName] || this.controlParent;
},
adjustComponentProps: function(e) {
e.container = e.container || this, this.inherited(arguments);
},
containerChanged: function(e) {
e && e.removeControl(this), this.container && this.container.addControl(this, this.addBefore);
},
parentChanged: function(e) {
e && e != this.parent && e.removeChild(this);
},
isDescendantOf: function(e) {
var t = this;
while (t && t != e) t = t.parent;
return e && t == e;
},
getControls: function() {
return this.controls;
},
getClientControls: function() {
var e = [];
for (var t = 0, n = this.controls, r; r = n[t]; t++) r.isChrome || e.push(r);
return e;
},
destroyClientControls: function() {
var e = this.getClientControls();
for (var t = 0, n; n = e[t]; t++) n.destroy();
},
addControl: function(e, t) {
this.controls.push(e), this.addChild(e, t);
},
removeControl: function(e) {
return e.setParent(null), enyo.remove(e, this.controls);
},
indexOfControl: function(e) {
return enyo.indexOf(e, this.controls);
},
indexOfClientControl: function(e) {
return enyo.indexOf(e, this.getClientControls());
},
indexInContainer: function() {
return this.container.indexOfControl(this);
},
clientIndexInContainer: function() {
return this.container.indexOfClientControl(this);
},
controlAtIndex: function(e) {
return this.controls[e];
},
addChild: function(e, t) {
if (this.controlParent) this.controlParent.addChild(e); else {
e.setParent(this);
if (t !== undefined) {
var n = t === null ? 0 : this.indexOfChild(t);
this.children.splice(n, 0, e);
} else this.children.push(e);
}
},
removeChild: function(e) {
return enyo.remove(e, this.children);
},
indexOfChild: function(e) {
return enyo.indexOf(e, this.children);
},
layoutKindChanged: function() {
this.layout && this.layout.destroy(), this.layout = enyo.createFromKind(this.layoutKind, this), this.generated && this.render();
},
flow: function() {
this.layout && this.layout.flow();
},
reflow: function() {
this.layout && this.layout.reflow();
},
resized: function() {
this.waterfall("onresize", enyo.UiComponent._resizeFlags), this.waterfall("onpostresize", enyo.UiComponent._resizeFlags);
},
resizeHandler: function() {
this.reflow();
},
waterfallDown: function(e, t, n) {
for (var r in this.$) this.$[r] instanceof enyo.UiComponent || this.$[r].waterfall(e, t, n);
for (var i = 0, s = this.children, o; o = s[i]; i++) (o.showing || !t || !t.showingOnly) && o.waterfall(e, t, n);
},
getBubbleTarget: function() {
return this.parent;
}
}), enyo.createFromKind = function(e, t) {
var n = e && enyo.constructorForKind(e);
if (n) return new n(t);
}, enyo.master = new enyo.Component({
name: "master",
notInstanceOwner: !0,
eventFlags: {
showingOnly: !0
},
getId: function() {
return "";
},
isDescendantOf: enyo.nop,
bubble: function(e, t, n) {
e == "onresize" ? (enyo.master.waterfallDown("onresize", this.eventFlags), enyo.master.waterfallDown("onpostresize", this.eventFlags)) : enyo.Signals.send(e, t);
}
});

// Layout.js

enyo.kind({
name: "enyo.Layout",
kind: null,
layoutClass: "",
constructor: function(e) {
this.container = e, e && e.addClass(this.layoutClass);
},
destroy: function() {
this.container && this.container.removeClass(this.layoutClass);
},
flow: function() {},
reflow: function() {}
});

// Signals.js

enyo.kind({
name: "enyo.Signals",
kind: enyo.Component,
create: function() {
this.inherited(arguments), enyo.Signals.addListener(this);
},
destroy: function() {
enyo.Signals.removeListener(this), this.inherited(arguments);
},
notify: function(e, t) {
this.dispatchEvent(e, t);
},
statics: {
listeners: [],
addListener: function(e) {
this.listeners.push(e);
},
removeListener: function(e) {
enyo.remove(e, this.listeners);
},
send: function(e, t) {
enyo.forEach(this.listeners, function(n) {
n.notify(e, t);
});
}
}
});

// Async.js

enyo.kind({
name: "enyo.Async",
kind: enyo.Object,
published: {
timeout: 0
},
failed: !1,
context: null,
constructor: function() {
this.responders = [], this.errorHandlers = [];
},
accumulate: function(e, t) {
var n = t.length < 2 ? t[0] : enyo.bind(t[0], t[1]);
e.push(n);
},
response: function() {
return this.accumulate(this.responders, arguments), this;
},
error: function() {
return this.accumulate(this.errorHandlers, arguments), this;
},
route: function(e, t) {
var n = enyo.bind(this, "respond");
e.response(function(e, t) {
n(t);
});
var r = enyo.bind(this, "fail");
e.error(function(e, t) {
r(t);
}), e.go(t);
},
handle: function(e, t) {
var n = t.shift();
if (n) if (n instanceof enyo.Async) this.route(n, e); else {
var r = enyo.call(this.context || this, n, [ this, e ]);
r = r !== undefined ? r : e, (this.failed ? this.fail : this.respond).call(this, r);
}
},
startTimer: function() {
this.startTime = enyo.now(), this.timeout && (this.timeoutJob = setTimeout(enyo.bind(this, "timeoutComplete"), this.timeout));
},
endTimer: function() {
this.timeoutJob && (this.endTime = enyo.now(), clearTimeout(this.timeoutJob), this.timeoutJob = null, this.latency = this.endTime - this.startTime);
},
timeoutComplete: function() {
this.timedout = !0, this.fail("timeout");
},
respond: function(e) {
this.failed = !1, this.endTimer(), this.handle(e, this.responders);
},
fail: function(e) {
this.failed = !0, this.endTimer(), this.handle(e, this.errorHandlers);
},
recover: function() {
this.failed = !1;
},
go: function(e) {
return enyo.asyncMethod(this, function() {
this.respond(e);
}), this;
}
});

// json.js

enyo.json = {
stringify: function(e, t, n) {
return JSON.stringify(e, t, n);
},
parse: function(e, t) {
return e ? JSON.parse(e, t) : null;
}
};

// cookie.js

enyo.getCookie = function(e) {
var t = document.cookie.match(new RegExp("(?:^|; )" + e + "=([^;]*)"));
return t ? decodeURIComponent(t[1]) : undefined;
}, enyo.setCookie = function(e, t, n) {
var r = e + "=" + encodeURIComponent(t), i = n || {}, s = i.expires;
if (typeof s == "number") {
var o = new Date;
o.setTime(o.getTime() + s * 24 * 60 * 60 * 1e3), s = o;
}
s && s.toUTCString && (i.expires = s.toUTCString());
var u, a;
for (u in i) r += "; " + u, a = i[u], a !== !0 && (r += "=" + a);
document.cookie = r;
};

// xhr.js

enyo.xhr = {
request: function(e) {
var t = this.getXMLHttpRequest(e), n = enyo.path.rewrite(this.simplifyFileURL(e.url)), r = e.method || "GET", i = !e.sync;
e.username ? t.open(r, n, i, e.username, e.password) : t.open(r, n, i), enyo.mixin(t, e.xhrFields), e.callback && this.makeReadyStateHandler(t, e.callback), e.headers = e.headers || {}, r !== "GET" && enyo.platform.ios && enyo.platform.ios >= 6 && e.headers["cache-control"] !== null && (e.headers["cache-control"] = e.headers["cache-control"] || "no-cache");
if (t.setRequestHeader) for (var s in e.headers) e.headers[s] && t.setRequestHeader(s, e.headers[s]);
return typeof t.overrideMimeType == "function" && e.mimeType && t.overrideMimeType(e.mimeType), t.send(e.body || null), !i && e.callback && t.onreadystatechange(t), t;
},
cancel: function(e) {
e.onload && (e.onload = null), e.onreadystatechange && (e.onreadystatechange = null), e.abort && e.abort();
},
makeReadyStateHandler: function(e, t) {
window.XDomainRequest && e instanceof XDomainRequest && (e.onload = function() {
var n;
typeof e.responseText == "string" && (n = e.responseText), t.apply(null, [ n, e ]);
}), e.onreadystatechange = function() {
if (e.readyState == 4) {
var n;
typeof e.responseText == "string" && (n = e.responseText), t.apply(null, [ n, e ]);
}
};
},
inOrigin: function(e) {
var t = document.createElement("a"), n = !1;
t.href = e;
if (t.protocol === ":" || t.protocol === window.location.protocol && t.hostname === window.location.hostname && t.port === (window.location.port || (window.location.protocol === "https:" ? "443" : "80"))) n = !0;
return n;
},
simplifyFileURL: function(e) {
var t = document.createElement("a"), n = !1;
return t.href = e, t.protocol === "file:" || t.protocol === ":" && window.location.protocol === "file:" ? t.protocol + "//" + t.host + t.pathname : t.protocol === ":" && window.location.protocol === "x-wmapp0:" ? window.location.protocol + "//" + window.location.pathname.split("/")[0] + "/" + t.host + t.pathname : e;
},
getXMLHttpRequest: function(e) {
try {
if (enyo.platform.ie < 10 && window.XDomainRequest && !e.headers && !this.inOrigin(e.url) && !/^file:\/\//.test(window.location.href)) return new XDomainRequest;
} catch (t) {}
try {
return new XMLHttpRequest;
} catch (t) {}
return null;
}
};

// formdata.js

(function(e) {
function i() {
this.fake = !0, this._fields = [], this.boundary = "--------------------------";
for (var e = 0; e < 24; e++) this.boundary += Math.floor(Math.random() * 10).toString(16);
}
function s(e, t) {
this.name = t.name, this.type = t.type || "application/octet-stream";
if (!enyo.isArray(e)) throw new Error("enyo.Blob only handles Arrays of Strings");
if (e.length > 0 && typeof e[0] != "string") throw new Error("enyo.Blob only handles Arrays of Strings");
this._bufs = e;
}
if (e.FormData) try {
var t = new e.FormData, n = new e.Blob;
enyo.FormData = e.FormData, enyo.Blob = e.Blob;
return;
} catch (r) {}
i.prototype.getContentType = function() {
return "multipart/form-data; boundary=" + this.boundary;
}, i.prototype.append = function(e, t, n) {
this._fields.push([ e, t, n ]);
}, i.prototype.toString = function() {
var e = this.boundary, t = "";
return enyo.forEach(this._fields, function(n) {
t += "--" + e + "\r\n";
if (n[2] || n[1].name) {
var r = n[1], i = n[2] || r.name;
t += 'Content-Disposition: form-data; name="' + n[0] + '"; filename="' + i + '"\r\n', t += "Content-Type: " + r.type + "\r\n\r\n", t += r.getAsBinary() + "\r\n";
} else t += 'Content-Disposition: form-data; name="' + n[0] + '";\r\n\r\n', t += n[1] + "\r\n";
}), t += "--" + e + "--", t;
}, enyo.FormData = i, s.prototype.getAsBinary = function() {
var e = "", t = e.concat.apply(e, this._bufs);
return t;
}, enyo.Blob = s;
})(window);

// AjaxProperties.js

enyo.AjaxProperties = {
cacheBust: !0,
url: "",
method: "GET",
handleAs: "json",
contentType: "application/x-www-form-urlencoded",
sync: !1,
headers: null,
postBody: "",
username: "",
password: "",
xhrFields: null,
mimeType: null
};

// Ajax.js

enyo.kind({
name: "enyo.Ajax",
kind: enyo.Async,
published: enyo.AjaxProperties,
constructor: function(e) {
enyo.mixin(this, e), this.inherited(arguments);
},
go: function(e) {
return this.startTimer(), this.request(e), this;
},
request: function(e) {
var t = this.url.split("?"), n = t.shift() || "", r = t.length ? t.join("?").split("&") : [], i = null;
enyo.isString(e) ? i = e : e && (i = enyo.Ajax.objectToQuery(e)), i && (r.push(i), i = null), this.cacheBust && r.push(Math.random());
var s = r.length ? [ n, r.join("&") ].join("?") : n, o = {}, u;
this.method != "GET" && (u = this.postBody, this.method === "POST" && u instanceof enyo.FormData ? u.fake && (o["Content-Type"] = u.getContentType(), u = u.toString()) : (o["Content-Type"] = this.contentType, u instanceof Object && (this.contentType === "application/json" ? u = JSON.stringify(u) : this.contentType === "application/x-www-form-urlencoded" ? u = enyo.Ajax.objectToQuery(u) : u = u.toString()))), enyo.mixin(o, this.headers), enyo.keys(o).length === 0 && (o = undefined);
try {
this.xhr = enyo.xhr.request({
url: s,
method: this.method,
callback: enyo.bind(this, "receive"),
body: u,
headers: o,
sync: window.PalmSystem ? !1 : this.sync,
username: this.username,
password: this.password,
xhrFields: this.xhrFields,
mimeType: this.mimeType
});
} catch (a) {
this.fail(a);
}
},
receive: function(e, t) {
if (!this.failed && !this.destroyed) {
var n;
typeof t.responseText == "string" ? n = t.responseText : n = t.responseBody, this.xhrResponse = {
status: t.status,
headers: enyo.Ajax.parseResponseHeaders(t),
body: n
}, this.isFailure(t) ? this.fail(t.status) : this.respond(this.xhrToResponse(t));
}
},
fail: function(e) {
this.xhr && (enyo.xhr.cancel(this.xhr), this.xhr = null), this.inherited(arguments);
},
xhrToResponse: function(e) {
if (e) return this[(this.handleAs || "text") + "Handler"](e);
},
isFailure: function(e) {
try {
var t = "";
return typeof e.responseText == "string" && (t = e.responseText), e.status === 0 && t === "" ? !0 : e.status !== 0 && (e.status < 200 || e.status >= 300);
} catch (n) {
return !0;
}
},
xmlHandler: function(e) {
return e.responseXML;
},
textHandler: function(e) {
return e.responseText;
},
jsonHandler: function(e) {
var t = e.responseText;
try {
return t && enyo.json.parse(t);
} catch (n) {
return enyo.warn("Ajax request set to handleAs JSON but data was not in JSON format"), t;
}
},
statics: {
objectToQuery: function(e) {
var t = encodeURIComponent, n = [], r = {};
for (var i in e) {
var s = e[i];
if (s != r[i]) {
var o = t(i) + "=";
if (enyo.isArray(s)) for (var u = 0; u < s.length; u++) n.push(o + t(s[u])); else n.push(o + t(s));
}
}
return n.join("&");
},
parseResponseHeaders: function(e) {
var t = {}, n = [];
e.getAllResponseHeaders && (n = e.getAllResponseHeaders().split(/\r?\n/));
for (var r = 0; r < n.length; r++) {
var i = n[r], s = i.indexOf(": ");
if (s > 0) {
var o = i.substring(0, s).toLowerCase(), u = i.substring(s + 2);
t[o] = u;
}
}
return t;
}
}
});

// Jsonp.js

enyo.kind({
name: "enyo.JsonpRequest",
kind: enyo.Async,
published: {
url: "",
charset: null,
callbackName: "callback",
cacheBust: !0
},
statics: {
nextCallbackID: 0
},
addScriptElement: function() {
var e = document.createElement("script");
e.src = this.src, e.async = "async", this.charset && (e.charset = this.charset), e.onerror = enyo.bind(this, function() {
this.fail(400);
});
var t = document.getElementsByTagName("script")[0];
t.parentNode.insertBefore(e, t), this.scriptTag = e;
},
removeScriptElement: function() {
var e = this.scriptTag;
this.scriptTag = null, e.onerror = null, e.parentNode && e.parentNode.removeChild(e);
},
constructor: function(e) {
enyo.mixin(this, e), this.inherited(arguments);
},
go: function(e) {
return this.startTimer(), this.jsonp(e), this;
},
jsonp: function(e) {
var t = "enyo_jsonp_callback_" + enyo.JsonpRequest.nextCallbackID++;
this.src = this.buildUrl(e, t), this.addScriptElement(), window[t] = enyo.bind(this, this.respond);
var n = enyo.bind(this, function() {
this.removeScriptElement(), window[t] = null;
});
this.response(n), this.error(n);
},
buildUrl: function(e, t) {
var n = this.url.split("?"), r = n.shift() || "", i = n.join("?").split("&"), s = this.bodyArgsFromParams(e, t);
return i.push(s), this.cacheBust && i.push(Math.random()), [ r, i.join("&") ].join("?");
},
bodyArgsFromParams: function(e, t) {
if (enyo.isString(e)) return e.replace("=?", "=" + t);
var n = enyo.mixin({}, e);
return n[this.callbackName] = t, enyo.Ajax.objectToQuery(n);
}
});

// WebService.js

enyo.kind({
name: "enyo._AjaxComponent",
kind: enyo.Component,
published: enyo.AjaxProperties
}), enyo.kind({
name: "enyo.WebService",
kind: enyo._AjaxComponent,
published: {
jsonp: !1,
callbackName: "callback",
charset: null,
timeout: 0
},
events: {
onResponse: "",
onError: ""
},
constructor: function(e) {
this.inherited(arguments);
},
send: function(e, t) {
return this.jsonp ? this.sendJsonp(e, t) : this.sendAjax(e, t);
},
sendJsonp: function(e, t) {
var n = new enyo.JsonpRequest;
for (var r in {
url: 1,
callbackName: 1,
charset: 1,
timeout: 1
}) n[r] = this[r];
return enyo.mixin(n, t), this.sendAsync(n, e);
},
sendAjax: function(e, t) {
var n = new enyo.Ajax(t);
for (var r in enyo.AjaxProperties) n[r] = this[r];
return n.timeout = this.timeout, enyo.mixin(n, t), this.sendAsync(n, e);
},
sendAsync: function(e, t) {
return e.go(t).response(this, "response").error(this, "error");
},
response: function(e, t) {
this.doResponse({
ajax: e,
data: t
});
},
error: function(e, t) {
this.doError({
ajax: e,
data: t
});
}
});

// dom.js

enyo.requiresWindow = function(e) {
e();
}, enyo.dom = {
byId: function(e, t) {
return typeof e == "string" ? (t || document).getElementById(e) : e;
},
escape: function(e) {
return e !== null ? String(e).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") : "";
},
getBounds: function(e) {
return e ? {
left: e.offsetLeft,
top: e.offsetTop,
width: e.offsetWidth,
height: e.offsetHeight
} : null;
},
getComputedStyle: function(e) {
return window.getComputedStyle && e && window.getComputedStyle(e, null);
},
getComputedStyleValue: function(e, t, n) {
var r = n || this.getComputedStyle(e);
return r ? r.getPropertyValue(t) : null;
},
getFirstElementByTagName: function(e) {
var t = document.getElementsByTagName(e);
return t && t[0];
},
applyBodyFit: function() {
var e = this.getFirstElementByTagName("html");
e && (e.className += " enyo-document-fit");
var t = this.getFirstElementByTagName("body");
t && (t.className += " enyo-body-fit"), enyo.bodyIsFitting = !0;
},
getWindowWidth: function() {
return window.innerWidth ? window.innerWidth : document.body && document.body.offsetWidth ? document.body.offsetWidth : document.compatMode == "CSS1Compat" && document.documentElement && document.documentElement.offsetWidth ? document.documentElement.offsetWidth : 320;
},
getWindowHeight: function() {
return window.innerHeight ? window.innerHeight : document.body && document.body.offsetHeight ? document.body.offsetHeight : document.compatMode == "CSS1Compat" && document.documentElement && document.documentElement.offsetHeight ? document.documentElement.offsetHeight : 480;
},
_ieCssToPixelValue: function(e, t) {
var n = t, r = e.style, i = r.left, s = e.runtimeStyle && e.runtimeStyle.left;
return s && (e.runtimeStyle.left = e.currentStyle.left), r.left = n, n = r.pixelLeft, r.left = i, s && (r.runtimeStyle.left = s), n;
},
_pxMatch: /px/i,
getComputedBoxValue: function(e, t, n, r) {
var i = r || this.getComputedStyle(e);
if (i) return parseInt(i.getPropertyValue(t + "-" + n), 0);
if (e && e.currentStyle) {
var s = e.currentStyle[t + enyo.cap(n)];
return s.match(this._pxMatch) || (s = this._ieCssToPixelValue(e, s)), parseInt(s, 0);
}
return 0;
},
calcBoxExtents: function(e, t) {
var n = this.getComputedStyle(e);
return {
top: this.getComputedBoxValue(e, t, "top", n),
right: this.getComputedBoxValue(e, t, "right", n),
bottom: this.getComputedBoxValue(e, t, "bottom", n),
left: this.getComputedBoxValue(e, t, "left", n)
};
},
calcPaddingExtents: function(e) {
return this.calcBoxExtents(e, "padding");
},
calcMarginExtents: function(e) {
return this.calcBoxExtents(e, "margin");
},
calcNodePosition: function(e, t) {
var n = 0, r = 0, i = e, s = i.offsetWidth, o = i.offsetHeight, u = enyo.dom.getStyleTransformProp(), a = /translateX\((-?\d+)px\)/i, f = /translateY\((-?\d+)px\)/i, l = 0, c = 0, h = 0, p = 0;
t ? (h = t.offsetHeight, p = t.offsetWidth) : (h = document.body.parentNode.offsetHeight > this.getWindowHeight() ? this.getWindowHeight() - document.body.parentNode.scrollTop : document.body.parentNode.offsetHeight, p = document.body.parentNode.offsetWidth > this.getWindowWidth() ? this.getWindowWidth() - document.body.parentNode.scrollLeft : document.body.parentNode.offsetWidth);
if (i.offsetParent) do r += i.offsetLeft - (i.offsetParent ? i.offsetParent.scrollLeft : 0), u && a.test(i.style[u]) && (r += parseInt(i.style[u].replace(a, "$1"), 10)), n += i.offsetTop - (i.offsetParent ? i.offsetParent.scrollTop : 0), u && f.test(i.style[u]) && (n += parseInt(i.style[u].replace(f, "$1"), 10)), i !== e && (i.currentStyle ? (l = parseInt(i.currentStyle.borderLeftWidth, 10), c = parseInt(i.currentStyle.borderTopWidth, 10)) : window.getComputedStyle ? (l = parseInt(window.getComputedStyle(i, "").getPropertyValue("border-left-width"), 10), c = parseInt(window.getComputedStyle(i, "").getPropertyValue("border-top-width"), 10)) : (l = parseInt(i.style.borderLeftWidth, 10), c = parseInt(i.style.borderTopWidth, 10)), l && (r += l), c && (n += c)); while ((i = i.offsetParent) && i !== t);
return {
top: n,
left: r,
bottom: h - n - o,
right: p - r - s,
height: o,
width: s
};
},
setInnerHtml: function(e, t) {
enyo.execUnsafeLocalFunction(function() {
e.innerHTML = t;
});
}
};

// transform.js

(function() {
enyo.dom.calcCanAccelerate = function() {
if (enyo.platform.android <= 2) return !1;
var e = [ "perspective", "WebkitPerspective", "MozPerspective", "msPerspective", "OPerspective" ];
for (var t = 0, n; n = e[t]; t++) if (typeof document.body.style[n] != "undefined") return !0;
return !1;
};
var e = [ "transform", "-webkit-transform", "-moz-transform", "-ms-transform", "-o-transform" ], t = [ "transform", "webkitTransform", "MozTransform", "msTransform", "OTransform" ];
enyo.dom.getCssTransformProp = function() {
if (this._cssTransformProp) return this._cssTransformProp;
var n = enyo.indexOf(this.getStyleTransformProp(), t);
return this._cssTransformProp = e[n];
}, enyo.dom.getStyleTransformProp = function() {
if (this._styleTransformProp || !document.body) return this._styleTransformProp;
for (var e = 0, n; n = t[e]; e++) if (typeof document.body.style[n] != "undefined") return this._styleTransformProp = n;
}, enyo.dom.domTransformsToCss = function(e) {
var t, n, r = "";
for (t in e) n = e[t], n !== null && n !== undefined && n !== "" && (r += t + "(" + n + ") ");
return r;
}, enyo.dom.transformsToDom = function(e) {
var t = this.domTransformsToCss(e.domTransforms), n = e.hasNode() ? e.node.style : null, r = e.domStyles, i = this.getStyleTransformProp(), s = this.getCssTransformProp();
i && s && (r[s] = t, n ? n[i] = t : e.domStylesChanged());
}, enyo.dom.canTransform = function() {
return Boolean(this.getStyleTransformProp());
}, enyo.dom.canAccelerate = function() {
return this.accelerando !== undefined ? this.accelerando : document.body && (this.accelerando = this.calcCanAccelerate());
}, enyo.dom.transform = function(e, t) {
var n = e.domTransforms = e.domTransforms || {};
enyo.mixin(n, t), this.transformsToDom(e);
}, enyo.dom.transformValue = function(e, t, n) {
var r = e.domTransforms = e.domTransforms || {};
r[t] = n, this.transformsToDom(e);
}, enyo.dom.accelerate = function(e, t) {
var n = t == "auto" ? this.canAccelerate() : t;
this.transformValue(e, "translateZ", n ? 0 : null);
};
})();

// Control.js

enyo.kind({
name: "enyo.Control",
kind: enyo.UiComponent,
published: {
tag: "div",
attributes: null,
classes: "",
style: "",
content: "",
showing: !0,
allowHtml: !1,
src: "",
canGenerate: !0,
fit: !1,
isContainer: !1
},
handlers: {
ontap: "tap"
},
defaultKind: "Control",
controlClasses: "",
node: null,
generated: !1,
create: function() {
this.initStyles(), this.inherited(arguments), this.showingChanged(), this.addClass(this.kindClasses), this.addClass(this.classes), this.initProps([ "id", "content", "src" ]);
},
destroy: function() {
this.removeNodeFromDom(), enyo.Control.unregisterDomEvents(this.id), this.inherited(arguments);
},
importProps: function(e) {
this.inherited(arguments), this.attributes = enyo.mixin(enyo.clone(this.kindAttributes), this.attributes);
},
initProps: function(e) {
for (var t = 0, n, r; n = e[t]; t++) this[n] && (r = n + "Changed", this[r] && this[r]());
},
classesChanged: function(e) {
this.removeClass(e), this.addClass(this.classes);
},
addChild: function(e) {
e.addClass(this.controlClasses), this.inherited(arguments);
},
removeChild: function(e) {
this.inherited(arguments), e.removeClass(this.controlClasses);
},
strictlyInternalEvents: {
onenter: 1,
onleave: 1
},
dispatchEvent: function(e, t, n) {
return this.strictlyInternalEvents[e] && this.isInternalEvent(t) ? !0 : this.inherited(arguments);
},
isInternalEvent: function(e) {
var t = enyo.dispatcher.findDispatchTarget(e.relatedTarget);
return t && t.isDescendantOf(this);
},
hasNode: function() {
return this.generated && (this.node || this.findNodeById());
},
addContent: function(e) {
this.setContent(this.content + e);
},
getAttribute: function(e) {
return this.hasNode() ? this.node.getAttribute(e) : this.attributes[e];
},
setAttribute: function(e, t) {
this.attributes[e] = t, this.hasNode() && this.attributeToNode(e, t), this.invalidateTags();
},
getNodeProperty: function(e, t) {
return this.hasNode() ? this.node[e] : t;
},
setNodeProperty: function(e, t) {
this.hasNode() && (this.node[e] = t);
},
setClassAttribute: function(e) {
this.setAttribute("class", e);
},
getClassAttribute: function() {
return this.attributes["class"] || "";
},
hasClass: function(e) {
return e && (" " + this.getClassAttribute() + " ").indexOf(" " + e + " ") >= 0;
},
addClass: function(e) {
if (e && !this.hasClass(e)) {
var t = this.getClassAttribute();
this.setClassAttribute(t + (t ? " " : "") + e);
}
},
removeClass: function(e) {
if (e && this.hasClass(e)) {
var t = this.getClassAttribute();
t = (" " + t + " ").replace(" " + e + " ", " ").slice(1, -1), this.setClassAttribute(t);
}
},
addRemoveClass: function(e, t) {
this[t ? "addClass" : "removeClass"](e);
},
initStyles: function() {
this.domStyles = this.domStyles || {}, enyo.Control.cssTextToDomStyles(this.kindStyle, this.domStyles), this.domCssText = enyo.Control.domStylesToCssText(this.domStyles);
},
styleChanged: function() {
this.invalidateTags(), this.renderStyles();
},
applyStyle: function(e, t) {
this.domStyles[e] = t, this.domStylesChanged();
},
addStyles: function(e) {
enyo.Control.cssTextToDomStyles(e, this.domStyles), this.domStylesChanged();
},
getComputedStyleValue: function(e, t) {
return this.hasNode() ? enyo.dom.getComputedStyleValue(this.node, e) : t;
},
domStylesChanged: function() {
this.domCssText = enyo.Control.domStylesToCssText(this.domStyles), this.invalidateTags(), this.renderStyles();
},
stylesToNode: function() {
this.node.style.cssText = this.style + (this.style[this.style.length - 1] == ";" ? " " : "; ") + this.domCssText;
},
setupBodyFitting: function() {
enyo.dom.applyBodyFit(), this.addClass("enyo-fit enyo-clip");
},
setupOverflowScrolling: function() {
if (enyo.platform.android || enyo.platform.androidChrome || enyo.platform.blackberry) return;
document.getElementsByTagName("body")[0].className += " webkitOverflowScrolling";
},
render: function() {
if (this.parent) {
this.parent.beforeChildRender(this);
if (!this.parent.generated) return this;
}
return this.hasNode() || this.renderNode(), this.hasNode() && (this.renderDom(), this.generated && this.rendered()), this;
},
renderInto: function(e) {
this.teardownRender();
var t = enyo.dom.byId(e);
return t == document.body ? this.setupBodyFitting() : this.fit && this.addClass("enyo-fit enyo-clip"), this.addClass("enyo-no-touch-action"), this.setupOverflowScrolling(), enyo.dom.setInnerHtml(t, this.generateHtml()), this.generated && this.rendered(), this;
},
write: function() {
return this.fit && this.setupBodyFitting(), this.addClass("enyo-no-touch-action"), this.setupOverflowScrolling(), document.write(this.generateHtml()), this.generated && this.rendered(), this;
},
rendered: function() {
this.reflow();
for (var e = 0, t; t = this.children[e]; e++) t.generated && t.rendered();
},
show: function() {
this.setShowing(!0);
},
hide: function() {
this.setShowing(!1);
},
getBounds: function() {
var e = this.node || this.hasNode(), t = enyo.dom.getBounds(e);
return t || {
left: undefined,
top: undefined,
width: undefined,
height: undefined
};
},
setBounds: function(e, t) {
var n = this.domStyles, r = t || "px", i = [ "width", "height", "left", "top", "right", "bottom" ];
for (var s = 0, o, u; u = i[s]; s++) {
o = e[u];
if (o || o === 0) n[u] = o + (enyo.isString(o) ? "" : r);
}
this.domStylesChanged();
},
findNodeById: function() {
return this.id && (this.node = enyo.dom.byId(this.id));
},
idChanged: function(e) {
e && enyo.Control.unregisterDomEvents(e), this.setAttribute("id", this.id), this.id && enyo.Control.registerDomEvents(this.id, this);
},
contentChanged: function() {
this.hasNode() && this.renderContent();
},
getSrc: function() {
return this.getAttribute("src");
},
srcChanged: function() {
this.setAttribute("src", enyo.path.rewrite(this.src));
},
attributesChanged: function() {
this.invalidateTags(), this.renderAttributes();
},
generateHtml: function() {
if (this.canGenerate === !1) return "";
var e = this.generateInnerHtml(), t = this.generateOuterHtml(e);
return this.generated = !0, t;
},
generateInnerHtml: function() {
return this.flow(), this.children.length ? this.generateChildHtml() : this.allowHtml ? this.content : enyo.Control.escapeHtml(this.content);
},
generateChildHtml: function() {
var e = "";
for (var t = 0, n; n = this.children[t]; t++) {
var r = n.generateHtml();
e += r;
}
return e;
},
generateOuterHtml: function(e) {
return this.tag ? (this.tagsValid || this.prepareTags(), this._openTag + e + this._closeTag) : e;
},
invalidateTags: function() {
this.tagsValid = !1;
},
prepareTags: function() {
var e = this.domCssText + this.style;
this._openTag = "<" + this.tag + (e ? ' style="' + e + '"' : "") + enyo.Control.attributesToHtml(this.attributes), enyo.Control.selfClosing[this.tag] ? (this._openTag += "/>", this._closeTag = "") : (this._openTag += ">", this._closeTag = "</" + this.tag + ">"), this.tagsValid = !0;
},
attributeToNode: function(e, t) {
t === null || t === !1 || t === "" ? this.node.removeAttribute(e) : this.node.setAttribute(e, t);
},
attributesToNode: function() {
for (var e in this.attributes) this.attributeToNode(e, this.attributes[e]);
},
getParentNode: function() {
return this.parentNode || this.parent && (this.parent.hasNode() || this.parent.getParentNode());
},
addNodeToParent: function() {
if (this.node) {
var e = this.getParentNode();
e && (this.addBefore !== undefined ? this.insertNodeInParent(e, this.addBefore && this.addBefore.hasNode()) : this.appendNodeToParent(e));
}
},
appendNodeToParent: function(e) {
e.appendChild(this.node);
},
insertNodeInParent: function(e, t) {
e.insertBefore(this.node, t || e.firstChild);
},
removeNodeFromDom: function() {
this.hasNode() && this.node.parentNode && this.node.parentNode.removeChild(this.node);
},
teardownRender: function() {
this.generated && this.teardownChildren(), this.node = null, this.generated = !1;
},
teardownChildren: function() {
for (var e = 0, t; t = this.children[e]; e++) t.teardownRender();
},
renderNode: function() {
this.teardownRender(), this.node = document.createElement(this.tag), this.addNodeToParent(), this.generated = !0;
},
renderDom: function() {
this.renderAttributes(), this.renderStyles(), this.renderContent();
},
renderContent: function() {
this.generated && this.teardownChildren(), enyo.dom.setInnerHtml(this.node, this.generateInnerHtml());
},
renderStyles: function() {
this.hasNode() && this.stylesToNode();
},
renderAttributes: function() {
this.hasNode() && this.attributesToNode();
},
beforeChildRender: function() {
this.generated && this.flow();
},
syncDisplayToShowing: function() {
var e = this.domStyles;
this.showing ? e.display == "none" && this.applyStyle("display", this._displayStyle || "") : (this._displayStyle = e.display == "none" ? "" : e.display, this.applyStyle("display", "none"));
},
showingChanged: function() {
this.syncDisplayToShowing();
},
getShowing: function() {
return this.showing = this.domStyles.display != "none";
},
fitChanged: function(e) {
this.parent.reflow();
},
statics: {
escapeHtml: function(e) {
return e != null ? String(e).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") : "";
},
registerDomEvents: function(e, t) {
enyo.$[e] = t;
},
unregisterDomEvents: function(e) {
enyo.$[e] = null;
},
selfClosing: {
img: 1,
hr: 1,
br: 1,
area: 1,
base: 1,
basefont: 1,
input: 1,
link: 1,
meta: 1,
command: 1,
embed: 1,
keygen: 1,
wbr: 1,
param: 1,
source: 1,
track: 1,
col: 1
},
cssTextToDomStyles: function(e, t) {
if (e) {
var n = e.replace(/; /g, ";").split(";");
for (var r = 0, i, s, o, u; u = n[r]; r++) i = u.split(":"), s = i.shift(), o = i.join(":"), t[s] = o;
}
},
domStylesToCssText: function(e) {
var t, n, r = "";
for (t in e) n = e[t], n !== null && n !== undefined && n !== "" && (r += t + ":" + n + ";");
return r;
},
stylesToHtml: function(e) {
var t = enyo.Control.domStylesToCssText(e);
return t ? ' style="' + t + '"' : "";
},
escapeAttribute: function(e) {
return enyo.isString(e) ? String(e).replace(/&/g, "&amp;").replace(/\"/g, "&quot;") : e;
},
attributesToHtml: function(e) {
var t, n, r = "";
for (t in e) n = e[t], n !== null && n !== !1 && n !== "" && (r += " " + t + '="' + enyo.Control.escapeAttribute(n) + '"');
return r;
}
}
}), enyo.defaultCtor = enyo.Control, enyo.Control.subclass = function(e, t) {
var n = e.prototype;
if (n.classes) {
var r = n.kindClasses;
n.kindClasses = (r ? r + " " : "") + n.classes, n.classes = "";
}
if (n.style) {
var i = n.kindStyle;
n.kindStyle = (i ? i + ";" : "") + n.style, n.style = "";
}
if (t.attributes) {
var s = n.kindAttributes;
n.kindAttributes = enyo.mixin(enyo.clone(s), n.attributes), n.attributes = null;
}
};

// platform.js

enyo.platform = {
touch: Boolean("ontouchstart" in window || window.navigator.msMaxTouchPoints),
gesture: Boolean("ongesturestart" in window || window.navigator.msMaxTouchPoints)
}, function() {
var e = navigator.userAgent, t = enyo.platform, n = [ {
platform: "androidChrome",
regex: /Android .* Chrome\/(\d+)[.\d]+/
}, {
platform: "android",
regex: /Android (\d+)/
}, {
platform: "android",
regex: /Silk\/1./,
forceVersion: 2,
extra: {
silk: 1
}
}, {
platform: "android",
regex: /Silk\/2./,
forceVersion: 4,
extra: {
silk: 2
}
}, {
platform: "windowsPhone",
regex: /Windows Phone (?:OS )?(\d+)[.\d]+/
}, {
platform: "ie",
regex: /MSIE (\d+)/
}, {
platform: "ios",
regex: /iP(?:hone|ad;(?: U;)? CPU) OS (\d+)/
}, {
platform: "webos",
regex: /(?:web|hpw)OS\/(\d+)/
}, {
platform: "safari",
regex: /Version\/(\d+)[.\d]+\s+Safari/
}, {
platform: "chrome",
regex: /Chrome\/(\d+)[.\d]+/
}, {
platform: "androidFirefox",
regex: /Android;.*Firefox\/(\d+)/
}, {
platform: "firefoxOS",
regex: /Mobile;.*Firefox\/(\d+)/
}, {
platform: "firefox",
regex: /Firefox\/(\d+)/
}, {
platform: "blackberry",
regex: /BB1\d;.*Version\/(\d+\.\d+)/
} ];
for (var r = 0, i, s, o; i = n[r]; r++) {
s = i.regex.exec(e);
if (s) {
i.forceVersion ? o = i.forceVersion : o = Number(s[1]), t[i.platform] = o, i.extra && enyo.mixin(t, i.extra);
break;
}
}
enyo.dumbConsole = Boolean(t.android || t.ios || t.webos);
}();

// animation.js

(function() {
var e = Math.round(1e3 / 60), t = [ "webkit", "moz", "ms", "o", "" ], n = "requestAnimationFrame", r = "cancel" + enyo.cap(n), i = function(t) {
return window.setTimeout(t, e);
}, s = function(e) {
return window.clearTimeout(e);
};
for (var o = 0, u = t.length, a, f, l; (a = t[o]) || o < u; o++) {
if (enyo.platform.ios >= 6) break;
f = a ? a + enyo.cap(r) : r, l = a ? a + enyo.cap(n) : n;
if (window[f]) {
s = window[f], i = window[l], a == "webkit" && s(i(enyo.nop));
break;
}
}
enyo.requestAnimationFrame = function(e, t) {
return i(e, t);
}, enyo.cancelRequestAnimationFrame = function(e) {
return s(e);
};
})(), enyo.easing = {
cubicIn: function(e) {
return Math.pow(e, 3);
},
cubicOut: function(e) {
return Math.pow(e - 1, 3) + 1;
},
expoOut: function(e) {
return e == 1 ? 1 : -1 * Math.pow(2, -10 * e) + 1;
},
quadInOut: function(e) {
return e *= 2, e < 1 ? Math.pow(e, 2) / 2 : -1 * (--e * (e - 2) - 1) / 2;
},
linear: function(e) {
return e;
}
}, enyo.easedLerp = function(e, t, n, r) {
var i = (enyo.now() - e) / t;
return r ? i >= 1 ? 0 : 1 - n(1 - i) : i >= 1 ? 1 : n(i);
};

// phonegap.js

(function() {
if (window.cordova || window.PhoneGap) {
var e = [ "deviceready", "pause", "resume", "online", "offline", "backbutton", "batterycritical", "batterylow", "batterystatus", "menubutton", "searchbutton", "startcallbutton", "endcallbutton", "volumedownbutton", "volumeupbutton" ];
for (var t = 0, n; n = e[t]; t++) document.addEventListener(n, enyo.bind(enyo.Signals, "send", "on" + n), !1);
}
})();

// dispatcher.js

enyo.$ = {}, enyo.dispatcher = {
events: [ "mousedown", "mouseup", "mouseover", "mouseout", "mousemove", "mousewheel", "click", "dblclick", "change", "keydown", "keyup", "keypress", "input" ],
windowEvents: [ "resize", "load", "unload", "message" ],
cssEvents: [ "webkitTransitionEnd", "transitionend" ],
features: [],
connect: function() {
var e = enyo.dispatcher, t, n;
for (t = 0; n = e.events[t]; t++) e.listen(document, n);
for (t = 0; n = e.cssEvents[t]; t++) e.listen(document, n);
for (t = 0; n = e.windowEvents[t]; t++) {
if (n === "unload" && typeof window.chrome == "object" && window.chrome.app) continue;
e.listen(window, n);
}
for (t = 0; n = e.cssEvents[t]; t++) e.listen(document, n);
},
listen: function(e, t, n) {
var r = enyo.dispatch;
e.addEventListener ? this.listen = function(e, t, n) {
e.addEventListener(t, n || r, !1);
} : this.listen = function(e, t, n) {
e.attachEvent("on" + t, function(e) {
return e.target = e.srcElement, e.preventDefault || (e.preventDefault = enyo.iePreventDefault), (n || r)(e);
});
}, this.listen(e, t, n);
},
dispatch: function(e) {
var t = this.findDispatchTarget(e.target) || this.findDefaultTarget(e);
e.dispatchTarget = t;
for (var n = 0, r; r = this.features[n]; n++) if (r.call(this, e) === !0) return;
t && !e.preventDispatch && this.dispatchBubble(e, t);
},
findDispatchTarget: function(e) {
var t, n = e;
try {
while (n) {
if (t = enyo.$[n.id]) {
t.eventNode = n;
break;
}
n = n.parentNode;
}
} catch (r) {
enyo.log(r, n);
}
return t;
},
findDefaultTarget: function(e) {
return enyo.master;
},
dispatchBubble: function(e, t) {
return t.bubble("on" + e.type, e, t);
}
}, enyo.iePreventDefault = function() {
try {
this.returnValue = !1;
} catch (e) {}
}, enyo.dispatch = function(e) {
return enyo.dispatcher.dispatch(e);
}, enyo.bubble = function(e) {
var t = e || window.event;
t && (t.target || (t.target = t.srcElement), enyo.dispatch(t));
}, enyo.bubbler = "enyo.bubble(arguments[0])", function() {
var e = function() {
enyo.bubble(arguments[0]);
};
enyo.makeBubble = function() {
var t = Array.prototype.slice.call(arguments, 0), n = t.shift();
typeof n == "object" && typeof n.hasNode == "function" && enyo.forEach(t, function(t) {
this.hasNode() && enyo.dispatcher.listen(this.node, t, e);
}, n);
};
}(), enyo.requiresWindow(enyo.dispatcher.connect), enyo.dispatcher.features.push(function(e) {
if ("click" === e.type && e.clientX === 0 && e.clientY === 0) {
var t = enyo.clone(e);
t.type = "tap", enyo.dispatch(t);
}
});

// preview.js

(function() {
var e = "previewDomEvent", t = {
feature: function(e) {
t.dispatch(e, e.dispatchTarget);
},
dispatch: function(t, n) {
var r = this.buildLineage(n);
for (var i = 0, s; s = r[i]; i++) if (s[e] && s[e](t) === !0) {
t.preventDispatch = !0;
return;
}
},
buildLineage: function(e) {
var t = [], n = e;
while (n) t.unshift(n), n = n.parent;
return t;
}
};
enyo.dispatcher.features.push(t.feature);
})();

// modal.js

enyo.dispatcher.features.push(function(e) {
var t = e.dispatchTarget, n = this.captureTarget && !this.noCaptureEvents[e.type], r = n && !(t && t.isDescendantOf && t.isDescendantOf(this.captureTarget));
if (r) {
var i = e.captureTarget = this.captureTarget, s = this.autoForwardEvents[e.type] || this.forwardEvents;
this.dispatchBubble(e, i), s || (e.preventDispatch = !0);
}
}), enyo.mixin(enyo.dispatcher, {
noCaptureEvents: {
load: 1,
unload: 1,
error: 1
},
autoForwardEvents: {
leave: 1,
resize: 1
},
captures: [],
capture: function(e, t) {
var n = {
target: e,
forward: t
};
this.captures.push(n), this.setCaptureInfo(n);
},
release: function() {
this.captures.pop(), this.setCaptureInfo(this.captures[this.captures.length - 1]);
},
setCaptureInfo: function(e) {
this.captureTarget = e && e.target, this.forwardEvents = e && e.forward;
}
});

// gesture.js

enyo.gesture = {
eventProps: [ "target", "relatedTarget", "clientX", "clientY", "pageX", "pageY", "screenX", "screenY", "altKey", "ctrlKey", "metaKey", "shiftKey", "detail", "identifier", "dispatchTarget", "which", "srcEvent" ],
makeEvent: function(e, t) {
var n = {
type: e
};
for (var r = 0, i; i = this.eventProps[r]; r++) n[i] = t[i];
n.srcEvent = n.srcEvent || t, n.preventDefault = this.preventDefault, n.disablePrevention = this.disablePrevention;
if (enyo.platform.ie < 10) {
enyo.platform.ie == 8 && n.target && (n.pageX = n.clientX + n.target.scrollLeft, n.pageY = n.clientY + n.target.scrollTop);
var s = window.event && window.event.button;
n.which = s & 1 ? 1 : s & 2 ? 2 : s & 4 ? 3 : 0;
} else (enyo.platform.webos || window.PalmSystem) && n.which === 0 && (n.which = 1);
return n;
},
down: function(e) {
var t = this.makeEvent("down", e);
enyo.dispatch(t), this.downEvent = t;
},
move: function(e) {
var t = this.makeEvent("move", e);
t.dx = t.dy = t.horizontal = t.vertical = 0, t.which && this.downEvent && (t.dx = e.clientX - this.downEvent.clientX, t.dy = e.clientY - this.downEvent.clientY, t.horizontal = Math.abs(t.dx) > Math.abs(t.dy), t.vertical = !t.horizontal), enyo.dispatch(t);
},
up: function(e) {
var t = this.makeEvent("up", e), n = !1;
t.preventTap = function() {
n = !0;
}, enyo.dispatch(t), !n && this.downEvent && this.downEvent.which == 1 && this.sendTap(t), this.downEvent = null;
},
over: function(e) {
enyo.dispatch(this.makeEvent("enter", e));
},
out: function(e) {
enyo.dispatch(this.makeEvent("leave", e));
},
sendTap: function(e) {
var t = this.findCommonAncestor(this.downEvent.target, e.target);
if (t) {
var n = this.makeEvent("tap", e);
n.target = t, enyo.dispatch(n);
}
},
findCommonAncestor: function(e, t) {
var n = t;
while (n) {
if (this.isTargetDescendantOf(e, n)) return n;
n = n.parentNode;
}
},
isTargetDescendantOf: function(e, t) {
var n = e;
while (n) {
if (n == t) return !0;
n = n.parentNode;
}
}
}, enyo.gesture.preventDefault = function() {
this.srcEvent && this.srcEvent.preventDefault();
}, enyo.gesture.disablePrevention = function() {
this.preventDefault = enyo.nop, this.srcEvent && (this.srcEvent.preventDefault = enyo.nop);
}, enyo.dispatcher.features.push(function(e) {
if (enyo.gesture.events[e.type]) return enyo.gesture.events[e.type](e);
}), enyo.gesture.events = {
mousedown: function(e) {
enyo.gesture.down(e);
},
mouseup: function(e) {
enyo.gesture.up(e);
},
mousemove: function(e) {
enyo.gesture.move(e);
},
mouseover: function(e) {
enyo.gesture.over(e);
},
mouseout: function(e) {
enyo.gesture.out(e);
}
}, enyo.requiresWindow(function() {
document.addEventListener && document.addEventListener("DOMMouseScroll", function(e) {
var t = enyo.clone(e);
t.preventDefault = function() {
e.preventDefault();
}, t.type = "mousewheel";
var n = t.VERTICAL_AXIS == t.axis ? "wheelDeltaY" : "wheelDeltaX";
t[n] = t.detail * -40, enyo.dispatch(t);
}, !1);
});

// drag.js

enyo.dispatcher.features.push(function(e) {
if (enyo.gesture.drag[e.type]) return enyo.gesture.drag[e.type](e);
}), enyo.gesture.drag = {
hysteresisSquared: 16,
holdPulseDelay: 200,
trackCount: 5,
minFlick: .1,
minTrack: 8,
down: function(e) {
this.stopDragging(e), this.cancelHold(), this.target = e.target, this.startTracking(e), this.beginHold(e);
},
move: function(e) {
if (this.tracking) {
this.track(e);
if (!e.which) {
this.stopDragging(e), this.cancelHold(), this.tracking = !1;
return;
}
this.dragEvent ? this.sendDrag(e) : this.dy * this.dy + this.dx * this.dx >= this.hysteresisSquared && (this.sendDragStart(e), this.cancelHold());
}
},
up: function(e) {
this.endTracking(e), this.stopDragging(e), this.cancelHold();
},
leave: function(e) {
this.dragEvent && this.sendDragOut(e);
},
stopDragging: function(e) {
if (this.dragEvent) {
this.sendDrop(e);
var t = this.sendDragFinish(e);
return this.dragEvent = null, t;
}
},
makeDragEvent: function(e, t, n, r) {
var i = Math.abs(this.dx), s = Math.abs(this.dy), o = i > s, u = (o ? s / i : i / s) < .414, a = {
type: e,
dx: this.dx,
dy: this.dy,
ddx: this.dx - this.lastDx,
ddy: this.dy - this.lastDy,
xDirection: this.xDirection,
yDirection: this.yDirection,
pageX: n.pageX,
pageY: n.pageY,
clientX: n.clientX,
clientY: n.clientY,
horizontal: o,
vertical: !o,
lockable: u,
target: t,
dragInfo: r,
ctrlKey: n.ctrlKey,
altKey: n.altKey,
metaKey: n.metaKey,
shiftKey: n.shiftKey,
srcEvent: n.srcEvent
};
return enyo.platform.ie == 8 && a.target && (a.pageX = a.clientX + a.target.scrollLeft, a.pageY = a.clientY + a.target.scrollTop), a.preventDefault = enyo.gesture.preventDefault, a.disablePrevention = enyo.gesture.disablePrevention, a;
},
sendDragStart: function(e) {
this.dragEvent = this.makeDragEvent("dragstart", this.target, e), enyo.dispatch(this.dragEvent);
},
sendDrag: function(e) {
var t = this.makeDragEvent("dragover", e.target, e, this.dragEvent.dragInfo);
enyo.dispatch(t), t.type = "drag", t.target = this.dragEvent.target, enyo.dispatch(t);
},
sendDragFinish: function(e) {
var t = this.makeDragEvent("dragfinish", this.dragEvent.target, e, this.dragEvent.dragInfo);
t.preventTap = function() {
e.preventTap && e.preventTap();
}, enyo.dispatch(t);
},
sendDragOut: function(e) {
var t = this.makeDragEvent("dragout", e.target, e, this.dragEvent.dragInfo);
enyo.dispatch(t);
},
sendDrop: function(e) {
var t = this.makeDragEvent("drop", e.target, e, this.dragEvent.dragInfo);
t.preventTap = function() {
e.preventTap && e.preventTap();
}, enyo.dispatch(t);
},
startTracking: function(e) {
this.tracking = !0, this.px0 = e.clientX, this.py0 = e.clientY, this.flickInfo = {
startEvent: e,
moves: []
}, this.track(e);
},
track: function(e) {
this.lastDx = this.dx, this.lastDy = this.dy, this.dx = e.clientX - this.px0, this.dy = e.clientY - this.py0, this.xDirection = this.calcDirection(this.dx - this.lastDx, 0), this.yDirection = this.calcDirection(this.dy - this.lastDy, 0);
var t = this.flickInfo;
t.moves.push({
x: e.clientX,
y: e.clientY,
t: enyo.now()
}), t.moves.length > this.trackCount && t.moves.shift();
},
endTracking: function(e) {
this.tracking = !1;
var t = this.flickInfo, n = t && t.moves;
if (n && n.length > 1) {
var r = n[n.length - 1], i = enyo.now();
for (var s = n.length - 2, o = 0, u = 0, a = 0, f = 0, l = 0, c = 0, h = 0, p; p = n[s]; s--) {
o = i - p.t, u = (r.x - p.x) / o, a = (r.y - p.y) / o, c = c || (u < 0 ? -1 : u > 0 ? 1 : 0), h = h || (a < 0 ? -1 : a > 0 ? 1 : 0);
if (u * c > f * c || a * h > l * h) f = u, l = a;
}
var d = Math.sqrt(f * f + l * l);
d > this.minFlick && this.sendFlick(t.startEvent, f, l, d);
}
this.flickInfo = null;
},
calcDirection: function(e, t) {
return e > 0 ? 1 : e < 0 ? -1 : t;
},
beginHold: function(e) {
this.holdStart = enyo.now(), this.holdJob = setInterval(enyo.bind(this, "sendHoldPulse", e), this.holdPulseDelay);
},
cancelHold: function() {
clearInterval(this.holdJob), this.holdJob = null, this.sentHold && (this.sentHold = !1, this.sendRelease(this.holdEvent));
},
sendHoldPulse: function(e) {
this.sentHold || (this.sentHold = !0, this.sendHold(e));
var t = enyo.gesture.makeEvent("holdpulse", e);
t.holdTime = enyo.now() - this.holdStart, enyo.dispatch(t);
},
sendHold: function(e) {
this.holdEvent = e;
var t = enyo.gesture.makeEvent("hold", e);
enyo.dispatch(t);
},
sendRelease: function(e) {
var t = enyo.gesture.makeEvent("release", e);
enyo.dispatch(t);
},
sendFlick: function(e, t, n, r) {
var i = enyo.gesture.makeEvent("flick", e);
i.xVelocity = t, i.yVelocity = n, i.velocity = r, enyo.dispatch(i);
}
};

// transition.js

enyo.dom.transition = enyo.platform.ios || enyo.platform.android || enyo.platform.chrome || enyo.platform.androidChrome || enyo.platform.safari ? "-webkit-transition" : enyo.platform.firefox || enyo.platform.firefoxOS || enyo.platform.androidFirefox ? "-moz-transition" : "transition";

// touch.js

enyo.requiresWindow(function() {
var e = enyo.gesture, t = e.events;
e.events.touchstart = function(t) {
e.events = n, e.events.touchstart(t);
};
var n = {
_touchCount: 0,
touchstart: function(t) {
this._touchCount += t.changedTouches.length, this.excludedTarget = null;
var n = this.makeEvent(t);
e.down(n), n = this.makeEvent(t), this.overEvent = n, e.over(n);
},
touchmove: function(t) {
enyo.job.stop("resetGestureEvents");
var n = e.drag.dragEvent;
this.excludedTarget = n && n.dragInfo && n.dragInfo.node;
var r = this.makeEvent(t);
e.move(r), enyo.bodyIsFitting && t.preventDefault(), this.overEvent && this.overEvent.target != r.target && (this.overEvent.relatedTarget = r.target, r.relatedTarget = this.overEvent.target, e.out(this.overEvent), e.over(r)), this.overEvent = r;
},
touchend: function(t) {
e.up(this.makeEvent(t)), e.out(this.overEvent), this._touchCount -= t.changedTouches.length;
},
mouseup: function(n) {
this._touchCount === 0 && (this.sawMousedown = !1, e.events = t);
},
makeEvent: function(e) {
var t = enyo.clone(e.changedTouches[0]);
return t.srcEvent = e, t.target = this.findTarget(t), t.which = 1, t;
},
calcNodeOffset: function(e) {
if (e.getBoundingClientRect) {
var t = e.getBoundingClientRect();
return {
left: t.left,
top: t.top,
width: t.width,
height: t.height
};
}
},
findTarget: function(e) {
return document.elementFromPoint(e.clientX, e.clientY);
},
findTargetTraverse: function(e, t, n) {
var r = e || document.body, i = this.calcNodeOffset(r);
if (i && r != this.excludedTarget) {
var s = t - i.left, o = n - i.top;
if (s > 0 && o > 0 && s <= i.width && o <= i.height) {
var u;
for (var a = r.childNodes, f = a.length - 1, l; l = a[f]; f--) {
u = this.findTargetTraverse(l, t, n);
if (u) return u;
}
return r;
}
}
},
connect: function() {
enyo.forEach([ "ontouchstart", "ontouchmove", "ontouchend", "ongesturestart", "ongesturechange", "ongestureend" ], function(e) {
document[e] = enyo.dispatch;
}), enyo.platform.androidChrome <= 18 || enyo.platform.silk === 2 ? this.findTarget = function(e) {
return document.elementFromPoint(e.screenX, e.screenY);
} : document.elementFromPoint || (this.findTarget = function(e) {
return this.findTargetTraverse(null, e.clientX, e.clientY);
});
}
};
n.connect();
});

// msevents.js

(function() {
var e = enyo.gesture;
if (window.navigator.msPointerEnabled) {
var t = [ "MSPointerDown", "MSPointerUp", "MSPointerMove", "MSPointerOver", "MSPointerOut", "MSPointerCancel", "MSGestureTap", "MSGestureDoubleTap", "MSGestureHold", "MSGestureStart", "MSGestureChange", "MSGestureEnd" ];
enyo.forEach(t, function(e) {
enyo.dispatcher.listen(document, e);
}), enyo.dispatcher.features.push(function(e) {
i[e.type] && e.isPrimary && i[e.type](e);
}), enyo.gesture.events = {};
}
var n = function(t, n) {
var r = enyo.clone(n);
return enyo.mixin(r, {
pageX: n.translationX || 0,
pageY: n.translationY || 0,
rotation: n.rotation * (180 / Math.PI) || 0,
type: t,
srcEvent: n,
preventDefault: e.preventDefault,
disablePrevention: e.disablePrevention
});
}, r = function(e) {
var t = enyo.clone(e);
return t.srcEvent = e, t.which = 1, t;
}, i = {
MSPointerDown: function(t) {
var n = r(t);
e.down(n);
},
MSPointerUp: function(t) {
var n = r(t);
e.up(n);
},
MSPointerMove: function(t) {
var n = r(t);
e.move(n);
},
MSPointerCancel: function(t) {
var n = r(t);
e.up(n);
},
MSPointerOver: function(t) {
var n = r(t);
e.over(n);
},
MSPointerOut: function(t) {
var n = r(t);
e.out(n);
}
};
})();

// gesture.js

(function() {
!enyo.platform.gesture && enyo.platform.touch && enyo.dispatcher.features.push(function(n) {
e[n.type] && t[n.type](n);
});
var e = {
touchstart: !0,
touchmove: !0,
touchend: !0
}, t = {
orderedTouches: [],
gesture: null,
touchstart: function(e) {
enyo.forEach(e.changedTouches, function(e) {
var t = e.identifier;
enyo.indexOf(t, this.orderedTouches) < 0 && this.orderedTouches.push(t);
}, this);
if (e.touches.length >= 2 && !this.gesture) {
var t = this.gesturePositions(e);
this.gesture = this.gestureVector(t), this.gesture.angle = this.gestureAngle(t), this.gesture.scale = 1, this.gesture.rotation = 0;
var n = this.makeGesture("gesturestart", e, {
vector: this.gesture,
scale: 1,
rotation: 0
});
enyo.dispatch(n);
}
},
touchend: function(e) {
enyo.forEach(e.changedTouches, function(e) {
enyo.remove(e.identifier, this.orderedTouches);
}, this);
if (e.touches.length <= 1 && this.gesture) {
var t = e.touches[0] || e.changedTouches[e.changedTouches.length - 1];
enyo.dispatch(this.makeGesture("gestureend", e, {
vector: {
xcenter: t.pageX,
ycenter: t.pageY
},
scale: this.gesture.scale,
rotation: this.gesture.rotation
})), this.gesture = null;
}
},
touchmove: function(e) {
if (this.gesture) {
var t = this.makeGesture("gesturechange", e);
this.gesture.scale = t.scale, this.gesture.rotation = t.rotation, enyo.dispatch(t);
}
},
findIdentifiedTouch: function(e, t) {
for (var n = 0, r; r = e[n]; n++) if (r.identifier === t) return r;
},
gesturePositions: function(e) {
var t = this.findIdentifiedTouch(e.touches, this.orderedTouches[0]), n = this.findIdentifiedTouch(e.touches, this.orderedTouches[this.orderedTouches.length - 1]), r = t.pageX, i = n.pageX, s = t.pageY, o = n.pageY, u = i - r, a = o - s, f = Math.sqrt(u * u + a * a);
return {
x: u,
y: a,
h: f,
fx: r,
lx: i,
fy: s,
ly: o
};
},
gestureAngle: function(e) {
var t = e, n = Math.asin(t.y / t.h) * (180 / Math.PI);
return t.x < 0 && (n = 180 - n), t.x > 0 && t.y < 0 && (n += 360), n;
},
gestureVector: function(e) {
var t = e;
return {
magnitude: t.h,
xcenter: Math.abs(Math.round(t.fx + t.x / 2)),
ycenter: Math.abs(Math.round(t.fy + t.y / 2))
};
},
makeGesture: function(e, t, n) {
var r, i, s;
if (n) r = n.vector, i = n.scale, s = n.rotation; else {
var o = this.gesturePositions(t);
r = this.gestureVector(o), i = r.magnitude / this.gesture.magnitude, s = (360 + this.gestureAngle(o) - this.gesture.angle) % 360;
}
var u = enyo.clone(t);
return enyo.mixin(u, {
type: e,
scale: i,
pageX: r.xcenter,
pageY: r.ycenter,
rotation: s
});
}
};
})();

// ScrollMath.js

enyo.kind({
name: "enyo.ScrollMath",
kind: enyo.Component,
published: {
vertical: !0,
horizontal: !0
},
events: {
onScrollStart: "",
onScroll: "",
onScrollStop: ""
},
kSpringDamping: .93,
kDragDamping: .5,
kFrictionDamping: .97,
kSnapFriction: .9,
kFlickScalar: 15,
kMaxFlick: enyo.platform.android > 2 ? 2 : 1e9,
kFrictionEpsilon: .01,
topBoundary: 0,
rightBoundary: 0,
bottomBoundary: 0,
leftBoundary: 0,
interval: 20,
fixedTime: !0,
x0: 0,
x: 0,
y0: 0,
y: 0,
destroy: function() {
this.stop(), this.inherited(arguments);
},
verlet: function(e) {
var t = this.x;
this.x += t - this.x0, this.x0 = t;
var n = this.y;
this.y += n - this.y0, this.y0 = n;
},
damping: function(e, t, n, r) {
var i = .5, s = e - t;
return Math.abs(s) < i ? t : e * r > t * r ? n * s + t : e;
},
boundaryDamping: function(e, t, n, r) {
return this.damping(this.damping(e, t, r, 1), n, r, -1);
},
constrain: function() {
var e = this.boundaryDamping(this.y, this.topBoundary, this.bottomBoundary, this.kSpringDamping);
e != this.y && (this.y0 = e - (this.y - this.y0) * this.kSnapFriction, this.y = e);
var t = this.boundaryDamping(this.x, this.leftBoundary, this.rightBoundary, this.kSpringDamping);
t != this.x && (this.x0 = t - (this.x - this.x0) * this.kSnapFriction, this.x = t);
},
friction: function(e, t, n) {
var r = this[e] - this[t], i = Math.abs(r) > this.kFrictionEpsilon ? n : 0;
this[e] = this[t] + i * r;
},
frame: 10,
simulate: function(e) {
while (e >= this.frame) e -= this.frame, this.dragging || this.constrain(), this.verlet(), this.friction("y", "y0", this.kFrictionDamping), this.friction("x", "x0", this.kFrictionDamping);
return e;
},
animate: function() {
this.stop();
var e = enyo.now(), t = 0, n, r, i = enyo.bind(this, function() {
var s = enyo.now();
this.job = enyo.requestAnimationFrame(i);
var o = s - e;
e = s, this.dragging && (this.y0 = this.y = this.uy, this.x0 = this.x = this.ux), t += Math.max(16, o), this.fixedTime && !this.isInOverScroll() && (t = this.interval), t = this.simulate(t), r != this.y || n != this.x ? this.scroll() : this.dragging || (this.stop(!0), this.scroll()), r = this.y, n = this.x;
});
this.job = enyo.requestAnimationFrame(i);
},
start: function() {
this.job || (this.animate(), this.doScrollStart());
},
stop: function(e) {
this.job = enyo.cancelRequestAnimationFrame(this.job), e && this.doScrollStop();
},
stabilize: function() {
this.start();
var e = Math.min(this.topBoundary, Math.max(this.bottomBoundary, this.y)), t = Math.min(this.leftBoundary, Math.max(this.rightBoundary, this.x));
this.y = this.y0 = e, this.x = this.x0 = t, this.scroll(), this.stop(!0);
},
startDrag: function(e) {
this.dragging = !0, this.my = e.pageY, this.py = this.uy = this.y, this.mx = e.pageX, this.px = this.ux = this.x;
},
drag: function(e) {
if (this.dragging) {
var t = this.vertical ? e.pageY - this.my : 0;
this.uy = t + this.py, this.uy = this.boundaryDamping(this.uy, this.topBoundary, this.bottomBoundary, this.kDragDamping);
var n = this.horizontal ? e.pageX - this.mx : 0;
return this.ux = n + this.px, this.ux = this.boundaryDamping(this.ux, this.leftBoundary, this.rightBoundary, this.kDragDamping), this.start(), !0;
}
},
dragDrop: function(e) {
if (this.dragging && !window.PalmSystem) {
var t = .5;
this.y = this.uy, this.y0 = this.y - (this.y - this.y0) * t, this.x = this.ux, this.x0 = this.x - (this.x - this.x0) * t;
}
this.dragFinish();
},
dragFinish: function() {
this.dragging = !1;
},
flick: function(e) {
var t;
this.vertical && (t = e.yVelocity > 0 ? Math.min(this.kMaxFlick, e.yVelocity) : Math.max(-this.kMaxFlick, e.yVelocity), this.y = this.y0 + t * this.kFlickScalar), this.horizontal && (t = e.xVelocity > 0 ? Math.min(this.kMaxFlick, e.xVelocity) : Math.max(-this.kMaxFlick, e.xVelocity), this.x = this.x0 + t * this.kFlickScalar), this.start();
},
mousewheel: function(e) {
var t = this.vertical ? e.wheelDeltaY || e.wheelDelta : 0;
if (t > 0 && this.y < this.topBoundary || t < 0 && this.y > this.bottomBoundary) return this.stop(!0), this.y = this.y0 = this.y0 + t, this.start(), !0;
},
scroll: function() {
this.doScroll();
},
scrollTo: function(e, t) {
t !== null && (this.y = this.y0 - (t + this.y0) * (1 - this.kFrictionDamping)), e !== null && (this.x = this.x0 - (e + this.x0) * (1 - this.kFrictionDamping)), this.start();
},
setScrollX: function(e) {
this.x = this.x0 = e;
},
setScrollY: function(e) {
this.y = this.y0 = e;
},
setScrollPosition: function(e) {
this.setScrollY(e);
},
isScrolling: function() {
return Boolean(this.job);
},
isInOverScroll: function() {
return this.job && (this.x > this.leftBoundary || this.x < this.rightBoundary || this.y > this.topBoundary || this.y < this.bottomBoundary);
}
});

// ScrollStrategy.js

enyo.kind({
name: "enyo.ScrollStrategy",
tag: null,
published: {
vertical: "default",
horizontal: "default",
scrollLeft: 0,
scrollTop: 0,
maxHeight: null
},
handlers: {
ondragstart: "dragstart",
ondragfinish: "dragfinish",
ondown: "down",
onmove: "move"
},
create: function() {
this.inherited(arguments), this.horizontalChanged(), this.verticalChanged(), this.maxHeightChanged();
},
rendered: function() {
this.inherited(arguments), enyo.makeBubble(this.container, "scroll"), this.scrollNode = this.calcScrollNode();
},
teardownRender: function() {
this.inherited(arguments), this.scrollNode = null;
},
calcScrollNode: function() {
return this.container.hasNode();
},
horizontalChanged: function() {
this.container.applyStyle("overflow-x", this.horizontal == "default" ? "auto" : this.horizontal);
},
verticalChanged: function() {
this.container.applyStyle("overflow-y", this.vertical == "default" ? "auto" : this.vertical);
},
maxHeightChanged: function() {
this.container.applyStyle("max-height", this.maxHeight);
},
scrollTo: function(e, t) {
this.scrollNode && (this.setScrollLeft(e), this.setScrollTop(t));
},
scrollToNode: function(e, t) {
if (this.scrollNode) {
var n = this.getScrollBounds(), r = e, i = {
height: r.offsetHeight,
width: r.offsetWidth,
top: 0,
left: 0
};
while (r && r.parentNode && r.id != this.scrollNode.id) i.top += r.offsetTop, i.left += r.offsetLeft, r = r.parentNode;
this.setScrollTop(Math.min(n.maxTop, t === !1 ? i.top - n.clientHeight + i.height : i.top)), this.setScrollLeft(Math.min(n.maxLeft, t === !1 ? i.left - n.clientWidth + i.width : i.left));
}
},
scrollIntoView: function(e, t) {
e.hasNode() && e.node.scrollIntoView(t);
},
isInView: function(e) {
var t = this.getScrollBounds(), n = e.offsetTop, r = e.offsetHeight, i = e.offsetLeft, s = e.offsetWidth;
return n >= t.top && n + r <= t.top + t.clientHeight && i >= t.left && i + s <= t.left + t.clientWidth;
},
setScrollTop: function(e) {
this.scrollTop = e, this.scrollNode && (this.scrollNode.scrollTop = this.scrollTop);
},
setScrollLeft: function(e) {
this.scrollLeft = e, this.scrollNode && (this.scrollNode.scrollLeft = this.scrollLeft);
},
getScrollLeft: function() {
return this.scrollNode ? this.scrollNode.scrollLeft : this.scrollLeft;
},
getScrollTop: function() {
return this.scrollNode ? this.scrollNode.scrollTop : this.scrollTop;
},
_getScrollBounds: function() {
var e = this.getScrollSize(), t = this.container.hasNode(), n = {
left: this.getScrollLeft(),
top: this.getScrollTop(),
clientHeight: t ? t.clientHeight : 0,
clientWidth: t ? t.clientWidth : 0,
height: e.height,
width: e.width
};
return n.maxLeft = Math.max(0, n.width - n.clientWidth), n.maxTop = Math.max(0, n.height - n.clientHeight), n;
},
getScrollSize: function() {
var e = this.scrollNode;
return {
width: e ? e.scrollWidth : 0,
height: e ? e.scrollHeight : 0
};
},
getScrollBounds: function() {
return this._getScrollBounds();
},
calcStartInfo: function() {
var e = this.getScrollBounds(), t = this.getScrollTop(), n = this.getScrollLeft();
this.canVertical = e.maxTop > 0 && this.vertical != "hidden", this.canHorizontal = e.maxLeft > 0 && this.horizontal != "hidden", this.startEdges = {
top: t === 0,
bottom: t === e.maxTop,
left: n === 0,
right: n === e.maxLeft
};
},
shouldDrag: function(e) {
var t = e.vertical;
return t && this.canVertical || !t && this.canHorizontal;
},
dragstart: function(e, t) {
this.dragging = this.shouldDrag(t);
if (this.dragging) return this.preventDragPropagation;
},
dragfinish: function(e, t) {
this.dragging && (this.dragging = !1, t.preventTap());
},
down: function(e, t) {
this.calcStartInfo();
},
move: function(e, t) {
t.which && (this.canVertical && t.vertical || this.canHorizontal && t.horizontal) && t.disablePrevention();
}
});

// Thumb.js

enyo.kind({
name: "enyo.ScrollThumb",
axis: "v",
minSize: 4,
cornerSize: 6,
classes: "enyo-thumb",
create: function() {
this.inherited(arguments);
var e = this.axis == "v";
this.dimension = e ? "height" : "width", this.offset = e ? "top" : "left", this.translation = e ? "translateY" : "translateX", this.positionMethod = e ? "getScrollTop" : "getScrollLeft", this.sizeDimension = e ? "clientHeight" : "clientWidth", this.addClass("enyo-" + this.axis + "thumb"), this.transform = enyo.dom.canTransform(), enyo.dom.canAccelerate() && enyo.dom.transformValue(this, "translateZ", 0);
},
sync: function(e) {
this.scrollBounds = e._getScrollBounds(), this.update(e);
},
update: function(e) {
if (this.showing) {
var t = this.dimension, n = this.offset, r = this.scrollBounds[this.sizeDimension], i = this.scrollBounds[t], s = 0, o = 0, u = 0;
if (r >= i) {
this.hide();
return;
}
e.isOverscrolling() && (u = e.getOverScrollBounds()["over" + n], s = Math.abs(u), o = Math.max(u, 0));
var a = e[this.positionMethod]() - u, f = r - this.cornerSize, l = Math.floor(r * r / i - s);
l = Math.max(this.minSize, l);
var c = Math.floor(f * a / i + o);
c = Math.max(0, Math.min(f - this.minSize, c)), this.needed = l < r, this.needed && this.hasNode() ? (this._pos !== c && (this._pos = c, this.transform ? enyo.dom.transformValue(this, this.translation, c + "px") : this.axis == "v" ? this.setBounds({
top: c + "px"
}) : this.setBounds({
left: c + "px"
})), this._size !== l && (this._size = l, this.node.style[t] = this.domStyles[t] = l + "px")) : this.hide();
}
},
setShowing: function(e) {
if (e && e != this.showing && this.scrollBounds[this.sizeDimension] >= this.scrollBounds[this.dimension]) return;
this.hasNode() && this.cancelDelayHide();
if (e != this.showing) {
var t = this.showing;
this.showing = e, this.showingChanged(t);
}
},
delayHide: function(e) {
this.showing && enyo.job(this.id + "hide", enyo.bind(this, "hide"), e || 0);
},
cancelDelayHide: function() {
enyo.job.stop(this.id + "hide");
}
});

// TouchScrollStrategy.js

enyo.kind({
name: "enyo.TouchScrollStrategy",
kind: "ScrollStrategy",
overscroll: !0,
preventDragPropagation: !0,
published: {
vertical: "default",
horizontal: "default",
thumb: !0,
scrim: !1,
dragDuringGesture: !0
},
events: {
onShouldDrag: ""
},
handlers: {
onscroll: "domScroll",
onflick: "flick",
onhold: "hold",
ondragstart: "dragstart",
onShouldDrag: "shouldDrag",
ondrag: "drag",
ondragfinish: "dragfinish",
onmousewheel: "mousewheel"
},
tools: [ {
kind: "ScrollMath",
onScrollStart: "scrollMathStart",
onScroll: "scrollMathScroll",
onScrollStop: "scrollMathStop"
}, {
name: "vthumb",
kind: "ScrollThumb",
axis: "v",
showing: !1
}, {
name: "hthumb",
kind: "ScrollThumb",
axis: "h",
showing: !1
} ],
scrimTools: [ {
name: "scrim",
classes: "enyo-fit",
style: "z-index: 1;",
showing: !1
} ],
components: [ {
name: "client",
classes: "enyo-touch-scroller"
} ],
listReordering: !1,
create: function() {
this.inherited(arguments), this.transform = enyo.dom.canTransform(), this.transform || this.overscroll && this.$.client.applyStyle("position", "relative"), this.accel = enyo.dom.canAccelerate();
var e = "enyo-touch-strategy-container";
enyo.platform.ios && this.accel && (e += " enyo-composite"), this.scrimChanged(), this.container.addClass(e), this.translation = this.accel ? "translate3d" : "translate";
},
initComponents: function() {
this.createChrome(this.tools), this.inherited(arguments);
},
destroy: function() {
this.container.removeClass("enyo-touch-strategy-container"), this.inherited(arguments);
},
rendered: function() {
this.inherited(arguments), enyo.makeBubble(this.$.client, "scroll"), this.calcBoundaries(), this.syncScrollMath(), this.thumb && this.alertThumbs();
},
scrimChanged: function() {
this.scrim && !this.$.scrim && this.makeScrim(), !this.scrim && this.$.scrim && this.$.scrim.destroy();
},
makeScrim: function() {
var e = this.controlParent;
this.controlParent = null, this.createChrome(this.scrimTools), this.controlParent = e;
var t = this.container.hasNode();
t && (this.$.scrim.parentNode = t, this.$.scrim.render());
},
isScrolling: function() {
var e = this.$.scrollMath;
return e ? e.isScrolling() : this.scrolling;
},
isOverscrolling: function() {
var e = this.$.scrollMath || this;
return this.overscroll ? e.isInOverScroll() : !1;
},
domScroll: function() {
this.isScrolling() || (this.calcBoundaries(), this.syncScrollMath(), this.thumb && this.alertThumbs());
},
horizontalChanged: function() {
this.$.scrollMath.horizontal = this.horizontal != "hidden";
},
verticalChanged: function() {
this.$.scrollMath.vertical = this.vertical != "hidden";
},
maxHeightChanged: function() {
this.$.client.applyStyle("max-height", this.maxHeight), this.$.client.addRemoveClass("enyo-scrollee-fit", !this.maxHeight);
},
thumbChanged: function() {
this.hideThumbs();
},
stop: function() {
this.isScrolling() && this.$.scrollMath.stop(!0);
},
stabilize: function() {
this.$.scrollMath && this.$.scrollMath.stabilize();
},
scrollTo: function(e, t) {
this.stop(), this.$.scrollMath.scrollTo(e, t || t === 0 ? t : null);
},
scrollIntoView: function() {
this.stop(), this.inherited(arguments);
},
setScrollLeft: function() {
this.stop(), this.inherited(arguments);
},
setScrollTop: function() {
this.stop(), this.inherited(arguments);
},
getScrollLeft: function() {
return this.isScrolling() ? this.scrollLeft : this.inherited(arguments);
},
getScrollTop: function() {
return this.isScrolling() ? this.scrollTop : this.inherited(arguments);
},
calcScrollNode: function() {
return this.$.client.hasNode();
},
calcAutoScrolling: function() {
var e = this.vertical == "auto", t = this.horizontal == "auto" || this.horizontal == "default";
if ((e || t) && this.scrollNode) {
var n = this.getScrollBounds();
e && (this.$.scrollMath.vertical = n.height > n.clientHeight), t && (this.$.scrollMath.horizontal = n.width > n.clientWidth);
}
},
shouldDrag: function(e, t) {
this.calcAutoScrolling();
var n = t.vertical, r = this.$.scrollMath.horizontal && !n, i = this.$.scrollMath.vertical && n, s = t.dy < 0, o = t.dx < 0, u = !s && this.startEdges.top || s && this.startEdges.bottom, a = !o && this.startEdges.left || o && this.startEdges.right;
!t.boundaryDragger && (r || i) && (t.boundaryDragger = this);
if (!u && i || !a && r) return t.dragger = this, !0;
},
flick: function(e, t) {
var n = Math.abs(t.xVelocity) > Math.abs(t.yVelocity) ? this.$.scrollMath.horizontal : this.$.scrollMath.vertical;
if (n && this.dragging) return this.$.scrollMath.flick(t), this.preventDragPropagation;
},
hold: function(e, t) {
if (this.isScrolling() && !this.isOverscrolling()) {
var n = this.$.scrollMath || this;
return n.stop(t), !0;
}
},
move: function(e, t) {},
dragstart: function(e, t) {
if (!this.dragDuringGesture && t.srcEvent.touches && t.srcEvent.touches.length > 1) return !0;
this.doShouldDrag(t), this.dragging = t.dragger == this || !t.dragger && t.boundaryDragger == this;
if (this.dragging) {
t.preventDefault(), this.syncScrollMath(), this.$.scrollMath.startDrag(t);
if (this.preventDragPropagation) return !0;
}
},
drag: function(e, t) {
if (this.listReordering) return !1;
this.dragging && (t.preventDefault(), this.$.scrollMath.drag(t), this.scrim && this.$.scrim.show());
},
dragfinish: function(e, t) {
this.dragging && (t.preventTap(), this.$.scrollMath.dragFinish(), this.dragging = !1, this.scrim && this.$.scrim.hide());
},
mousewheel: function(e, t) {
if (!this.dragging) {
this.calcBoundaries(), this.syncScrollMath(), this.stabilize();
if (this.$.scrollMath.mousewheel(t)) return t.preventDefault(), !0;
}
},
scrollMathStart: function(e) {
this.scrollNode && (this.calcBoundaries(), this.thumb && this.showThumbs());
},
scrollMathScroll: function(e) {
this.overscroll ? this.effectScroll(-e.x, -e.y) : this.effectScroll(-Math.min(e.leftBoundary, Math.max(e.rightBoundary, e.x)), -Math.min(e.topBoundary, Math.max(e.bottomBoundary, e.y))), this.thumb && this.updateThumbs();
},
scrollMathStop: function(e) {
this.effectScrollStop(), this.thumb && this.delayHideThumbs(100);
},
calcBoundaries: function() {
var e = this.$.scrollMath || this, t = this._getScrollBounds();
e.bottomBoundary = t.clientHeight - t.height, e.rightBoundary = t.clientWidth - t.width;
},
syncScrollMath: function() {
var e = this.$.scrollMath;
e && (e.setScrollX(-this.getScrollLeft()), e.setScrollY(-this.getScrollTop()));
},
effectScroll: function(e, t) {
this.scrollNode && (this.scrollLeft = this.scrollNode.scrollLeft = e, this.scrollTop = this.scrollNode.scrollTop = t, this.effectOverscroll(Math.round(e), Math.round(t)));
},
effectScrollStop: function() {
this.effectOverscroll(null, null);
},
effectOverscroll: function(e, t) {
var n = this.scrollNode, r = "0", i = "0", s = this.accel ? ",0" : "";
t !== null && Math.abs(t - n.scrollTop) > 1 && (i = n.scrollTop - t), e !== null && Math.abs(e - n.scrollLeft) > 1 && (r = n.scrollLeft - e), this.transform ? enyo.dom.transformValue(this.$.client, this.translation, r + "px, " + i + "px" + s) : this.$.client.setBounds({
left: r + "px",
top: i + "px"
});
},
getOverScrollBounds: function() {
var e = this.$.scrollMath || this;
return {
overleft: Math.min(e.leftBoundary - e.x, 0) || Math.max(e.rightBoundary - e.x, 0),
overtop: Math.min(e.topBoundary - e.y, 0) || Math.max(e.bottomBoundary - e.y, 0)
};
},
_getScrollBounds: function() {
var e = this.inherited(arguments);
return enyo.mixin(e, this.getOverScrollBounds()), e;
},
getScrollBounds: function() {
return this.stop(), this.inherited(arguments);
},
alertThumbs: function() {
this.showThumbs(), this.delayHideThumbs(500);
},
syncThumbs: function() {
this.$.vthumb.sync(this), this.$.hthumb.sync(this);
},
updateThumbs: function() {
this.$.vthumb.update(this), this.$.hthumb.update(this);
},
showThumbs: function() {
this.syncThumbs(), this.horizontal != "hidden" && this.$.hthumb.show(), this.vertical != "hidden" && this.$.vthumb.show();
},
hideThumbs: function() {
this.$.vthumb.hide(), this.$.hthumb.hide();
},
delayHideThumbs: function(e) {
this.$.vthumb.delayHide(e), this.$.hthumb.delayHide(e);
}
});

// TranslateScrollStrategy.js

enyo.kind({
name: "enyo.TranslateScrollStrategy",
kind: "TouchScrollStrategy",
translateOptimized: !1,
components: [ {
name: "clientContainer",
classes: "enyo-touch-scroller",
components: [ {
name: "client"
} ]
} ],
rendered: function() {
this.inherited(arguments), enyo.makeBubble(this.$.clientContainer, "scroll");
},
getScrollSize: function() {
var e = this.$.client.hasNode();
return {
width: e ? e.scrollWidth : 0,
height: e ? e.scrollHeight : 0
};
},
create: function() {
this.inherited(arguments), enyo.dom.transformValue(this.$.client, this.translation, "0,0,0");
},
calcScrollNode: function() {
return this.$.clientContainer.hasNode();
},
maxHeightChanged: function() {
this.$.client.applyStyle("min-height", this.maxHeight ? null : "100%"), this.$.client.applyStyle("max-height", this.maxHeight), this.$.clientContainer.addRemoveClass("enyo-scrollee-fit", !this.maxHeight);
},
shouldDrag: function(e, t) {
return this.stop(), this.calcStartInfo(), this.inherited(arguments);
},
syncScrollMath: function() {
this.translateOptimized || this.inherited(arguments);
},
setScrollLeft: function(e) {
this.stop();
if (this.translateOptimized) {
var t = this.$.scrollMath;
t.setScrollX(-e), t.stabilize();
} else this.inherited(arguments);
},
setScrollTop: function(e) {
this.stop();
if (this.translateOptimized) {
var t = this.$.scrollMath;
t.setScrollY(-e), t.stabilize();
} else this.inherited(arguments);
},
getScrollLeft: function() {
return this.translateOptimized ? this.scrollLeft : this.inherited(arguments);
},
getScrollTop: function() {
return this.translateOptimized ? this.scrollTop : this.inherited(arguments);
},
scrollMathStart: function(e) {
this.inherited(arguments), this.scrollStarting = !0, this.startX = 0, this.startY = 0, !this.translateOptimized && this.scrollNode && (this.startX = this.getScrollLeft(), this.startY = this.getScrollTop());
},
scrollMathScroll: function(e) {
this.overscroll ? (this.scrollLeft = -e.x, this.scrollTop = -e.y) : (this.scrollLeft = -Math.min(e.leftBoundary, Math.max(e.rightBoundary, e.x)), this.scrollTop = -Math.min(e.topBoundary, Math.max(e.bottomBoundary, e.y))), this.isScrolling() && (this.$.scrollMath.isScrolling() && this.effectScroll(this.startX - this.scrollLeft, this.startY - this.scrollTop), this.thumb && this.updateThumbs());
},
effectScroll: function(e, t) {
var n = e + "px, " + t + "px" + (this.accel ? ",0" : "");
enyo.dom.transformValue(this.$.client, this.translation, n);
},
effectScrollStop: function() {
if (!this.translateOptimized) {
var e = "0,0" + (this.accel ? ",0" : ""), t = this.$.scrollMath, n = this._getScrollBounds(), r = Boolean(n.maxTop + t.bottomBoundary || n.maxLeft + t.rightBoundary);
enyo.dom.transformValue(this.$.client, this.translation, r ? null : e), this.setScrollLeft(this.scrollLeft), this.setScrollTop(this.scrollTop), r && enyo.dom.transformValue(this.$.client, this.translation, e);
}
},
twiddle: function() {
this.translateOptimized && this.scrollNode && (this.scrollNode.scrollTop = 1, this.scrollNode.scrollTop = 0);
},
down: enyo.nop
});

// TransitionScrollStrategy.js

enyo.kind({
name: "enyo.TransitionScrollStrategy",
kind: "enyo.TouchScrollStrategy",
components: [ {
name: "clientContainer",
classes: "enyo-touch-scroller",
components: [ {
name: "client"
} ]
} ],
events: {
onScrollStart: "",
onScroll: "",
onScrollStop: ""
},
handlers: {
ondown: "down",
ondragfinish: "dragfinish",
onwebkitTransitionEnd: "transitionComplete"
},
tools: [ {
name: "vthumb",
kind: "ScrollThumb",
axis: "v",
showing: !0
}, {
name: "hthumb",
kind: "ScrollThumb",
axis: "h",
showing: !1
} ],
kFlickScalar: 600,
topBoundary: 0,
rightBoundary: 0,
bottomBoundary: 0,
leftBoundary: 0,
scrolling: !1,
listener: null,
boundaryX: 0,
boundaryY: 0,
stopTimeout: null,
stopTimeoutMS: 80,
scrollInterval: null,
scrollIntervalMS: 50,
transitions: {
none: "",
scroll: "3.8s cubic-bezier(.19,1,.28,1.0) 0s",
bounce: "0.5s cubic-bezier(0.06,.5,.5,.94) 0s"
},
setScrollLeft: function(e) {
var t = this.scrollLeft;
this.stop(), this.scrollLeft = e;
if (this.isInLeftOverScroll() || this.isInRightOverScroll()) this.scrollLeft = t;
this.effectScroll();
},
setScrollTop: function(e) {
var t = this.scrollTop;
this.stop(), this.scrollTop = e;
if (this.isInTopOverScroll() || this.isInBottomOverScroll()) this.scrollTop = t;
this.effectScroll();
},
setScrollX: function(e) {
this.scrollLeft = -1 * e;
},
setScrollY: function(e) {
this.scrollTop = -1 * e;
},
getScrollLeft: function() {
return this.scrollLeft;
},
getScrollTop: function() {
return this.scrollTop;
},
create: function() {
this.inherited(arguments), enyo.dom.transformValue(this.$.client, this.translation, "0,0,0");
},
destroy: function() {
this.clearCSSTransitionInterval(), this.inherited(arguments);
},
getScrollSize: function() {
var e = this.$.client.hasNode();
return {
width: e ? e.scrollWidth : 0,
height: e ? e.scrollHeight : 0
};
},
horizontalChanged: function() {
this.horizontal == "hidden" && (this.scrollHorizontal = !1);
},
verticalChanged: function() {
this.vertical == "hidden" && (this.scrollVertical = !1);
},
calcScrollNode: function() {
return this.$.clientContainer.hasNode();
},
calcBoundaries: function() {
var e = this._getScrollBounds();
this.bottomBoundary = e.clientHeight - e.height, this.rightBoundary = e.clientWidth - e.width;
},
maxHeightChanged: function() {
this.$.client.applyStyle("min-height", this.maxHeight ? null : "100%"), this.$.client.applyStyle("max-height", this.maxHeight), this.$.clientContainer.addRemoveClass("enyo-scrollee-fit", !this.maxHeight);
},
calcAutoScrolling: function() {
var e = this.getScrollBounds();
this.vertical && (this.scrollVertical = e.height > e.clientHeight), this.horizontal && (this.scrollHorizontal = e.width > e.clientWidth);
},
isInOverScroll: function() {
return this.isInTopOverScroll() || this.isInBottomOverScroll() || this.isInLeftOverScroll() || this.isInRightOverScroll();
},
isInLeftOverScroll: function() {
return this.getScrollLeft() < this.leftBoundary;
},
isInRightOverScroll: function() {
return this.getScrollLeft <= 0 ? !1 : this.getScrollLeft() * -1 < this.rightBoundary;
},
isInTopOverScroll: function() {
return this.getScrollTop() < this.topBoundary;
},
isInBottomOverScroll: function() {
return this.getScrollTop() <= 0 ? !1 : this.getScrollTop() * -1 < this.bottomBoundary;
},
calcStartInfo: function() {
var e = this.getScrollBounds(), t = this.getScrollTop(), n = this.getScrollLeft();
this.startEdges = {
top: t === 0,
bottom: t === e.maxTop,
left: n === 0,
right: n === e.maxLeft
};
},
mousewheel: function(e, t) {
if (!this.dragging) {
this.calcBoundaries(), this.syncScrollMath(), this.stabilize();
var n = this.vertical ? t.wheelDeltaY || t.wheelDelta : 0, r = parseFloat(this.getScrollTop()) + -1 * parseFloat(n);
return r = r * -1 < this.bottomBoundary ? -1 * this.bottomBoundary : r < this.topBoundary ? this.topBoundary : r, this.setScrollTop(r), this.doScroll(), t.preventDefault(), !0;
}
},
scroll: function(e, t) {
this.thumb && this.updateThumbs(), this.calcBoundaries(), this.doScroll();
},
start: function() {
this.startScrolling(), this.doScrollStart();
},
stop: function() {
this.isScrolling() && this.stopScrolling(), this.thumb && this.delayHideThumbs(100), this.doScrollStop();
},
updateX: function() {
var e = window.getComputedStyle(this.$.client.node, null).getPropertyValue(enyo.dom.getCssTransformProp()).split("(")[1];
return e = e == undefined ? 0 : e.split(")")[0].split(",")[4], -1 * parseFloat(e) === this.scrollLeft ? !1 : (this.scrollLeft = -1 * parseFloat(e), !0);
},
updateY: function() {
var e = window.getComputedStyle(this.$.client.node, null).getPropertyValue(enyo.dom.getCssTransformProp()).split("(")[1];
return e = e == undefined ? 0 : e.split(")")[0].split(",")[5], -1 * parseFloat(e) === this.scrollTop ? !1 : (this.scrollTop = -1 * parseFloat(e), !0);
},
effectScroll: function() {
var e = -1 * this.scrollLeft + "px, " + -1 * this.scrollTop + "px" + (this.accel ? ", 0" : "");
enyo.dom.transformValue(this.$.client, this.translation, e);
},
down: function(e, t) {
var n = this;
if (this.isScrolling() && !this.isOverscrolling()) return this.stopTimeout = setTimeout(function() {
n.stop();
}, this.stopTimeoutMS), !0;
},
dragstart: function(e, t) {
this.stopTimeout && clearTimeout(this.stopTimeout);
if (!this.dragDuringGesture && t.srcEvent.touches && t.srcEvent.touches.length > 1) return !0;
this.shouldDrag(t), this.dragging = t.dragger == this || !t.dragger && t.boundaryDragger == this;
if (this.dragging) {
this.isScrolling() && this.stopScrolling(), this.thumb && this.showThumbs(), t.preventDefault(), this.prevY = t.pageY, this.prevX = t.pageX;
if (this.preventDragPropagation) return !0;
}
},
shouldDrag: function(e) {
return this.calcStartInfo(), this.calcBoundaries(), this.calcAutoScrolling(), this.scrollHorizontal ? this.scrollVertical ? this.shouldDragVertical(e) || this.shouldDragHorizontal(e) : this.shouldDragHorizontal(e) : this.shouldDragVertical(e);
},
shouldDragVertical: function(e) {
var t = this.canDragVertical(e), n = this.oobVertical(e);
!e.boundaryDragger && t && (e.boundaryDragger = this);
if (!n && t) return e.dragger = this, !0;
},
shouldDragHorizontal: function(e) {
var t = this.canDragHorizontal(e), n = this.oobHorizontal(e);
!e.boundaryDragger && t && (e.boundaryDragger = this);
if (!n && t) return e.dragger = this, !0;
},
canDragVertical: function(e) {
return this.scrollVertical && e.vertical;
},
canDragHorizontal: function(e) {
return this.scrollHorizontal && !e.vertical;
},
oobVertical: function(e) {
var t = e.dy < 0;
return !t && this.startEdges.top || t && this.startEdges.bottom;
},
oobHorizontal: function(e) {
var t = e.dx < 0;
return !t && this.startEdges.left || t && this.startEdges.right;
},
drag: function(e, t) {
if (this.listReordering) return !1;
this.dragging && (t.preventDefault(), this.scrollLeft = this.scrollHorizontal ? this.calculateDragDistance(parseInt(this.getScrollLeft(), 10), -1 * (t.pageX - this.prevX), this.leftBoundary, this.rightBoundary) : this.getScrollLeft(), this.scrollTop = this.scrollVertical ? this.calculateDragDistance(this.getScrollTop(), -1 * (t.pageY - this.prevY), this.topBoundary, this.bottomBoundary) : this.getScrollTop(), this.effectScroll(), this.scroll(), this.prevY = t.pageY, this.prevX = t.pageX, this.resetBoundaryX(), this.resetBoundaryY());
},
calculateDragDistance: function(e, t, n, r) {
var i = e + t;
return this.overscrollDragDamping(e, i, t, n, r);
},
overscrollDragDamping: function(e, t, n, r, i) {
if (t < r || t * -1 < i) n /= 2, t = e + n;
return t;
},
resetBoundaryX: function() {
this.boundaryX = 0;
},
resetBoundaryY: function() {
this.boundaryY = 0;
},
dragfinish: function(e, t) {
this.dragging && (t.preventTap(), this.dragging = !1, this.isScrolling() || this.correctOverflow(), this.scrim && this.$.scrim.hide());
},
correctOverflow: function() {
if (this.isInOverScroll()) {
var e = this.scrollHorizontal ? this.correctOverflowX() : !1, t = this.scrollVertical ? this.correctOverflowY() : !1;
e !== !1 && t !== !1 ? (this.scrollLeft = e !== !1 ? e : this.getScrollLeft(), this.scrollTop = t !== !1 ? t : this.getScrollTop(), this.startOverflowScrolling()) : e !== !1 ? (this.scrollLeft = e, this.scrollTop = this.targetScrollTop || this.scrollTop, this.targetScrollLeft = this.getScrollLeft(), this.vertical ? this.startScrolling() : this.startOverflowScrolling()) : t !== !1 && (this.scrollTop = t, this.scrollLeft = this.targetScrollLeft || this.scrollLeft, this.targetScrollTop = this.getScrollTop(), this.scrollHorizontal ? this.startScrolling() : this.startOverflowScrolling());
}
},
correctOverflowX: function() {
if (this.isInLeftOverScroll()) {
if (this.beyondBoundary(this.getScrollLeft(), this.leftBoundary, this.boundaryX)) return this.leftBoundary;
} else if (this.isInRightOverScroll() && this.beyondBoundary(this.getScrollLeft(), this.rightBoundary, this.boundaryX)) return -1 * this.rightBoundary;
return !1;
},
correctOverflowY: function() {
if (this.isInTopOverScroll()) {
if (this.beyondBoundary(this.getScrollTop(), this.topBoundary, this.boundaryY)) return this.topBoundary;
} else if (this.isInBottomOverScroll() && this.beyondBoundary(this.getScrollTop(), this.bottomBoundary, this.boundaryY)) return -1 * this.bottomBoundary;
return !1;
},
beyondBoundary: function(e, t, n) {
return Math.abs(Math.abs(t) - Math.abs(e)) > Math.abs(n);
},
flick: function(e, t) {
if (this.dragging && this.flickOnEnabledAxis(t)) return this.scrollLeft = this.scrollHorizontal ? this.calculateFlickDistance(this.scrollLeft, -1 * t.xVelocity) : this.getScrollLeft(), this.scrollTop = this.scrollVertical ? this.calculateFlickDistance(this.scrollTop, -1 * t.yVelocity) : this.getScrollTop(), this.targetScrollLeft = this.scrollLeft, this.targetScrollTop = this.scrollTop, this.boundaryX = null, this.boundaryY = null, this.isInLeftOverScroll() ? this.boundaryX = this.figureBoundary(this.getScrollLeft()) : this.isInRightOverScroll() && (this.boundaryX = this.figureBoundary(-1 * this.bottomBoundary - this.getScrollLeft())), this.isInTopOverScroll() ? this.boundaryY = this.figureBoundary(this.getScrollTop()) : this.isInBottomOverScroll() && (this.boundaryY = this.figureBoundary(-1 * this.bottomBoundary - this.getScrollTop())), this.startScrolling(), this.preventDragPropagation;
},
flickOnEnabledAxis: function(e) {
return Math.abs(e.xVelocity) > Math.abs(e.yVelocity) ? this.scrollHorizontal : this.scrollVertical;
},
calculateFlickDistance: function(e, t) {
return e + t * this.kFlickScalar;
},
startScrolling: function() {
this.applyTransition("scroll"), this.effectScroll(), this.setCSSTransitionInterval(), this.scrolling = !0;
},
startOverflowScrolling: function() {
this.applyTransition("bounce"), this.effectScroll(), this.setOverflowTransitionInterval(), this.scrolling = !0;
},
applyTransition: function(e) {
var t = this.translation + ": " + this.transitions[e];
this.$.client.applyStyle("-webkit-transition", this.transitions[e]);
},
stopScrolling: function() {
this.resetCSSTranslationVals(), this.clearCSSTransitionInterval(), this.scrolling = !1;
},
setCSSTransitionInterval: function() {
this.clearCSSTransitionInterval(), this.scrollInterval = setInterval(enyo.bind(this, function() {
this.updateScrollPosition(), this.correctOverflow();
}), this.scrollIntervalMS);
},
setOverflowTransitionInterval: function() {
this.clearCSSTransitionInterval(), this.scrollInterval = setInterval(enyo.bind(this, function() {
this.updateScrollPosition();
}), this.scrollIntervalMS);
},
updateScrollPosition: function() {
var e = this.updateY(), t = this.updateX();
this.scroll(), !e && !t && this.stop();
},
clearCSSTransitionInterval: function() {
this.scrollInterval && (clearInterval(this.scrollInterval), this.scrollInterval = null);
},
resetCSSTranslationVals: function() {
var e = enyo.dom.getCssTransformProp(), t = window.getComputedStyle(this.$.client.node, null).getPropertyValue(e).split("(")[1].split(")")[0].split(",");
this.applyTransition("none"), this.scrollLeft = -1 * t[4], this.scrollTop = -1 * t[5], this.effectScroll();
},
figureBoundary: function(e) {
var t = Math.abs(e), n = t - t / Math.pow(t, .02);
return n = e < 0 ? -1 * n : n, n;
},
transitionComplete: function(e, t) {
if (t.originator !== this.$.client) return;
var n = !1;
this.isInTopOverScroll() ? (n = !0, this.scrollTop = this.topBoundary) : this.isInBottomOverScroll() && (n = !0, this.scrollTop = -1 * this.bottomBoundary), this.isInLeftOverScroll() ? (n = !0, this.scrollLeft = this.leftBoundary) : this.isInRightOverScroll() && (n = !0, this.scrollLeft = -1 * this.rightBoundary), n ? this.startOverflowScrolling() : this.stop();
},
scrollTo: function(e, t) {
this.setScrollTop(t), this.setScrollLeft(e), this.start();
},
getOverScrollBounds: function() {
return {
overleft: Math.min(this.leftBoundary + this.scrollLeft, 0) || Math.max(this.rightBoundary + this.scrollLeft, 0),
overtop: Math.min(this.topBoundary + this.scrollTop, 0) || Math.max(this.bottomBoundary + this.scrollTop, 0)
};
}
});

// Scroller.js

enyo.kind({
name: "enyo.Scroller",
published: {
horizontal: "default",
vertical: "default",
scrollTop: 0,
scrollLeft: 0,
maxHeight: null,
touch: !1,
strategyKind: "ScrollStrategy",
thumb: !0
},
events: {
onScrollStart: "",
onScroll: "",
onScrollStop: ""
},
touchOverscroll: !0,
preventDragPropagation: !0,
preventScrollPropagation: !0,
handlers: {
onscroll: "domScroll",
onScrollStart: "scrollStart",
onScroll: "scroll",
onScrollStop: "scrollStop"
},
classes: "enyo-scroller",
statics: {
osInfo: [ {
os: "android",
version: 3
}, {
os: "androidChrome",
version: 18
}, {
os: "androidFirefox",
version: 16
}, {
os: "firefoxOS",
version: 16
}, {
os: "ios",
version: 5
}, {
os: "webos",
version: 1e9
}, {
os: "blackberry",
version: 1e9
} ],
hasTouchScrolling: function() {
for (var e = 0, t, n; t = this.osInfo[e]; e++) if (enyo.platform[t.os]) return !0;
if ((enyo.platform.ie >= 10 || enyo.platform.windowsPhone >= 8) && enyo.platform.touch) return !0;
},
hasNativeScrolling: function() {
for (var e = 0, t, n; t = this.osInfo[e]; e++) if (enyo.platform[t.os] < t.version) return !1;
return !0;
},
getTouchStrategy: function() {
return enyo.platform.android >= 3 || enyo.platform.windowsPhone === 8 ? "TranslateScrollStrategy" : "TouchScrollStrategy";
}
},
controlParentName: "strategy",
create: function() {
this.inherited(arguments), this.horizontalChanged(), this.verticalChanged();
},
importProps: function(e) {
this.inherited(arguments), e && e.strategyKind === undefined && (enyo.Scroller.touchScrolling || this.touch) && (this.strategyKind = enyo.Scroller.getTouchStrategy());
},
initComponents: function() {
this.strategyKindChanged(), this.inherited(arguments);
},
teardownChildren: function() {
this.cacheScrollPosition(), this.inherited(arguments);
},
rendered: function() {
this.inherited(arguments), this.restoreScrollPosition();
},
strategyKindChanged: function() {
this.$.strategy && (this.$.strategy.destroy(), this.controlParent = null), this.createStrategy(), this.hasNode() && this.render();
},
createStrategy: function() {
this.createComponents([ {
name: "strategy",
maxHeight: this.maxHeight,
kind: this.strategyKind,
thumb: this.thumb,
preventDragPropagation: this.preventDragPropagation,
overscroll: this.touchOverscroll,
isChrome: !0
} ]);
},
getStrategy: function() {
return this.$.strategy;
},
maxHeightChanged: function() {
this.$.strategy.setMaxHeight(this.maxHeight);
},
showingChanged: function() {
this.showing || (this.cacheScrollPosition(), this.setScrollLeft(0), this.setScrollTop(0)), this.inherited(arguments), this.showing && this.restoreScrollPosition();
},
thumbChanged: function() {
this.$.strategy.setThumb(this.thumb);
},
cacheScrollPosition: function() {
this.cachedPosition = {
left: this.getScrollLeft(),
top: this.getScrollTop()
};
},
restoreScrollPosition: function() {
this.cachedPosition && (this.setScrollLeft(this.cachedPosition.left), this.setScrollTop(this.cachedPosition.top), this.cachedPosition = null);
},
horizontalChanged: function() {
this.$.strategy.setHorizontal(this.horizontal);
},
verticalChanged: function() {
this.$.strategy.setVertical(this.vertical);
},
setScrollLeft: function(e) {
this.scrollLeft = e, this.$.strategy.setScrollLeft(this.scrollLeft);
},
setScrollTop: function(e) {
this.scrollTop = e, this.$.strategy.setScrollTop(e);
},
getScrollLeft: function() {
return this.$.strategy.getScrollLeft();
},
getScrollTop: function() {
return this.$.strategy.getScrollTop();
},
getScrollBounds: function() {
return this.$.strategy.getScrollBounds();
},
scrollIntoView: function(e, t) {
this.$.strategy.scrollIntoView(e, t);
},
scrollTo: function(e, t) {
this.$.strategy.scrollTo(e, t);
},
scrollToControl: function(e, t) {
this.scrollToNode(e.hasNode(), t);
},
scrollToNode: function(e, t) {
this.$.strategy.scrollToNode(e, t);
},
domScroll: function(e, t) {
return this.$.strategy.domScroll && t.originator == this && this.$.strategy.scroll(e, t), this.doScroll(t), !0;
},
shouldStopScrollEvent: function(e) {
return this.preventScrollPropagation && e.originator.owner != this.$.strategy;
},
scrollStart: function(e, t) {
return this.shouldStopScrollEvent(t);
},
scroll: function(e, t) {
return t.dispatchTarget ? this.preventScrollPropagation && t.originator != this && t.originator.owner != this.$.strategy : this.shouldStopScrollEvent(t);
},
scrollStop: function(e, t) {
return this.shouldStopScrollEvent(t);
},
scrollToTop: function() {
this.setScrollTop(0);
},
scrollToBottom: function() {
this.setScrollTop(this.getScrollBounds().maxTop);
},
scrollToRight: function() {
this.setScrollLeft(this.getScrollBounds().maxLeft);
},
scrollToLeft: function() {
this.setScrollLeft(0);
},
stabilize: function() {
var e = this.getStrategy();
e.stabilize && e.stabilize();
}
}), enyo.Scroller.hasTouchScrolling() && (enyo.Scroller.prototype.strategyKind = enyo.Scroller.getTouchStrategy());

// Animator.js

enyo.kind({
name: "enyo.Animator",
kind: "Component",
published: {
duration: 350,
startValue: 0,
endValue: 1,
node: null,
easingFunction: enyo.easing.cubicOut
},
events: {
onStep: "",
onEnd: "",
onStop: ""
},
constructed: function() {
this.inherited(arguments), this._next = enyo.bind(this, "next");
},
destroy: function() {
this.stop(), this.inherited(arguments);
},
play: function(e) {
return this.stop(), this.reversed = !1, e && enyo.mixin(this, e), this.t0 = this.t1 = enyo.now(), this.value = this.startValue, this.job = !0, this.next(), this;
},
stop: function() {
if (this.isAnimating()) return this.cancel(), this.fire("onStop"), this;
},
reverse: function() {
if (this.isAnimating()) {
this.reversed = !this.reversed;
var e = this.t1 = enyo.now(), t = e - this.t0;
this.t0 = e + t - this.duration;
var n = this.startValue;
return this.startValue = this.endValue, this.endValue = n, this;
}
},
isAnimating: function() {
return Boolean(this.job);
},
requestNext: function() {
this.job = enyo.requestAnimationFrame(this._next, this.node);
},
cancel: function() {
enyo.cancelRequestAnimationFrame(this.job), this.node = null, this.job = null;
},
shouldEnd: function() {
return this.dt >= this.duration;
},
next: function() {
this.t1 = enyo.now(), this.dt = this.t1 - this.t0;
var e = this.fraction = enyo.easedLerp(this.t0, this.duration, this.easingFunction, this.reversed);
this.value = this.startValue + e * (this.endValue - this.startValue), e >= 1 || this.shouldEnd() ? (this.value = this.endValue, this.fraction = 1, this.fire("onStep"), this.fire("onEnd"), this.cancel()) : (this.fire("onStep"), this.requestNext());
},
fire: function(e) {
var t = this[e];
enyo.isString(t) ? this.bubble(e) : t && t.call(this.context || window, this);
}
});

// BaseLayout.js

enyo.kind({
name: "enyo.BaseLayout",
kind: enyo.Layout,
layoutClass: "enyo-positioned",
reflow: function() {
enyo.forEach(this.container.children, function(e) {
e.fit !== null && e.addRemoveClass("enyo-fit", e.fit);
}, this);
}
});

// Image.js

enyo.kind({
name: "enyo.Image",
noEvents: !1,
tag: "img",
attributes: {
draggable: "false"
},
create: function() {
this.noEvents && (delete this.attributes.onload, delete this.attributes.onerror), this.inherited(arguments);
},
rendered: function() {
this.inherited(arguments), enyo.makeBubble(this, "load", "error");
}
});

// Input.js

enyo.kind({
name: "enyo.Input",
published: {
value: "",
placeholder: "",
type: "",
disabled: !1,
selectOnFocus: !1
},
events: {
onDisabledChange: ""
},
defaultFocus: !1,
tag: "input",
classes: "enyo-input",
handlers: {
onfocus: "focused",
oninput: "input",
onclear: "clear",
ondragstart: "dragstart"
},
create: function() {
enyo.platform.ie && (this.handlers.onkeyup = "iekeyup"), enyo.platform.windowsPhone && (this.handlers.onkeydown = "iekeydown"), this.inherited(arguments), this.placeholderChanged(), this.type && this.typeChanged(), this.valueChanged();
},
rendered: function() {
this.inherited(arguments), enyo.makeBubble(this, "focus", "blur"), enyo.platform.ie == 8 && this.setAttribute("onchange", enyo.bubbler), this.disabledChanged(), this.defaultFocus && this.focus();
},
typeChanged: function() {
this.setAttribute("type", this.type);
},
placeholderChanged: function() {
this.setAttribute("placeholder", this.placeholder);
},
disabledChanged: function() {
this.setAttribute("disabled", this.disabled), this.bubble("onDisabledChange");
},
getValue: function() {
return this.getNodeProperty("value", this.value);
},
valueChanged: function() {
this.setAttribute("value", this.value), this.setNodeProperty("value", this.value);
},
iekeyup: function(e, t) {
var n = enyo.platform.ie, r = t.keyCode;
(n <= 8 || n == 9 && (r == 8 || r == 46)) && this.bubble("oninput", t);
},
iekeydown: function(e, t) {
var n = enyo.platform.windowsPhone, r = t.keyCode, i = t.dispatchTarget;
n <= 8 && r == 13 && this.tag == "input" && i.hasNode() && i.node.blur();
},
clear: function() {
this.setValue("");
},
focus: function() {
this.hasNode() && this.node.focus();
},
hasFocus: function() {
if (this.hasNode()) return document.activeElement === this.node;
},
dragstart: function() {
return this.hasFocus();
},
focused: function() {
this.selectOnFocus && enyo.asyncMethod(this, "selectContents");
},
selectContents: function() {
var e = this.hasNode();
if (e && e.setSelectionRange) e.setSelectionRange(0, e.value.length); else if (e && e.createTextRange) {
var t = e.createTextRange();
t.expand("textedit"), t.select();
}
}
});

// RichText.js

enyo.kind({
name: "enyo.RichText",
classes: "enyo-richtext enyo-selectable",
published: {
allowHtml: !0,
disabled: !1,
value: ""
},
defaultFocus: !1,
statics: {
osInfo: [ {
os: "android",
version: 3
}, {
os: "ios",
version: 5
} ],
hasContentEditable: function() {
for (var e = 0, t, n; t = enyo.RichText.osInfo[e]; e++) if (enyo.platform[t.os] < t.version) return !1;
return !0;
}
},
kind: enyo.Input,
attributes: {
contenteditable: !0
},
handlers: {
onfocus: "focusHandler",
onblur: "blurHandler"
},
create: function() {
this.setTag(enyo.RichText.hasContentEditable() ? "div" : "textarea"), this.inherited(arguments);
},
focusHandler: function() {
this._value = this.getValue();
},
blurHandler: function() {
this._value !== this.getValue() && this.bubble("onchange");
},
valueChanged: function() {
this.hasFocus() ? (this.selectAll(), this.insertAtCursor(this.value)) : this.setPropertyValue("content", this.value, "contentChanged");
},
getValue: function() {
if (this.hasNode()) return this.node.innerHTML;
},
hasFocus: function() {
if (this.hasNode()) return document.activeElement === this.node;
},
getSelection: function() {
if (this.hasFocus()) return window.getSelection();
},
removeSelection: function(e) {
var t = this.getSelection();
t && t[e ? "collapseToStart" : "collapseToEnd"]();
},
modifySelection: function(e, t, n) {
var r = this.getSelection();
r && r.modify(e || "move", t, n);
},
moveCursor: function(e, t) {
this.modifySelection("move", e, t);
},
moveCursorToEnd: function() {
this.moveCursor("forward", "documentboundary");
},
moveCursorToStart: function() {
this.moveCursor("backward", "documentboundary");
},
selectAll: function() {
this.hasFocus() && document.execCommand("selectAll");
},
insertAtCursor: function(e) {
if (this.hasFocus()) {
var t = this.allowHtml ? e : enyo.Control.escapeHtml(e).replace(/\n/g, "<br/>");
document.execCommand("insertHTML", !1, t);
}
}
});

// TextArea.js

enyo.kind({
name: "enyo.TextArea",
kind: enyo.Input,
tag: "textarea",
classes: "enyo-textarea",
rendered: function() {
this.inherited(arguments), this.valueChanged();
}
});

// Select.js

enyo.kind({
name: "enyo.Select",
published: {
selected: 0
},
handlers: {
onchange: "change"
},
tag: "select",
defaultKind: "enyo.Option",
rendered: function() {
this.inherited(arguments), enyo.platform.ie == 8 && this.setAttribute("onchange", enyo.bubbler), this.selectedChanged();
},
getSelected: function() {
return Number(this.getNodeProperty("selectedIndex", this.selected));
},
setSelected: function(e) {
this.setPropertyValue("selected", Number(e), "selectedChanged");
},
selectedChanged: function() {
this.setNodeProperty("selectedIndex", this.selected);
},
change: function() {
this.selected = this.getSelected();
},
render: function() {
enyo.platform.ie ? this.parent.render() : this.inherited(arguments);
},
getValue: function() {
if (this.hasNode()) return this.node.value;
}
}), enyo.kind({
name: "enyo.Option",
published: {
value: ""
},
tag: "option",
create: function() {
this.inherited(arguments), this.valueChanged();
},
valueChanged: function() {
this.setAttribute("value", this.value);
}
}), enyo.kind({
name: "enyo.OptionGroup",
published: {
label: ""
},
tag: "optgroup",
defaultKind: "enyo.Option",
create: function() {
this.inherited(arguments), this.labelChanged();
},
labelChanged: function() {
this.setAttribute("label", this.label);
}
});

// Group.js

enyo.kind({
name: "enyo.Group",
published: {
highlander: !0,
active: null
},
handlers: {
onActivate: "activate"
},
activate: function(e, t) {
this.highlander && (t.originator.active ? this.setActive(t.originator) : t.originator == this.active && this.active.setActive(!0));
},
activeChanged: function(e) {
e && (e.setActive(!1), e.removeClass("active")), this.active && this.active.addClass("active");
}
});

// GroupItem.js

enyo.kind({
name: "enyo.GroupItem",
published: {
active: !1
},
rendered: function() {
this.inherited(arguments), this.activeChanged();
},
activeChanged: function() {
this.bubble("onActivate");
}
});

// ToolDecorator.js

enyo.kind({
name: "enyo.ToolDecorator",
kind: enyo.GroupItem,
classes: "enyo-tool-decorator"
});

// Button.js

enyo.kind({
name: "enyo.Button",
kind: enyo.ToolDecorator,
tag: "button",
attributes: {
type: "button"
},
published: {
disabled: !1
},
create: function() {
this.inherited(arguments), this.disabledChanged();
},
disabledChanged: function() {
this.setAttribute("disabled", this.disabled);
},
tap: function() {
if (this.disabled) return !0;
this.setActive(!0);
}
});

// Checkbox.js

enyo.kind({
name: "enyo.Checkbox",
kind: enyo.Input,
classes: "enyo-checkbox",
events: {
onActivate: ""
},
published: {
checked: !1,
active: !1,
type: "checkbox"
},
kindClasses: "",
handlers: {
onchange: "change",
onclick: "click"
},
create: function() {
this.inherited(arguments);
},
rendered: function() {
this.inherited(arguments), this.active && this.activeChanged(), this.checkedChanged();
},
getChecked: function() {
return enyo.isTrue(this.getNodeProperty("checked", this.checked));
},
checkedChanged: function() {
this.setNodeProperty("checked", this.checked), this.setAttribute("checked", this.checked ? "checked" : ""), this.setActive(this.checked);
},
activeChanged: function() {
this.active = enyo.isTrue(this.active), this.setChecked(this.active), this.bubble("onActivate");
},
setValue: function(e) {
this.setChecked(enyo.isTrue(e));
},
getValue: function() {
return this.getChecked();
},
valueChanged: function() {},
change: function() {
this.setActive(this.getChecked());
},
click: function(e, t) {
enyo.platform.ie <= 8 && this.bubble("onchange", t);
}
});

// Repeater.js

enyo.kind({
name: "enyo.Repeater",
published: {
count: 0
},
events: {
onSetupItem: ""
},
create: function() {
this.inherited(arguments), this.countChanged();
},
initComponents: function() {
this.itemComponents = this.components || this.kindComponents, this.components = this.kindComponents = null, this.inherited(arguments);
},
setCount: function(e) {
this.setPropertyValue("count", e, "countChanged");
},
countChanged: function() {
this.build();
},
itemAtIndex: function(e) {
return this.controlAtIndex(e);
},
build: function() {
this.destroyClientControls();
for (var e = 0, t; e < this.count; e++) t = this.createComponent({
kind: "enyo.OwnerProxy",
index: e
}), t.createComponents(this.itemComponents), this.doSetupItem({
index: e,
item: t
});
this.render();
},
renderRow: function(e) {
var t = this.itemAtIndex(e);
this.doSetupItem({
index: e,
item: t
});
}
}), enyo.kind({
name: "enyo.OwnerProxy",
tag: null,
decorateEvent: function(e, t, n) {
t && (t.index = this.index), this.inherited(arguments);
},
delegateEvent: function(e, t, n, r, i) {
return e == this && (e = this.owner.owner), this.inherited(arguments, [ e, t, n, r, i ]);
}
});

// DragAvatar.js

enyo.kind({
name: "enyo._DragAvatar",
style: "position: absolute; z-index: 10; pointer-events: none; cursor: move;",
showing: !1,
showingChanged: function() {
this.inherited(arguments), document.body.style.cursor = this.showing ? "move" : null;
}
}), enyo.kind({
name: "enyo.DragAvatar",
kind: enyo.Component,
published: {
showing: !1,
offsetX: 20,
offsetY: 30
},
initComponents: function() {
this.avatarComponents = this.components, this.components = null, this.inherited(arguments);
},
requireAvatar: function() {
this.avatar || (this.avatar = this.createComponent({
kind: enyo._DragAvatar,
parentNode: document.body,
showing: !1,
components: this.avatarComponents
}).render());
},
showingChanged: function() {
this.avatar.setShowing(this.showing), document.body.style.cursor = this.showing ? "move" : null;
},
drag: function(e) {
this.requireAvatar(), this.avatar.setBounds({
top: e.pageY - this.offsetY,
left: e.pageX + this.offsetX
}), this.show();
},
show: function() {
this.setShowing(!0);
},
hide: function() {
this.setShowing(!1);
}
});

// FloatingLayer.js

enyo.kind({
name: "enyo.FloatingLayer",
create: function() {
this.inherited(arguments), this.setParent(null);
},
render: function() {
return this.parentNode = document.body, this.inherited(arguments);
},
generateInnerHtml: function() {
return "";
},
beforeChildRender: function() {
this.hasNode() || this.render();
},
teardownChildren: function() {}
}), enyo.floatingLayer = new enyo.FloatingLayer;

// Popup.js

enyo.kind({
name: "enyo.Popup",
classes: "enyo-popup enyo-no-touch-action",
published: {
modal: !1,
autoDismiss: !0,
floating: !1,
centered: !1
},
showing: !1,
handlers: {
ondown: "down",
onkeydown: "keydown",
ondragstart: "dragstart",
onfocus: "focus",
onblur: "blur",
onRequestShow: "requestShow",
onRequestHide: "requestHide"
},
captureEvents: !0,
events: {
onShow: "",
onHide: ""
},
tools: [ {
kind: "Signals",
onKeydown: "keydown"
} ],
create: function() {
this.inherited(arguments), this.canGenerate = !this.floating;
},
render: function() {
this.floating && (enyo.floatingLayer.hasNode() || enyo.floatingLayer.render(), this.parentNode = enyo.floatingLayer.hasNode()), this.inherited(arguments);
},
destroy: function() {
this.showing && this.release(), this.inherited(arguments);
},
reflow: function() {
this.updatePosition(), this.inherited(arguments);
},
calcViewportSize: function() {
if (window.innerWidth) return {
width: window.innerWidth,
height: window.innerHeight
};
var e = document.documentElement;
return {
width: e.offsetWidth,
height: e.offsetHeight
};
},
updatePosition: function() {
var e = this.calcViewportSize(), t = this.getBounds();
if (this.targetPosition) {
var n = this.targetPosition;
typeof n.left == "number" ? n.left + t.width > e.width ? (n.left - t.width >= 0 ? n.right = e.width - n.left : n.right = 0, n.left = null) : n.right = null : typeof n.right == "number" && (n.right + t.width > e.width ? (n.right - t.width >= 0 ? n.left = e.width - n.right : n.left = 0, n.right = null) : n.left = null), typeof n.top == "number" ? n.top + t.height > e.height ? (n.top - t.height >= 0 ? n.bottom = e.height - n.top : n.bottom = 0, n.top = null) : n.bottom = null : typeof n.bottom == "number" && (n.bottom + t.height > e.height ? (n.bottom - t.height >= 0 ? n.top = e.height - n.bottom : n.top = 0, n.bottom = null) : n.top = null), this.addStyles("left: " + (n.left !== null ? n.left + "px" : "initial") + "; right: " + (n.right !== null ? n.right + "px" : "initial") + "; top: " + (n.top !== null ? n.top + "px" : "initial") + "; bottom: " + (n.bottom !== null ? n.bottom + "px" : "initial") + ";");
} else this.centered && this.addStyles("top: " + Math.max((e.height - t.height) / 2, 0) + "px; left: " + Math.max((e.width - t.width) / 2, 0) + "px;");
},
showingChanged: function() {
this.floating && this.showing && !this.hasNode() && this.render();
if (this.centered || this.targetPosition) this.applyStyle("visibility", "hidden"), this.addStyles("top: 0px; left: 0px; right: initial; bottom: initial;");
this.inherited(arguments), this.showing ? (this.resized(), this.captureEvents && this.capture()) : this.captureEvents && this.release(), (this.centered || this.targetPosition) && this.applyStyle("visibility", null), this.hasNode() && this[this.showing ? "doShow" : "doHide"]();
},
capture: function() {
enyo.dispatcher.capture(this, !this.modal);
},
release: function() {
enyo.dispatcher.release();
},
down: function(e, t) {
this.downEvent = t, this.modal && !t.dispatchTarget.isDescendantOf(this) && t.preventDefault();
},
tap: function(e, t) {
if (this.autoDismiss && !t.dispatchTarget.isDescendantOf(this) && this.downEvent && !this.downEvent.dispatchTarget.isDescendantOf(this)) return this.downEvent = null, this.hide(), !0;
},
dragstart: function(e, t) {
var n = t.dispatchTarget === this || t.dispatchTarget.isDescendantOf(this);
return e.autoDismiss && !n && e.setShowing(!1), !0;
},
keydown: function(e, t) {
this.showing && this.autoDismiss && t.keyCode == 27 && this.hide();
},
blur: function(e, t) {
t.dispatchTarget.isDescendantOf(this) && (this.lastFocus = t.originator);
},
focus: function(e, t) {
var n = t.dispatchTarget;
if (this.modal && !n.isDescendantOf(this)) {
n.hasNode() && n.node.blur();
var r = this.lastFocus && this.lastFocus.hasNode() || this.hasNode();
r && r.focus();
}
},
requestShow: function(e, t) {
return this.show(), !0;
},
requestHide: function(e, t) {
return this.hide(), !0;
},
showAtEvent: function(e, t) {
var n = {
left: e.centerX || e.clientX || e.pageX,
top: e.centerY || e.clientY || e.pageY
};
t && (n.left += t.left || 0, n.top += t.top || 0), this.showAtPosition(n);
},
showAtPosition: function(e) {
this.targetPosition = e, this.show();
}
});

// Selection.js

enyo.kind({
name: "enyo.Selection",
kind: enyo.Component,
published: {
multi: !1
},
events: {
onSelect: "",
onDeselect: "",
onChange: ""
},
create: function() {
this.clear(), this.inherited(arguments);
},
multiChanged: function() {
this.multi || this.clear(), this.doChange();
},
highlander: function(e) {
this.multi || this.deselect(this.lastSelected);
},
clear: function() {
this.selected = {};
},
isSelected: function(e) {
return this.selected[e];
},
setByKey: function(e, t, n) {
if (t) this.selected[e] = n || !0, this.lastSelected = e, this.doSelect({
key: e,
data: this.selected[e]
}); else {
var r = this.isSelected(e);
delete this.selected[e], this.doDeselect({
key: e,
data: r
});
}
this.doChange();
},
deselect: function(e) {
this.isSelected(e) && this.setByKey(e, !1);
},
select: function(e, t) {
this.multi ? this.setByKey(e, !this.isSelected(e), t) : this.isSelected(e) || (this.highlander(), this.setByKey(e, !0, t));
},
toggle: function(e, t) {
!this.multi && this.lastSelected != e && this.deselect(this.lastSelected), this.setByKey(e, !this.isSelected(e), t);
},
getSelected: function() {
return this.selected;
},
remove: function(e) {
var t = {};
for (var n in this.selected) n < e ? t[n] = this.selected[n] : n > e && (t[n - 1] = this.selected[n]);
this.selected = t;
}
});


// minifier: path aliases

enyo.path.addPaths({layout: "/home/reviewdaemon/hudson/trunk/agent/workspace/Enyo-github-build/bootplate/enyo/../lib/layout/", onyx: "/home/reviewdaemon/hudson/trunk/agent/workspace/Enyo-github-build/bootplate/enyo/../lib/onyx/", onyx: "/home/reviewdaemon/hudson/trunk/agent/workspace/Enyo-github-build/bootplate/enyo/../lib/onyx/source/"});

// FittableLayout.js

enyo.kind({
name: "enyo.FittableLayout",
kind: "Layout",
calcFitIndex: function() {
for (var e = 0, t = this.container.children, n; n = t[e]; e++) if (n.fit && n.showing) return e;
},
getFitControl: function() {
var e = this.container.children, t = e[this.fitIndex];
return t && t.fit && t.showing || (this.fitIndex = this.calcFitIndex(), t = e[this.fitIndex]), t;
},
getLastControl: function() {
var e = this.container.children, t = e.length - 1, n = e[t];
while ((n = e[t]) && !n.showing) t--;
return n;
},
_reflow: function(e, t, n, r) {
this.container.addRemoveClass("enyo-stretch", !this.container.noStretch);
var i = this.getFitControl();
if (!i) return;
var s = 0, o = 0, u = 0, a, f = this.container.hasNode();
f && (a = enyo.dom.calcPaddingExtents(f), s = f[t] - (a[n] + a[r]));
var l = i.getBounds();
o = l[n] - (a && a[n] || 0);
var c = this.getLastControl();
if (c) {
var h = enyo.dom.getComputedBoxValue(c.hasNode(), "margin", r) || 0;
if (c != i) {
var p = c.getBounds(), d = l[n] + l[e], v = p[n] + p[e] + h;
u = v - d;
} else u = h;
}
var m = s - (o + u);
i.applyStyle(e, m + "px");
},
reflow: function() {
this.orient == "h" ? this._reflow("width", "clientWidth", "left", "right") : this._reflow("height", "clientHeight", "top", "bottom");
}
}), enyo.kind({
name: "enyo.FittableColumnsLayout",
kind: "FittableLayout",
orient: "h",
layoutClass: "enyo-fittable-columns-layout"
}), enyo.kind({
name: "enyo.FittableRowsLayout",
kind: "FittableLayout",
layoutClass: "enyo-fittable-rows-layout",
orient: "v"
});

// FittableRows.js

enyo.kind({
name: "enyo.FittableRows",
layoutKind: "FittableRowsLayout",
noStretch: !1
});

// FittableColumns.js

enyo.kind({
name: "enyo.FittableColumns",
layoutKind: "FittableColumnsLayout",
noStretch: !1
});

// FlyweightRepeater.js

enyo.kind({
name: "enyo.FlyweightRepeater",
published: {
count: 0,
noSelect: !1,
multiSelect: !1,
toggleSelected: !1,
clientClasses: "",
clientStyle: "",
rowOffset: 0
},
events: {
onSetupItem: "",
onRenderRow: ""
},
bottomUp: !1,
components: [ {
kind: "Selection",
onSelect: "selectDeselect",
onDeselect: "selectDeselect"
}, {
name: "client"
} ],
create: function() {
this.inherited(arguments), this.noSelectChanged(), this.multiSelectChanged(), this.clientClassesChanged(), this.clientStyleChanged();
},
noSelectChanged: function() {
this.noSelect && this.$.selection.clear();
},
multiSelectChanged: function() {
this.$.selection.setMulti(this.multiSelect);
},
clientClassesChanged: function() {
this.$.client.setClasses(this.clientClasses);
},
clientStyleChanged: function() {
this.$.client.setStyle(this.clientStyle);
},
setupItem: function(e) {
this.doSetupItem({
index: e,
selected: this.isSelected(e)
});
},
generateChildHtml: function() {
var e = "";
this.index = null;
for (var t = 0, n = 0; t < this.count; t++) n = this.rowOffset + (this.bottomUp ? this.count - t - 1 : t), this.setupItem(n), this.$.client.setAttribute("data-enyo-index", n), e += this.inherited(arguments), this.$.client.teardownRender();
return e;
},
previewDomEvent: function(e) {
var t = this.index = this.rowForEvent(e);
e.rowIndex = e.index = t, e.flyweight = this;
},
decorateEvent: function(e, t, n) {
var r = t && t.index != null ? t.index : this.index;
t && r != null && (t.index = r, t.flyweight = this), this.inherited(arguments);
},
tap: function(e, t) {
if (this.noSelect || t.index === -1) return;
this.toggleSelected ? this.$.selection.toggle(t.index) : this.$.selection.select(t.index);
},
selectDeselect: function(e, t) {
this.renderRow(t.key);
},
getSelection: function() {
return this.$.selection;
},
isSelected: function(e) {
return this.getSelection().isSelected(e);
},
renderRow: function(e) {
if (e < this.rowOffset || e >= this.count + this.rowOffset) return;
this.setupItem(e);
var t = this.fetchRowNode(e);
t && (enyo.dom.setInnerHtml(t, this.$.client.generateChildHtml()), this.$.client.teardownChildren(), this.doRenderRow({
rowIndex: e
}));
},
fetchRowNode: function(e) {
if (this.hasNode()) return this.node.querySelector('[data-enyo-index="' + e + '"]');
},
rowForEvent: function(e) {
if (!this.hasNode()) return -1;
var t = e.target;
while (t && t !== this.node) {
var n = t.getAttribute && t.getAttribute("data-enyo-index");
if (n !== null) return Number(n);
t = t.parentNode;
}
return -1;
},
prepareRow: function(e) {
if (e < 0 || e >= this.count) return;
this.setupItem(e);
var t = this.fetchRowNode(e);
enyo.FlyweightRepeater.claimNode(this.$.client, t);
},
lockRow: function() {
this.$.client.teardownChildren();
},
performOnRow: function(e, t, n) {
if (e < 0 || e >= this.count) return;
t && (this.prepareRow(e), enyo.call(n || null, t), this.lockRow());
},
statics: {
claimNode: function(e, t) {
var n;
t && (t.id !== e.id ? n = t.querySelector("#" + e.id) : n = t), e.generated = Boolean(n || !e.tag), e.node = n, e.node && e.rendered();
for (var r = 0, i = e.children, s; s = i[r]; r++) this.claimNode(s, t);
}
}
});

// List.js

enyo.kind({
name: "enyo.List",
kind: "Scroller",
classes: "enyo-list",
published: {
count: 0,
rowsPerPage: 50,
bottomUp: !1,
noSelect: !1,
multiSelect: !1,
toggleSelected: !1,
fixedHeight: !1,
reorderable: !1,
centerReorderContainer: !0,
reorderComponents: [],
pinnedReorderComponents: [],
swipeableComponents: [],
enableSwipe: !1,
persistSwipeableItem: !1
},
events: {
onSetupItem: "",
onSetupReorderComponents: "",
onSetupPinnedReorderComponents: "",
onReorder: "",
onSetupSwipeItem: "",
onSwipeDrag: "",
onSwipe: "",
onSwipeComplete: ""
},
handlers: {
onAnimateFinish: "animateFinish",
onRenderRow: "rowRendered",
ondragstart: "dragstart",
ondrag: "drag",
ondragfinish: "dragfinish",
onup: "up",
onholdpulse: "holdpulse"
},
rowHeight: 0,
listTools: [ {
name: "port",
classes: "enyo-list-port enyo-border-box",
components: [ {
name: "generator",
kind: "FlyweightRepeater",
canGenerate: !1,
components: [ {
tag: null,
name: "client"
} ]
}, {
name: "holdingarea",
allowHtml: !0,
classes: "enyo-list-holdingarea"
}, {
name: "page0",
allowHtml: !0,
classes: "enyo-list-page"
}, {
name: "page1",
allowHtml: !0,
classes: "enyo-list-page"
}, {
name: "placeholder"
}, {
name: "swipeableComponents",
style: "position:absolute; display:block; top:-1000px; left:0;"
} ]
} ],
reorderHoldTimeMS: 600,
draggingRowIndex: -1,
draggingRowNode: null,
placeholderRowIndex: -1,
dragToScrollThreshold: .1,
prevScrollTop: 0,
autoScrollTimeoutMS: 20,
autoScrollTimeout: null,
autoscrollPageY: 0,
pinnedReorderMode: !1,
initialPinPosition: -1,
itemMoved: !1,
currentPageNumber: -1,
completeReorderTimeout: null,
swipeIndex: null,
swipeDirection: null,
persistentItemVisible: !1,
persistentItemOrigin: null,
swipeComplete: !1,
completeSwipeTimeout: null,
completeSwipeDelayMS: 500,
normalSwipeSpeedMS: 200,
fastSwipeSpeedMS: 100,
percentageDraggedThreshold: .2,
importProps: function(e) {
e && e.reorderable && (this.touch = !0), this.inherited(arguments);
},
create: function() {
this.pageHeights = [], this.inherited(arguments), this.getStrategy().translateOptimized = !0, this.bottomUpChanged(), this.noSelectChanged(), this.multiSelectChanged(), this.toggleSelectedChanged(), this.$.generator.setRowOffset(0), this.$.generator.setCount(this.count);
},
initComponents: function() {
this.createReorderTools(), this.inherited(arguments), this.createSwipeableComponents();
},
createReorderTools: function() {
this.createComponent({
name: "reorderContainer",
classes: "enyo-list-reorder-container",
ondown: "sendToStrategy",
ondrag: "sendToStrategy",
ondragstart: "sendToStrategy",
ondragfinish: "sendToStrategy",
onflick: "sendToStrategy"
});
},
createStrategy: function() {
this.controlParentName = "strategy", this.inherited(arguments), this.createChrome(this.listTools), this.controlParentName = "client", this.discoverControlParent();
},
createSwipeableComponents: function() {
for (var e = 0; e < this.swipeableComponents.length; e++) this.$.swipeableComponents.createComponent(this.swipeableComponents[e], {
owner: this.owner
});
},
rendered: function() {
this.inherited(arguments), this.$.generator.node = this.$.port.hasNode(), this.$.generator.generated = !0, this.reset();
},
resizeHandler: function() {
this.inherited(arguments), this.refresh();
},
bottomUpChanged: function() {
this.$.generator.bottomUp = this.bottomUp, this.$.page0.applyStyle(this.pageBound, null), this.$.page1.applyStyle(this.pageBound, null), this.pageBound = this.bottomUp ? "bottom" : "top", this.hasNode() && this.reset();
},
noSelectChanged: function() {
this.$.generator.setNoSelect(this.noSelect);
},
multiSelectChanged: function() {
this.$.generator.setMultiSelect(this.multiSelect);
},
toggleSelectedChanged: function() {
this.$.generator.setToggleSelected(this.toggleSelected);
},
countChanged: function() {
this.hasNode() && this.updateMetrics();
},
sendToStrategy: function(e, t) {
this.$.strategy.dispatchEvent("on" + t.type, t, e);
},
updateMetrics: function() {
this.defaultPageHeight = this.rowsPerPage * (this.rowHeight || 100), this.pageCount = Math.ceil(this.count / this.rowsPerPage), this.portSize = 0;
for (var e = 0; e < this.pageCount; e++) this.portSize += this.getPageHeight(e);
this.adjustPortSize();
},
holdpulse: function(e, t) {
if (!this.getReorderable() || this.isReordering()) return;
if (t.holdTime >= this.reorderHoldTimeMS && this.shouldStartReordering(e, t)) return t.preventDefault(), this.startReordering(t), !1;
},
dragstart: function(e, t) {
if (this.isReordering()) return !0;
if (this.isSwipeable()) return this.swipeDragStart(e, t);
},
drag: function(e, t) {
if (this.shouldDoReorderDrag(t)) return t.preventDefault(), this.reorderDrag(t), !0;
if (this.isSwipeable()) return t.preventDefault(), this.swipeDrag(e, t), !0;
},
dragfinish: function(e, t) {
this.isReordering() ? this.finishReordering(e, t) : this.isSwipeable() && this.swipeDragFinish(e, t);
},
up: function(e, t) {
this.isReordering() && this.finishReordering(e, t);
},
generatePage: function(e, t) {
this.page = e;
var n = this.rowsPerPage * this.page;
this.$.generator.setRowOffset(n);
var r = Math.min(this.count - n, this.rowsPerPage);
this.$.generator.setCount(r);
var i = this.$.generator.generateChildHtml();
t.setContent(i), this.getReorderable() && this.draggingRowIndex > -1 && this.hideReorderingRow();
var s = t.getBounds().height;
!this.rowHeight && s > 0 && (this.rowHeight = Math.floor(s / r), this.updateMetrics());
if (!this.fixedHeight) {
var o = this.getPageHeight(e);
this.pageHeights[e] = s, this.portSize += s - o;
}
},
pageForRow: function(e) {
return Math.floor(e / this.rowsPerPage);
},
preserveDraggingRowNode: function(e) {
this.draggingRowNode && this.pageForRow(this.draggingRowIndex) === e && (this.$.holdingarea.hasNode().appendChild(this.draggingRowNode), this.draggingRowNode = null, this.removedInitialPage = !0);
},
update: function(e) {
var t = !1, n = this.positionToPageInfo(e), r = n.pos + this.scrollerHeight / 2, i = Math.floor(r / Math.max(n.height, this.scrollerHeight) + .5) + n.no, s = i % 2 === 0 ? i : i - 1;
this.p0 != s && this.isPageInRange(s) && (this.preserveDraggingRowNode(this.p0), this.generatePage(s, this.$.page0), this.positionPage(s, this.$.page0), this.p0 = s, t = !0, this.p0RowBounds = this.getPageRowHeights(this.$.page0)), s = i % 2 === 0 ? Math.max(1, i - 1) : i, this.p1 != s && this.isPageInRange(s) && (this.preserveDraggingRowNode(this.p1), this.generatePage(s, this.$.page1), this.positionPage(s, this.$.page1), this.p1 = s, t = !0, this.p1RowBounds = this.getPageRowHeights(this.$.page1)), t && (this.$.generator.setRowOffset(0), this.$.generator.setCount(this.count), this.fixedHeight || (this.adjustBottomPage(), this.adjustPortSize()));
},
getPageRowHeights: function(e) {
var t = {}, n = e.hasNode().querySelectorAll("div[data-enyo-index]");
for (var r = 0, i, s; r < n.length; r++) i = n[r].getAttribute("data-enyo-index"), i !== null && (s = enyo.dom.getBounds(n[r]), t[parseInt(i, 10)] = {
height: s.height,
width: s.width
});
return t;
},
updateRowBounds: function(e) {
this.p0RowBounds[e] ? this.updateRowBoundsAtIndex(e, this.p0RowBounds, this.$.page0) : this.p1RowBounds[e] && this.updateRowBoundsAtIndex(e, this.p1RowBounds, this.$.page1);
},
updateRowBoundsAtIndex: function(e, t, n) {
var r = n.hasNode().querySelector('div[data-enyo-index="' + e + '"]'), i = enyo.dom.getBounds(r);
t[e].height = i.height, t[e].width = i.width;
},
updateForPosition: function(e) {
this.update(this.calcPos(e));
},
calcPos: function(e) {
return this.bottomUp ? this.portSize - this.scrollerHeight - e : e;
},
adjustBottomPage: function() {
var e = this.p0 >= this.p1 ? this.$.page0 : this.$.page1;
this.positionPage(e.pageNo, e);
},
adjustPortSize: function() {
this.scrollerHeight = this.getBounds().height;
var e = Math.max(this.scrollerHeight, this.portSize);
this.$.port.applyStyle("height", e + "px");
},
positionPage: function(e, t) {
t.pageNo = e;
var n = this.pageToPosition(e);
t.applyStyle(this.pageBound, n + "px");
},
pageToPosition: function(e) {
var t = 0, n = e;
while (n > 0) n--, t += this.getPageHeight(n);
return t;
},
positionToPageInfo: function(e) {
var t = -1, n = this.calcPos(e), r = this.defaultPageHeight;
while (n >= 0) t++, r = this.getPageHeight(t), n -= r;
return t = Math.max(t, 0), {
no: t,
height: r,
pos: n + r,
startRow: t * this.rowsPerPage,
endRow: Math.min((t + 1) * this.rowsPerPage - 1, this.count - 1)
};
},
isPageInRange: function(e) {
return e == Math.max(0, Math.min(this.pageCount - 1, e));
},
getPageHeight: function(e) {
var t = this.pageHeights[e];
if (!t) {
var n = this.rowsPerPage * e, r = Math.min(this.count - n, this.rowsPerPage);
t = this.defaultPageHeight * (r / this.rowsPerPage);
}
return Math.max(1, t);
},
invalidatePages: function() {
this.p0 = this.p1 = null, this.p0RowBounds = {}, this.p1RowBounds = {}, this.$.page0.setContent(""), this.$.page1.setContent("");
},
invalidateMetrics: function() {
this.pageHeights = [], this.rowHeight = 0, this.updateMetrics();
},
scroll: function(e, t) {
var n = this.inherited(arguments), r = this.getScrollTop();
return this.lastPos === r ? n : (this.lastPos = r, this.update(r), this.pinnedReorderMode && this.reorderScroll(e, t), n);
},
setScrollTop: function(e) {
this.update(e), this.inherited(arguments), this.twiddle();
},
getScrollPosition: function() {
return this.calcPos(this.getScrollTop());
},
setScrollPosition: function(e) {
this.setScrollTop(this.calcPos(e));
},
scrollToBottom: function() {
this.update(this.getScrollBounds().maxTop), this.inherited(arguments);
},
scrollToRow: function(e) {
var t = this.pageForRow(e), n = e % this.rowsPerPage, r = this.pageToPosition(t);
this.updateForPosition(r), r = this.pageToPosition(t), this.setScrollPosition(r);
if (t == this.p0 || t == this.p1) {
var i = this.$.generator.fetchRowNode(e);
if (i) {
var s = i.offsetTop;
this.bottomUp && (s = this.getPageHeight(t) - i.offsetHeight - s);
var o = this.getScrollPosition() + s;
this.setScrollPosition(o);
}
}
},
scrollToStart: function() {
this[this.bottomUp ? "scrollToBottom" : "scrollToTop"]();
},
scrollToEnd: function() {
this[this.bottomUp ? "scrollToTop" : "scrollToBottom"]();
},
refresh: function() {
this.invalidatePages(), this.update(this.getScrollTop()), this.stabilize(), enyo.platform.android === 4 && this.twiddle();
},
reset: function() {
this.getSelection().clear(), this.invalidateMetrics(), this.invalidatePages(), this.stabilize(), this.scrollToStart();
},
getSelection: function() {
return this.$.generator.getSelection();
},
select: function(e, t) {
return this.getSelection().select(e, t);
},
deselect: function(e) {
return this.getSelection().deselect(e);
},
isSelected: function(e) {
return this.$.generator.isSelected(e);
},
renderRow: function(e) {
this.$.generator.renderRow(e);
},
rowRendered: function(e, t) {
this.updateRowBounds(t.rowIndex);
},
prepareRow: function(e) {
this.$.generator.prepareRow(e);
},
lockRow: function() {
this.$.generator.lockRow();
},
performOnRow: function(e, t, n) {
this.$.generator.performOnRow(e, t, n);
},
animateFinish: function(e) {
return this.twiddle(), !0;
},
twiddle: function() {
var e = this.getStrategy();
enyo.call(e, "twiddle");
},
pageForPageNumber: function(e, t) {
return e % 2 === 0 ? !t || e === this.p0 ? this.$.page0 : null : !t || e === this.p1 ? this.$.page1 : null;
},
shouldStartReordering: function(e, t) {
return !!this.getReorderable() && t.rowIndex >= 0 && !this.pinnedReorderMode && e === this.$.strategy && t.index >= 0 ? !0 : !1;
},
startReordering: function(e) {
this.$.strategy.listReordering = !0, this.buildReorderContainer(), this.doSetupReorderComponents(e), this.styleReorderContainer(e), this.draggingRowIndex = this.placeholderRowIndex = e.rowIndex, this.draggingRowNode = e.target, this.removedInitialPage = !1, this.itemMoved = !1, this.initialPageNumber = this.currentPageNumber = this.pageForRow(e.rowIndex), this.prevScrollTop = this.getScrollTop(), this.replaceNodeWithPlaceholder(e.rowIndex);
},
buildReorderContainer: function() {
this.$.reorderContainer.destroyClientControls();
for (var e = 0; e < this.reorderComponents.length; e++) this.$.reorderContainer.createComponent(this.reorderComponents[e], {
owner: this.owner
});
this.$.reorderContainer.render();
},
styleReorderContainer: function(e) {
this.setItemPosition(this.$.reorderContainer, e.rowIndex), this.setItemBounds(this.$.reorderContainer, e.rowIndex), this.$.reorderContainer.setShowing(!0), this.centerReorderContainer && this.centerReorderContainerOnPointer(e);
},
appendNodeToReorderContainer: function(e) {
this.$.reorderContainer.createComponent({
allowHtml: !0,
content: e.innerHTML
}).render();
},
centerReorderContainerOnPointer: function(e) {
var t = enyo.dom.calcNodePosition(this.hasNode()), n = e.pageX - t.left - parseInt(this.$.reorderContainer.domStyles.width, 10) / 2, r = e.pageY - t.top + this.getScrollTop() - parseInt(this.$.reorderContainer.domStyles.height, 10) / 2;
this.getStrategyKind() != "ScrollStrategy" && (n -= this.getScrollLeft(), r -= this.getScrollTop()), this.positionReorderContainer(n, r);
},
positionReorderContainer: function(e, t) {
this.$.reorderContainer.addClass("enyo-animatedTopAndLeft"), this.$.reorderContainer.addStyles("left:" + e + "px;top:" + t + "px;"), this.setPositionReorderContainerTimeout();
},
setPositionReorderContainerTimeout: function() {
this.clearPositionReorderContainerTimeout(), this.positionReorderContainerTimeout = setTimeout(enyo.bind(this, function() {
this.$.reorderContainer.removeClass("enyo-animatedTopAndLeft"), this.clearPositionReorderContainerTimeout();
}), 100);
},
clearPositionReorderContainerTimeout: function() {
this.positionReorderContainerTimeout && (clearTimeout(this.positionReorderContainerTimeout), this.positionReorderContainerTimeout = null);
},
shouldDoReorderDrag: function() {
return !this.getReorderable() || this.draggingRowIndex < 0 || this.pinnedReorderMode ? !1 : !0;
},
reorderDrag: function(e) {
this.positionReorderNode(e), this.checkForAutoScroll(e), this.updatePlaceholderPosition(e.pageY);
},
updatePlaceholderPosition: function(e) {
var t = this.getRowIndexFromCoordinate(e);
t !== -1 && (t >= this.placeholderRowIndex ? this.movePlaceholderToIndex(Math.min(this.count, t + 1)) : this.movePlaceholderToIndex(t));
},
positionReorderNode: function(e) {
var t = this.$.reorderContainer.getBounds(), n = t.left + e.ddx, r = t.top + e.ddy;
r = this.getStrategyKind() == "ScrollStrategy" ? r + (this.getScrollTop() - this.prevScrollTop) : r, this.$.reorderContainer.addStyles("top: " + r + "px ; left: " + n + "px"), this.prevScrollTop = this.getScrollTop();
},
checkForAutoScroll: function(e) {
var t = enyo.dom.calcNodePosition(this.hasNode()), n = this.getBounds(), r;
this.autoscrollPageY = e.pageY, e.pageY - t.top < n.height * this.dragToScrollThreshold ? (r = 100 * (1 - (e.pageY - t.top) / (n.height * this.dragToScrollThreshold)), this.scrollDistance = -1 * r) : e.pageY - t.top > n.height * (1 - this.dragToScrollThreshold) ? (r = 100 * ((e.pageY - t.top - n.height * (1 - this.dragToScrollThreshold)) / (n.height - n.height * (1 - this.dragToScrollThreshold))), this.scrollDistance = 1 * r) : this.scrollDistance = 0, this.scrollDistance === 0 ? this.stopAutoScrolling() : this.autoScrollTimeout || this.startAutoScrolling();
},
stopAutoScrolling: function() {
this.autoScrollTimeout && (clearTimeout(this.autoScrollTimeout), this.autoScrollTimeout = null);
},
startAutoScrolling: function() {
this.autoScrollTimeout = setInterval(enyo.bind(this, this.autoScroll), this.autoScrollTimeoutMS);
},
autoScroll: function() {
this.scrollDistance === 0 ? this.stopAutoScrolling() : this.autoScrollTimeout || this.startAutoScrolling(), this.setScrollPosition(this.getScrollPosition() + this.scrollDistance), this.positionReorderNode({
ddx: 0,
ddy: 0
}), this.updatePlaceholderPosition(this.autoscrollPageY);
},
movePlaceholderToIndex: function(e) {
var t, n;
if (e < 0) return;
e >= this.count ? (t = null, n = this.pageForPageNumber(this.pageForRow(this.count - 1)).hasNode()) : (t = this.$.generator.fetchRowNode(e), n = t.parentNode);
var r = this.pageForRow(e);
r >= this.pageCount && (r = this.currentPageNumber), n.insertBefore(this.placeholderNode, t), this.currentPageNumber !== r && (this.updatePageHeight(this.currentPageNumber), this.updatePageHeight(r), this.updatePagePositions(r)), this.placeholderRowIndex = e, this.currentPageNumber = r, this.itemMoved = !0;
},
finishReordering: function(e, t) {
if (!this.isReordering() || this.pinnedReorderMode || this.completeReorderTimeout) return;
return this.stopAutoScrolling(), this.$.strategy.listReordering = !1, this.moveReorderedContainerToDroppedPosition(t), this.completeReorderTimeout = setTimeout(enyo.bind(this, this.completeFinishReordering, t), 100), t.preventDefault(), !0;
},
moveReorderedContainerToDroppedPosition: function() {
var e = this.getRelativeOffset(this.placeholderNode, this.hasNode()), t = this.getStrategyKind() == "ScrollStrategy" ? e.top : e.top - this.getScrollTop(), n = e.left - this.getScrollLeft();
this.positionReorderContainer(n, t);
},
completeFinishReordering: function(e) {
this.completeReorderTimeout = null, this.placeholderRowIndex > this.draggingRowIndex && (this.placeholderRowIndex = Math.max(0, this.placeholderRowIndex - 1));
if (this.draggingRowIndex == this.placeholderRowIndex && this.pinnedReorderComponents.length && !this.pinnedReorderMode && !this.itemMoved) {
this.beginPinnedReorder(e);
return;
}
this.removeDraggingRowNode(), this.removePlaceholderNode(), this.emptyAndHideReorderContainer(), this.pinnedReorderMode = !1, this.reorderRows(e), this.draggingRowIndex = this.placeholderRowIndex = -1, this.refresh();
},
beginPinnedReorder: function(e) {
this.buildPinnedReorderContainer(), this.doSetupPinnedReorderComponents(enyo.mixin(e, {
index: this.draggingRowIndex
})), this.pinnedReorderMode = !0, this.initialPinPosition = e.pageY;
},
emptyAndHideReorderContainer: function() {
this.$.reorderContainer.destroyComponents(), this.$.reorderContainer.setShowing(!1);
},
buildPinnedReorderContainer: function() {
this.$.reorderContainer.destroyClientControls();
for (var e = 0; e < this.pinnedReorderComponents.length; e++) this.$.reorderContainer.createComponent(this.pinnedReorderComponents[e], {
owner: this.owner
});
this.$.reorderContainer.render();
},
reorderRows: function(e) {
this.doReorder(this.makeReorderEvent(e)), this.positionReorderedNode(), this.updateListIndices();
},
makeReorderEvent: function(e) {
return e.reorderFrom = this.draggingRowIndex, e.reorderTo = this.placeholderRowIndex, e;
},
positionReorderedNode: function() {
if (!this.removedInitialPage) {
var e = this.$.generator.fetchRowNode(this.placeholderRowIndex);
e && (e.parentNode.insertBefore(this.hiddenNode, e), this.showNode(this.hiddenNode)), this.hiddenNode = null;
if (this.currentPageNumber != this.initialPageNumber) {
var t, n, r = this.pageForPageNumber(this.currentPageNumber), i = this.pageForPageNumber(this.currentPageNumber + 1);
this.initialPageNumber < this.currentPageNumber ? (t = r.hasNode().firstChild, i.hasNode().appendChild(t)) : (t = r.hasNode().lastChild, n = i.hasNode().firstChild, i.hasNode().insertBefore(t, n)), this.correctPageHeights(), this.updatePagePositions(this.initialPageNumber);
}
}
},
updateListIndices: function() {
if (this.shouldDoRefresh()) {
this.refresh(), this.correctPageHeights();
return;
}
var e = Math.min(this.draggingRowIndex, this.placeholderRowIndex), t = Math.max(this.draggingRowIndex, this.placeholderRowIndex), n = this.draggingRowIndex - this.placeholderRowIndex > 0 ? 1 : -1, r, i, s, o;
if (n === 1) {
r = this.$.generator.fetchRowNode(this.draggingRowIndex), r && r.setAttribute("data-enyo-index", "reordered");
for (i = t - 1, s = t; i >= e; i--) {
r = this.$.generator.fetchRowNode(i);
if (!r) continue;
o = parseInt(r.getAttribute("data-enyo-index"), 10), s = o + 1, r.setAttribute("data-enyo-index", s);
}
r = this.hasNode().querySelector('[data-enyo-index="reordered"]'), r.setAttribute("data-enyo-index", this.placeholderRowIndex);
} else {
r = this.$.generator.fetchRowNode(this.draggingRowIndex), r && r.setAttribute("data-enyo-index", this.placeholderRowIndex);
for (i = e + 1, s = e; i <= t; i++) {
r = this.$.generator.fetchRowNode(i);
if (!r) continue;
o = parseInt(r.getAttribute("data-enyo-index"), 10), s = o - 1, r.setAttribute("data-enyo-index", s);
}
}
},
shouldDoRefresh: function() {
return Math.abs(this.initialPageNumber - this.currentPageNumber) > 1;
},
getNodeStyle: function(e) {
var t = this.$.generator.fetchRowNode(e);
if (!t) return;
var n = this.getRelativeOffset(t, this.hasNode()), r = enyo.dom.getBounds(t);
return {
h: r.height,
w: r.width,
left: n.left,
top: n.top
};
},
getRelativeOffset: function(e, t) {
var n = {
top: 0,
left: 0
};
if (e !== t && e.parentNode) do n.top += e.offsetTop || 0, n.left += e.offsetLeft || 0, e = e.offsetParent; while (e && e !== t);
return n;
},
replaceNodeWithPlaceholder: function(e) {
var t = this.$.generator.fetchRowNode(e);
if (!t) {
enyo.log("No node - " + e);
return;
}
this.placeholderNode = this.createPlaceholderNode(t), this.hiddenNode = this.hideNode(t);
var n = this.pageForPageNumber(this.currentPageNumber);
n.hasNode().insertBefore(this.placeholderNode, this.hiddenNode);
},
createPlaceholderNode: function(e) {
var t = this.$.placeholder.hasNode().cloneNode(!0), n = enyo.dom.getBounds(e);
return t.style.height = n.height + "px", t.style.width = n.width + "px", t;
},
removePlaceholderNode: function() {
this.removeNode(this.placeholderNode), this.placeholderNode = null;
},
removeDraggingRowNode: function() {
this.draggingRowNode = null;
var e = this.$.holdingarea.hasNode();
e.innerHTML = "";
},
removeNode: function(e) {
if (!e || !e.parentNode) return;
e.parentNode.removeChild(e);
},
updatePageHeight: function(e) {
if (e < 0) return;
var t = this.pageForPageNumber(e, !0);
if (t) {
var n = this.pageHeights[e], r = Math.max(1, t.getBounds().height);
this.pageHeights[e] = r, this.portSize += r - n;
}
},
updatePagePositions: function(e) {
this.positionPage(this.currentPageNumber, this.pageForPageNumber(this.currentPageNumber)), this.positionPage(e, this.pageForPageNumber(e));
},
correctPageHeights: function() {
this.updatePageHeight(this.currentPageNumber), this.initialPageNumber != this.currentPageNumber && this.updatePageHeight(this.initialPageNumber);
},
hideNode: function(e) {
return e.style.display = "none", e;
},
showNode: function(e) {
return e.style.display = "block", e;
},
dropPinnedRow: function(e) {
this.moveReorderedContainerToDroppedPosition(e), this.completeReorderTimeout = setTimeout(enyo.bind(this, this.completeFinishReordering, e), 100);
return;
},
cancelPinnedMode: function(e) {
this.placeholderRowIndex = this.draggingRowIndex, this.dropPinnedRow(e);
},
getRowIndexFromCoordinate: function(e) {
var t = this.getScrollTop() + e - enyo.dom.calcNodePosition(this.hasNode()).top;
if (t < 0) return -1;
var n = this.positionToPageInfo(t), r = n.no == this.p0 ? this.p0RowBounds : this.p1RowBounds;
if (!r) return this.count;
var i = n.pos, s = this.placeholderNode ? enyo.dom.getBounds(this.placeholderNode).height : 0, o = 0;
for (var u = n.startRow; u <= n.endRow; ++u) {
if (u === this.placeholderRowIndex) {
o += s;
if (o >= i) return -1;
}
if (u !== this.draggingRowIndex) {
o += r[u].height;
if (o >= i) return u;
}
}
return u;
},
getIndexPosition: function(e) {
return enyo.dom.calcNodePosition(this.$.generator.fetchRowNode(e));
},
setItemPosition: function(e, t) {
var n = this.getNodeStyle(t), r = this.getStrategyKind() == "ScrollStrategy" ? n.top : n.top - this.getScrollTop(), i = "top:" + r + "px; left:" + n.left + "px;";
e.addStyles(i);
},
setItemBounds: function(e, t) {
var n = this.getNodeStyle(t), r = "width:" + n.w + "px; height:" + n.h + "px;";
e.addStyles(r);
},
reorderScroll: function(e, t) {
this.getStrategyKind() == "ScrollStrategy" && this.$.reorderContainer.addStyles("top:" + (this.initialPinPosition + this.getScrollTop() - this.rowHeight) + "px;"), this.updatePlaceholderPosition(this.initialPinPosition);
},
hideReorderingRow: function() {
var e = this.hasNode().querySelector('[data-enyo-index="' + this.draggingRowIndex + '"]');
e && (this.hiddenNode = this.hideNode(e));
},
isReordering: function() {
return this.draggingRowIndex > -1;
},
isSwiping: function() {
return this.swipeIndex != null && !this.swipeComplete && this.swipeDirection != null;
},
swipeDragStart: function(e, t) {
return t.index == null || t.vertical ? !0 : (this.completeSwipeTimeout && this.completeSwipe(t), this.swipeComplete = !1, this.swipeIndex != t.index && (this.clearSwipeables(), this.swipeIndex = t.index), this.swipeDirection = t.xDirection, this.persistentItemVisible || this.startSwipe(t), this.draggedXDistance = 0, this.draggedYDistance = 0, !0);
},
swipeDrag: function(e, t) {
return this.persistentItemVisible ? (this.dragPersistentItem(t), this.preventDragPropagation) : this.isSwiping() ? (this.dragSwipeableComponents(this.calcNewDragPosition(t.ddx)), this.draggedXDistance = t.dx, this.draggedYDistance = t.dy, !0) : !1;
},
swipeDragFinish: function(e, t) {
if (this.persistentItemVisible) this.dragFinishPersistentItem(t); else {
if (!this.isSwiping()) return !1;
var n = this.calcPercentageDragged(this.draggedXDistance);
n > this.percentageDraggedThreshold && t.xDirection === this.swipeDirection ? this.swipe(this.fastSwipeSpeedMS) : this.backOutSwipe(t);
}
return this.preventDragPropagation;
},
isSwipeable: function() {
return this.enableSwipe && this.$.swipeableComponents.controls.length !== 0 && !this.isReordering() && !this.pinnedReorderMode;
},
positionSwipeableContainer: function(e, t) {
var n = this.$.generator.fetchRowNode(e);
if (!n) return;
var r = this.getRelativeOffset(n, this.hasNode()), i = enyo.dom.getBounds(n), s = t == 1 ? -1 * i.width : i.width;
this.$.swipeableComponents.addStyles("top: " + r.top + "px; left: " + s + "px; height: " + i.height + "px; width: " + i.width + "px;");
},
calcNewDragPosition: function(e) {
var t = this.$.swipeableComponents.getBounds(), n = t.left, r = this.$.swipeableComponents.getBounds(), i = this.swipeDirection == 1 ? 0 : -1 * r.width, s = this.swipeDirection == 1 ? n + e > i ? i : n + e : n + e < i ? i : n + e;
return s;
},
dragSwipeableComponents: function(e) {
this.$.swipeableComponents.applyStyle("left", e + "px");
},
startSwipe: function(e) {
e.index = this.swipeIndex, this.positionSwipeableContainer(this.swipeIndex, e.xDirection), this.$.swipeableComponents.setShowing(!0), this.setPersistentItemOrigin(e.xDirection), this.doSetupSwipeItem(e);
},
dragPersistentItem: function(e) {
var t = 0, n = this.persistentItemOrigin == "right" ? Math.max(t, t + e.dx) : Math.min(t, t + e.dx);
this.$.swipeableComponents.applyStyle("left", n + "px");
},
dragFinishPersistentItem: function(e) {
var t = this.calcPercentageDragged(e.dx) > .2, n = e.dx > 0 ? "right" : e.dx < 0 ? "left" : null;
this.persistentItemOrigin == n ? t ? this.slideAwayItem() : this.bounceItem(e) : this.bounceItem(e);
},
setPersistentItemOrigin: function(e) {
this.persistentItemOrigin = e == 1 ? "left" : "right";
},
calcPercentageDragged: function(e) {
return Math.abs(e / this.$.swipeableComponents.getBounds().width);
},
swipe: function(e) {
this.swipeComplete = !0, this.animateSwipe(0, e);
},
backOutSwipe: function(e) {
var t = this.$.swipeableComponents.getBounds(), n = this.swipeDirection == 1 ? -1 * t.width : t.width;
this.animateSwipe(n, this.fastSwipeSpeedMS), this.swipeDirection = null;
},
bounceItem: function(e) {
var t = this.$.swipeableComponents.getBounds();
t.left != t.width && this.animateSwipe(0, this.normalSwipeSpeedMS);
},
slideAwayItem: function() {
var e = this.$.swipeableComponents, t = e.getBounds().width, n = this.persistentItemOrigin == "left" ? -1 * t : t;
this.animateSwipe(n, this.normalSwipeSpeedMS), this.persistentItemVisible = !1, this.setPersistSwipeableItem(!1);
},
clearSwipeables: function() {
this.$.swipeableComponents.setShowing(!1), this.persistentItemVisible = !1, this.setPersistSwipeableItem(!1);
},
completeSwipe: function(e) {
this.completeSwipeTimeout && (clearTimeout(this.completeSwipeTimeout), this.completeSwipeTimeout = null), this.getPersistSwipeableItem() ? this.persistentItemVisible = !0 : (this.$.swipeableComponents.setShowing(!1), this.swipeComplete && this.doSwipeComplete({
index: this.swipeIndex,
xDirection: this.swipeDirection
})), this.swipeIndex = null, this.swipeDirection = null;
},
animateSwipe: function(e, t) {
var n = enyo.now(), r = 0, i = this.$.swipeableComponents, s = parseInt(i.domStyles.left, 10), o = e - s;
this.stopAnimateSwipe();
var u = enyo.bind(this, function() {
var e = enyo.now() - n, r = e / t, a = s + o * Math.min(r, 1);
i.applyStyle("left", a + "px"), this.job = enyo.requestAnimationFrame(u), e / t >= 1 && (this.stopAnimateSwipe(), this.completeSwipeTimeout = setTimeout(enyo.bind(this, function() {
this.completeSwipe();
}), this.completeSwipeDelayMS));
});
this.job = enyo.requestAnimationFrame(u);
},
stopAnimateSwipe: function() {
this.job && (this.job = enyo.cancelRequestAnimationFrame(this.job));
}
});

// PulldownList.js

enyo.kind({
name: "enyo.PulldownList",
kind: "List",
touch: !0,
pully: null,
pulldownTools: [ {
name: "pulldown",
classes: "enyo-list-pulldown",
components: [ {
name: "puller",
kind: "Puller"
} ]
} ],
events: {
onPullStart: "",
onPullCancel: "",
onPull: "",
onPullRelease: "",
onPullComplete: ""
},
handlers: {
onScrollStart: "scrollStartHandler",
onScrollStop: "scrollStopHandler",
ondragfinish: "dragfinish"
},
pullingMessage: "Pull down to refresh...",
pulledMessage: "Release to refresh...",
loadingMessage: "Loading...",
pullingIconClass: "enyo-puller-arrow enyo-puller-arrow-down",
pulledIconClass: "enyo-puller-arrow enyo-puller-arrow-up",
loadingIconClass: "",
create: function() {
var e = {
kind: "Puller",
showing: !1,
text: this.loadingMessage,
iconClass: this.loadingIconClass,
onCreate: "setPully"
};
this.listTools.splice(0, 0, e), this.inherited(arguments), this.setPulling();
},
initComponents: function() {
this.createChrome(this.pulldownTools), this.accel = enyo.dom.canAccelerate(), this.translation = this.accel ? "translate3d" : "translate", this.strategyKind = this.resetStrategyKind(), this.inherited(arguments);
},
resetStrategyKind: function() {
return enyo.platform.android >= 3 ? "TranslateScrollStrategy" : "TouchScrollStrategy";
},
setPully: function(e, t) {
this.pully = t.originator;
},
scrollStartHandler: function() {
this.firedPullStart = !1, this.firedPull = !1, this.firedPullCancel = !1;
},
scroll: function(e, t) {
var n = this.inherited(arguments);
this.completingPull && this.pully.setShowing(!1);
var r = this.getStrategy().$.scrollMath || this.getStrategy(), i = -1 * this.getScrollTop();
return r.isInOverScroll() && i > 0 && (enyo.dom.transformValue(this.$.pulldown, this.translation, "0," + i + "px" + (this.accel ? ",0" : "")), this.firedPullStart || (this.firedPullStart = !0, this.pullStart(), this.pullHeight = this.$.pulldown.getBounds().height), i > this.pullHeight && !this.firedPull && (this.firedPull = !0, this.firedPullCancel = !1, this.pull()), this.firedPull && !this.firedPullCancel && i < this.pullHeight && (this.firedPullCancel = !0, this.firedPull = !1, this.pullCancel())), n;
},
scrollStopHandler: function() {
this.completingPull && (this.completingPull = !1, this.doPullComplete());
},
dragfinish: function() {
if (this.firedPull) {
var e = this.getStrategy().$.scrollMath || this.getStrategy();
e.setScrollY(-1 * this.getScrollTop() - this.pullHeight), this.pullRelease();
}
},
completePull: function() {
this.completingPull = !0;
var e = this.getStrategy().$.scrollMath || this.getStrategy();
e.setScrollY(this.pullHeight), e.start();
},
pullStart: function() {
this.setPulling(), this.pully.setShowing(!1), this.$.puller.setShowing(!0), this.doPullStart();
},
pull: function() {
this.setPulled(), this.doPull();
},
pullCancel: function() {
this.setPulling(), this.doPullCancel();
},
pullRelease: function() {
this.$.puller.setShowing(!1), this.pully.setShowing(!0), this.doPullRelease();
},
setPulling: function() {
this.$.puller.setText(this.pullingMessage), this.$.puller.setIconClass(this.pullingIconClass);
},
setPulled: function() {
this.$.puller.setText(this.pulledMessage), this.$.puller.setIconClass(this.pulledIconClass);
}
}), enyo.kind({
name: "enyo.Puller",
classes: "enyo-puller",
published: {
text: "",
iconClass: ""
},
events: {
onCreate: ""
},
components: [ {
name: "icon"
}, {
name: "text",
tag: "span",
classes: "enyo-puller-text"
} ],
create: function() {
this.inherited(arguments), this.doCreate(), this.textChanged(), this.iconClassChanged();
},
textChanged: function() {
this.$.text.setContent(this.text);
},
iconClassChanged: function() {
this.$.icon.setClasses(this.iconClass);
}
});

// AroundList.js

enyo.kind({
name: "enyo.AroundList",
kind: "enyo.List",
listTools: [ {
name: "port",
classes: "enyo-list-port enyo-border-box",
components: [ {
name: "aboveClient"
}, {
name: "generator",
kind: "FlyweightRepeater",
canGenerate: !1,
components: [ {
tag: null,
name: "client"
} ]
}, {
name: "holdingarea",
allowHtml: !0,
classes: "enyo-list-holdingarea"
}, {
name: "page0",
allowHtml: !0,
classes: "enyo-list-page"
}, {
name: "page1",
allowHtml: !0,
classes: "enyo-list-page"
}, {
name: "belowClient"
}, {
name: "placeholder"
}, {
name: "swipeableComponents",
style: "position:absolute; display:block; top:-1000px; left:0px;"
} ]
} ],
aboveComponents: null,
initComponents: function() {
this.inherited(arguments), this.aboveComponents && this.$.aboveClient.createComponents(this.aboveComponents, {
owner: this.owner
}), this.belowComponents && this.$.belowClient.createComponents(this.belowComponents, {
owner: this.owner
});
},
updateMetrics: function() {
this.defaultPageHeight = this.rowsPerPage * (this.rowHeight || 100), this.pageCount = Math.ceil(this.count / this.rowsPerPage), this.aboveHeight = this.$.aboveClient.getBounds().height, this.belowHeight = this.$.belowClient.getBounds().height, this.portSize = this.aboveHeight + this.belowHeight;
for (var e = 0; e < this.pageCount; e++) this.portSize += this.getPageHeight(e);
this.adjustPortSize();
},
positionPage: function(e, t) {
t.pageNo = e;
var n = this.pageToPosition(e), r = this.bottomUp ? this.belowHeight : this.aboveHeight;
n += r, t.applyStyle(this.pageBound, n + "px");
},
scrollToContentStart: function() {
var e = this.bottomUp ? this.belowHeight : this.aboveHeight;
this.setScrollPosition(e);
}
});

// Slideable.js

enyo.kind({
name: "enyo.Slideable",
kind: "Control",
published: {
axis: "h",
value: 0,
unit: "px",
min: 0,
max: 0,
accelerated: "auto",
overMoving: !0,
draggable: !0
},
events: {
onAnimateFinish: "",
onChange: ""
},
preventDragPropagation: !1,
tools: [ {
kind: "Animator",
onStep: "animatorStep",
onEnd: "animatorComplete"
} ],
handlers: {
ondragstart: "dragstart",
ondrag: "drag",
ondragfinish: "dragfinish"
},
kDragScalar: 1,
dragEventProp: "dx",
unitModifier: !1,
canTransform: !1,
create: function() {
this.inherited(arguments), this.acceleratedChanged(), this.transformChanged(), this.axisChanged(), this.valueChanged(), this.addClass("enyo-slideable");
},
initComponents: function() {
this.createComponents(this.tools), this.inherited(arguments);
},
rendered: function() {
this.inherited(arguments), this.canModifyUnit(), this.updateDragScalar();
},
resizeHandler: function() {
this.inherited(arguments), this.updateDragScalar();
},
canModifyUnit: function() {
if (!this.canTransform) {
var e = this.getInitialStyleValue(this.hasNode(), this.boundary);
e.match(/px/i) && this.unit === "%" && (this.unitModifier = this.getBounds()[this.dimension]);
}
},
getInitialStyleValue: function(e, t) {
var n = enyo.dom.getComputedStyle(e);
return n ? n.getPropertyValue(t) : e && e.currentStyle ? e.currentStyle[t] : "0";
},
updateBounds: function(e, t) {
var n = {};
n[this.boundary] = e, this.setBounds(n, this.unit), this.setInlineStyles(e, t);
},
updateDragScalar: function() {
if (this.unit == "%") {
var e = this.getBounds()[this.dimension];
this.kDragScalar = e ? 100 / e : 1, this.canTransform || this.updateBounds(this.value, 100);
}
},
transformChanged: function() {
this.canTransform = enyo.dom.canTransform();
},
acceleratedChanged: function() {
enyo.platform.android > 2 || enyo.dom.accelerate(this, this.accelerated);
},
axisChanged: function() {
var e = this.axis == "h";
this.dragMoveProp = e ? "dx" : "dy", this.shouldDragProp = e ? "horizontal" : "vertical", this.transform = e ? "translateX" : "translateY", this.dimension = e ? "width" : "height", this.boundary = e ? "left" : "top";
},
setInlineStyles: function(e, t) {
var n = {};
this.unitModifier ? (n[this.boundary] = this.percentToPixels(e, this.unitModifier), n[this.dimension] = this.unitModifier, this.setBounds(n)) : (t ? n[this.dimension] = t : n[this.boundary] = e, this.setBounds(n, this.unit));
},
valueChanged: function(e) {
var t = this.value;
this.isOob(t) && !this.isAnimating() && (this.value = this.overMoving ? this.dampValue(t) : this.clampValue(t)), enyo.platform.android > 2 && (this.value ? (e === 0 || e === undefined) && enyo.dom.accelerate(this, this.accelerated) : enyo.dom.accelerate(this, !1)), this.canTransform ? enyo.dom.transformValue(this, this.transform, this.value + this.unit) : this.setInlineStyles(this.value, !1), this.doChange();
},
getAnimator: function() {
return this.$.animator;
},
isAtMin: function() {
return this.value <= this.calcMin();
},
isAtMax: function() {
return this.value >= this.calcMax();
},
calcMin: function() {
return this.min;
},
calcMax: function() {
return this.max;
},
clampValue: function(e) {
var t = this.calcMin(), n = this.calcMax();
return Math.max(t, Math.min(e, n));
},
dampValue: function(e) {
return this.dampBound(this.dampBound(e, this.min, 1), this.max, -1);
},
dampBound: function(e, t, n) {
var r = e;
return r * n < t * n && (r = t + (r - t) / 4), r;
},
percentToPixels: function(e, t) {
return Math.floor(t / 100 * e);
},
pixelsToPercent: function(e) {
var t = this.unitModifier ? this.getBounds()[this.dimension] : this.container.getBounds()[this.dimension];
return e / t * 100;
},
shouldDrag: function(e) {
return this.draggable && e[this.shouldDragProp];
},
isOob: function(e) {
return e > this.calcMax() || e < this.calcMin();
},
dragstart: function(e, t) {
if (this.shouldDrag(t)) return t.preventDefault(), this.$.animator.stop(), t.dragInfo = {}, this.dragging = !0, this.drag0 = this.value, this.dragd0 = 0, this.preventDragPropagation;
},
drag: function(e, t) {
if (this.dragging) {
t.preventDefault();
var n = this.canTransform ? t[this.dragMoveProp] * this.kDragScalar : this.pixelsToPercent(t[this.dragMoveProp]), r = this.drag0 + n, i = n - this.dragd0;
return this.dragd0 = n, i && (t.dragInfo.minimizing = i < 0), this.setValue(r), this.preventDragPropagation;
}
},
dragfinish: function(e, t) {
if (this.dragging) return this.dragging = !1, this.completeDrag(t), t.preventTap(), this.preventDragPropagation;
},
completeDrag: function(e) {
this.value !== this.calcMax() && this.value != this.calcMin() && this.animateToMinMax(e.dragInfo.minimizing);
},
isAnimating: function() {
return this.$.animator.isAnimating();
},
play: function(e, t) {
this.$.animator.play({
startValue: e,
endValue: t,
node: this.hasNode()
});
},
animateTo: function(e) {
this.play(this.value, e);
},
animateToMin: function() {
this.animateTo(this.calcMin());
},
animateToMax: function() {
this.animateTo(this.calcMax());
},
animateToMinMax: function(e) {
e ? this.animateToMin() : this.animateToMax();
},
animatorStep: function(e) {
return this.setValue(e.value), !0;
},
animatorComplete: function(e) {
return this.doAnimateFinish(e), !0;
},
toggleMinMax: function() {
this.animateToMinMax(!this.isAtMin());
}
});

// Arranger.js

enyo.kind({
name: "enyo.Arranger",
kind: "Layout",
layoutClass: "enyo-arranger",
accelerated: "auto",
dragProp: "ddx",
dragDirectionProp: "xDirection",
canDragProp: "horizontal",
incrementalPoints: !1,
destroy: function() {
var e = this.container.getPanels();
for (var t = 0, n; n = e[t]; t++) n._arranger = null;
this.inherited(arguments);
},
arrange: function(e, t) {},
size: function() {},
start: function() {
var e = this.container.fromIndex, t = this.container.toIndex, n = this.container.transitionPoints = [ e ];
if (this.incrementalPoints) {
var r = Math.abs(t - e) - 2, i = e;
while (r >= 0) i += t < e ? -1 : 1, n.push(i), r--;
}
n.push(this.container.toIndex);
},
finish: function() {},
calcArrangementDifference: function(e, t, n, r) {},
canDragEvent: function(e) {
return e[this.canDragProp];
},
calcDragDirection: function(e) {
return e[this.dragDirectionProp];
},
calcDrag: function(e) {
return e[this.dragProp];
},
drag: function(e, t, n, r, i) {
var s = this.measureArrangementDelta(-e, t, n, r, i);
return s;
},
measureArrangementDelta: function(e, t, n, r, i) {
var s = this.calcArrangementDifference(t, n, r, i), o = s ? e / Math.abs(s) : 0;
return o *= this.container.fromIndex > this.container.toIndex ? -1 : 1, o;
},
_arrange: function(e) {
this.containerBounds || this.reflow();
var t = this.getOrderedControls(e);
this.arrange(t, e);
},
arrangeControl: function(e, t) {
e._arranger = enyo.mixin(e._arranger || {}, t);
},
flow: function() {
this.c$ = [].concat(this.container.getPanels()), this.controlsIndex = 0;
for (var e = 0, t = this.container.getPanels(), n; n = t[e]; e++) {
enyo.dom.accelerate(n, this.accelerated);
if (enyo.platform.safari) {
var r = n.children;
for (var i = 0, s; s = r[i]; i++) enyo.dom.accelerate(s, this.accelerated);
}
}
},
reflow: function() {
var e = this.container.hasNode();
this.containerBounds = e ? {
width: e.clientWidth,
height: e.clientHeight
} : {}, this.size();
},
flowArrangement: function() {
var e = this.container.arrangement;
if (e) for (var t = 0, n = this.container.getPanels(), r; r = n[t]; t++) this.flowControl(r, e[t]);
},
flowControl: function(e, t) {
enyo.Arranger.positionControl(e, t);
var n = t.opacity;
n != null && enyo.Arranger.opacifyControl(e, n);
},
getOrderedControls: function(e) {
var t = Math.floor(e), n = t - this.controlsIndex, r = n > 0, i = this.c$ || [];
for (var s = 0; s < Math.abs(n); s++) r ? i.push(i.shift()) : i.unshift(i.pop());
return this.controlsIndex = t, i;
},
statics: {
positionControl: function(e, t, n) {
var r = n || "px";
if (!this.updating) if (enyo.dom.canTransform() && !enyo.platform.android && enyo.platform.ie !== 10) {
var i = t.left, s = t.top;
i = enyo.isString(i) ? i : i && i + r, s = enyo.isString(s) ? s : s && s + r, enyo.dom.transform(e, {
translateX: i || null,
translateY: s || null
});
} else e.setBounds(t, n);
},
opacifyControl: function(e, t) {
var n = t;
n = n > .99 ? 1 : n < .01 ? 0 : n, enyo.platform.ie < 9 ? e.applyStyle("filter", "progid:DXImageTransform.Microsoft.Alpha(Opacity=" + n * 100 + ")") : e.applyStyle("opacity", n);
}
}
});

// CardArranger.js

enyo.kind({
name: "enyo.CardArranger",
kind: "Arranger",
layoutClass: "enyo-arranger enyo-arranger-fit",
calcArrangementDifference: function(e, t, n, r) {
return this.containerBounds.width;
},
arrange: function(e, t) {
for (var n = 0, r, i, s; r = e[n]; n++) s = n === 0 ? 1 : 0, this.arrangeControl(r, {
opacity: s
});
},
start: function() {
this.inherited(arguments);
var e = this.container.getPanels();
for (var t = 0, n; n = e[t]; t++) {
var r = n.showing;
n.setShowing(t == this.container.fromIndex || t == this.container.toIndex), n.showing && !r && n.resized();
}
},
finish: function() {
this.inherited(arguments);
var e = this.container.getPanels();
for (var t = 0, n; n = e[t]; t++) n.setShowing(t == this.container.toIndex);
},
destroy: function() {
var e = this.container.getPanels();
for (var t = 0, n; n = e[t]; t++) enyo.Arranger.opacifyControl(n, 1), n.showing || n.setShowing(!0);
this.inherited(arguments);
}
});

// CardSlideInArranger.js

enyo.kind({
name: "enyo.CardSlideInArranger",
kind: "CardArranger",
start: function() {
var e = this.container.getPanels();
for (var t = 0, n; n = e[t]; t++) {
var r = n.showing;
n.setShowing(t == this.container.fromIndex || t == this.container.toIndex), n.showing && !r && n.resized();
}
var i = this.container.fromIndex;
t = this.container.toIndex, this.container.transitionPoints = [ t + "." + i + ".s", t + "." + i + ".f" ];
},
finish: function() {
this.inherited(arguments);
var e = this.container.getPanels();
for (var t = 0, n; n = e[t]; t++) n.setShowing(t == this.container.toIndex);
},
arrange: function(e, t) {
var n = t.split("."), r = n[0], i = n[1], s = n[2] == "s", o = this.containerBounds.width;
for (var u = 0, a = this.container.getPanels(), f, l; f = a[u]; u++) l = o, i == u && (l = s ? 0 : -o), r == u && (l = s ? o : 0), i == u && i == r && (l = 0), this.arrangeControl(f, {
left: l
});
},
destroy: function() {
var e = this.container.getPanels();
for (var t = 0, n; n = e[t]; t++) enyo.Arranger.positionControl(n, {
left: null
});
this.inherited(arguments);
}
});

// CarouselArranger.js

enyo.kind({
name: "enyo.CarouselArranger",
kind: "Arranger",
size: function() {
var e = this.container.getPanels(), t = this.containerPadding = this.container.hasNode() ? enyo.dom.calcPaddingExtents(this.container.node) : {}, n = this.containerBounds, r, i, s, o, u;
n.height -= t.top + t.bottom, n.width -= t.left + t.right;
var a;
for (r = 0, s = 0; u = e[r]; r++) o = enyo.dom.calcMarginExtents(u.hasNode()), u.width = u.getBounds().width, u.marginWidth = o.right + o.left, s += (u.fit ? 0 : u.width) + u.marginWidth, u.fit && (a = u);
if (a) {
var f = n.width - s;
a.width = f >= 0 ? f : a.width;
}
for (r = 0, i = t.left; u = e[r]; r++) u.setBounds({
top: t.top,
bottom: t.bottom,
width: u.fit ? u.width : null
});
},
arrange: function(e, t) {
this.container.wrap ? this.arrangeWrap(e, t) : this.arrangeNoWrap(e, t);
},
arrangeNoWrap: function(e, t) {
var n, r, i, s, o = this.container.getPanels(), u = this.container.clamp(t), a = this.containerBounds.width;
for (n = u, i = 0; s = o[n]; n++) {
i += s.width + s.marginWidth;
if (i > a) break;
}
var f = a - i, l = 0;
if (f > 0) {
var c = u;
for (n = u - 1, r = 0; s = o[n]; n--) {
r += s.width + s.marginWidth;
if (f - r <= 0) {
l = f - r, u = n;
break;
}
}
}
var h, p;
for (n = 0, p = this.containerPadding.left + l; s = o[n]; n++) h = s.width + s.marginWidth, n < u ? this.arrangeControl(s, {
left: -h
}) : (this.arrangeControl(s, {
left: Math.floor(p)
}), p += h);
},
arrangeWrap: function(e, t) {
for (var n = 0, r = this.containerPadding.left, i, s; s = e[n]; n++) this.arrangeControl(s, {
left: r
}), r += s.width + s.marginWidth;
},
calcArrangementDifference: function(e, t, n, r) {
var i = Math.abs(e % this.c$.length);
return t[i].left - r[i].left;
},
destroy: function() {
var e = this.container.getPanels();
for (var t = 0, n; n = e[t]; t++) enyo.Arranger.positionControl(n, {
left: null,
top: null
}), n.applyStyle("top", null), n.applyStyle("bottom", null), n.applyStyle("left", null), n.applyStyle("width", null);
this.inherited(arguments);
}
});

// CollapsingArranger.js

enyo.kind({
name: "enyo.CollapsingArranger",
kind: "CarouselArranger",
peekWidth: 0,
size: function() {
this.clearLastSize(), this.inherited(arguments);
},
clearLastSize: function() {
for (var e = 0, t = this.container.getPanels(), n; n = t[e]; e++) n._fit && e != t.length - 1 && (n.applyStyle("width", null), n._fit = null);
},
constructor: function() {
this.inherited(arguments), this.peekWidth = this.container.peekWidth != null ? this.container.peekWidth : this.peekWidth;
},
arrange: function(e, t) {
var n = this.container.getPanels();
for (var r = 0, i = this.containerPadding.left, s, o, u = 0; o = n[r]; r++) o.getShowing() ? (this.arrangeControl(o, {
left: i + u * this.peekWidth
}), r >= t && (i += o.width + o.marginWidth - this.peekWidth), u++) : (this.arrangeControl(o, {
left: i
}), r >= t && (i += o.width + o.marginWidth)), r == n.length - 1 && t < 0 && this.arrangeControl(o, {
left: i - t
});
},
calcArrangementDifference: function(e, t, n, r) {
var i = this.container.getPanels().length - 1;
return Math.abs(r[i].left - t[i].left);
},
flowControl: function(e, t) {
this.inherited(arguments);
if (this.container.realtimeFit) {
var n = this.container.getPanels(), r = n.length - 1, i = n[r];
e == i && this.fitControl(e, t.left);
}
},
finish: function() {
this.inherited(arguments);
if (!this.container.realtimeFit && this.containerBounds) {
var e = this.container.getPanels(), t = this.container.arrangement, n = e.length - 1, r = e[n];
this.fitControl(r, t[n].left);
}
},
fitControl: function(e, t) {
e._fit = !0, e.applyStyle("width", this.containerBounds.width - t + "px"), e.resized();
}
});

// DockRightArranger.js

enyo.kind({
name: "enyo.DockRightArranger",
kind: "Arranger",
basePanel: !1,
overlap: 0,
layoutWidth: 0,
constructor: function() {
this.inherited(arguments), this.overlap = this.container.overlap != null ? this.container.overlap : this.overlap, this.layoutWidth = this.container.layoutWidth != null ? this.container.layoutWidth : this.layoutWidth;
},
size: function() {
var e = this.container.getPanels(), t = this.containerPadding = this.container.hasNode() ? enyo.dom.calcPaddingExtents(this.container.node) : {}, n = this.containerBounds, r, i, s;
n.width -= t.left + t.right;
var o = n.width, u = e.length;
this.container.transitionPositions = {};
for (r = 0; s = e[r]; r++) s.width = r === 0 && this.container.basePanel ? o : s.getBounds().width;
for (r = 0; s = e[r]; r++) {
r === 0 && this.container.basePanel && s.setBounds({
width: o
}), s.setBounds({
top: t.top,
bottom: t.bottom
});
for (j = 0; s = e[j]; j++) {
var a;
if (r === 0 && this.container.basePanel) a = 0; else if (j < r) a = o; else {
if (r !== j) break;
var f = o > this.layoutWidth ? this.overlap : 0;
a = o - e[r].width + f;
}
this.container.transitionPositions[r + "." + j] = a;
}
if (j < u) {
var l = !1;
for (k = r + 1; k < u; k++) {
var f = 0;
if (l) f = 0; else if (e[r].width + e[k].width - this.overlap > o) f = 0, l = !0; else {
f = e[r].width - this.overlap;
for (i = r; i < k; i++) {
var c = f + e[i + 1].width - this.overlap;
if (!(c < o)) {
f = o;
break;
}
f = c;
}
f = o - f;
}
this.container.transitionPositions[r + "." + k] = f;
}
}
}
},
arrange: function(e, t) {
var n, r, i = this.container.getPanels(), s = this.container.clamp(t);
for (n = 0; r = i[n]; n++) {
var o = this.container.transitionPositions[n + "." + s];
this.arrangeControl(r, {
left: o
});
}
},
calcArrangementDifference: function(e, t, n, r) {
var i = this.container.getPanels(), s = e < n ? i[n].width : i[e].width;
return s;
},
destroy: function() {
var e = this.container.getPanels();
for (var t = 0, n; n = e[t]; t++) enyo.Arranger.positionControl(n, {
left: null,
top: null
}), n.applyStyle("top", null), n.applyStyle("bottom", null), n.applyStyle("left", null), n.applyStyle("width", null);
this.inherited(arguments);
}
});

// OtherArrangers.js

enyo.kind({
name: "enyo.LeftRightArranger",
kind: "Arranger",
margin: 40,
axisSize: "width",
offAxisSize: "height",
axisPosition: "left",
constructor: function() {
this.inherited(arguments), this.margin = this.container.margin != null ? this.container.margin : this.margin;
},
size: function() {
var e = this.container.getPanels(), t = this.containerBounds[this.axisSize], n = t - this.margin - this.margin;
for (var r = 0, i, s; s = e[r]; r++) i = {}, i[this.axisSize] = n, i[this.offAxisSize] = "100%", s.setBounds(i);
},
start: function() {
this.inherited(arguments);
var e = this.container.fromIndex, t = this.container.toIndex, n = this.getOrderedControls(t), r = Math.floor(n.length / 2);
for (var i = 0, s; s = n[i]; i++) e > t ? i == n.length - r ? s.applyStyle("z-index", 0) : s.applyStyle("z-index", 1) : i == n.length - 1 - r ? s.applyStyle("z-index", 0) : s.applyStyle("z-index", 1);
},
arrange: function(e, t) {
var n, r, i, s;
if (this.container.getPanels().length == 1) {
s = {}, s[this.axisPosition] = this.margin, this.arrangeControl(this.container.getPanels()[0], s);
return;
}
var o = Math.floor(this.container.getPanels().length / 2), u = this.getOrderedControls(Math.floor(t) - o), a = this.containerBounds[this.axisSize] - this.margin - this.margin, f = this.margin - a * o;
for (n = 0; r = u[n]; n++) s = {}, s[this.axisPosition] = f, this.arrangeControl(r, s), f += a;
},
calcArrangementDifference: function(e, t, n, r) {
if (this.container.getPanels().length == 1) return 0;
var i = Math.abs(e % this.c$.length);
return t[i][this.axisPosition] - r[i][this.axisPosition];
},
destroy: function() {
var e = this.container.getPanels();
for (var t = 0, n; n = e[t]; t++) enyo.Arranger.positionControl(n, {
left: null,
top: null
}), enyo.Arranger.opacifyControl(n, 1), n.applyStyle("left", null), n.applyStyle("top", null), n.applyStyle("height", null), n.applyStyle("width", null);
this.inherited(arguments);
}
}), enyo.kind({
name: "enyo.TopBottomArranger",
kind: "LeftRightArranger",
dragProp: "ddy",
dragDirectionProp: "yDirection",
canDragProp: "vertical",
axisSize: "height",
offAxisSize: "width",
axisPosition: "top"
}), enyo.kind({
name: "enyo.SpiralArranger",
kind: "Arranger",
incrementalPoints: !0,
inc: 20,
size: function() {
var e = this.container.getPanels(), t = this.containerBounds, n = this.controlWidth = t.width / 3, r = this.controlHeight = t.height / 3;
for (var i = 0, s; s = e[i]; i++) s.setBounds({
width: n,
height: r
});
},
arrange: function(e, t) {
var n = this.inc;
for (var r = 0, i = e.length, s; s = e[r]; r++) {
var o = Math.cos(r / i * 2 * Math.PI) * r * n + this.controlWidth, u = Math.sin(r / i * 2 * Math.PI) * r * n + this.controlHeight;
this.arrangeControl(s, {
left: o,
top: u
});
}
},
start: function() {
this.inherited(arguments);
var e = this.getOrderedControls(this.container.toIndex);
for (var t = 0, n; n = e[t]; t++) n.applyStyle("z-index", e.length - t);
},
calcArrangementDifference: function(e, t, n, r) {
return this.controlWidth;
},
destroy: function() {
var e = this.container.getPanels();
for (var t = 0, n; n = e[t]; t++) n.applyStyle("z-index", null), enyo.Arranger.positionControl(n, {
left: null,
top: null
}), n.applyStyle("left", null), n.applyStyle("top", null), n.applyStyle("height", null), n.applyStyle("width", null);
this.inherited(arguments);
}
}), enyo.kind({
name: "enyo.GridArranger",
kind: "Arranger",
incrementalPoints: !0,
colWidth: 100,
colHeight: 100,
size: function() {
var e = this.container.getPanels(), t = this.colWidth, n = this.colHeight;
for (var r = 0, i; i = e[r]; r++) i.setBounds({
width: t,
height: n
});
},
arrange: function(e, t) {
var n = this.colWidth, r = this.colHeight, i = Math.max(1, Math.floor(this.containerBounds.width / n)), s;
for (var o = 0, u = 0; u < e.length; o++) for (var a = 0; a < i && (s = e[u]); a++, u++) this.arrangeControl(s, {
left: n * a,
top: r * o
});
},
flowControl: function(e, t) {
this.inherited(arguments), enyo.Arranger.opacifyControl(e, t.top % this.colHeight !== 0 ? .25 : 1);
},
calcArrangementDifference: function(e, t, n, r) {
return this.colWidth;
},
destroy: function() {
var e = this.container.getPanels();
for (var t = 0, n; n = e[t]; t++) enyo.Arranger.positionControl(n, {
left: null,
top: null
}), n.applyStyle("left", null), n.applyStyle("top", null), n.applyStyle("height", null), n.applyStyle("width", null);
this.inherited(arguments);
}
});

// Panels.js

enyo.kind({
name: "enyo.Panels",
classes: "enyo-panels",
published: {
index: 0,
draggable: !0,
animate: !0,
wrap: !1,
arrangerKind: "CardArranger",
narrowFit: !0
},
events: {
onTransitionStart: "",
onTransitionFinish: ""
},
handlers: {
ondragstart: "dragstart",
ondrag: "drag",
ondragfinish: "dragfinish",
onscroll: "domScroll"
},
tools: [ {
kind: "Animator",
onStep: "step",
onEnd: "completed"
} ],
fraction: 0,
create: function() {
this.transitionPoints = [], this.inherited(arguments), this.arrangerKindChanged(), this.narrowFitChanged(), this.indexChanged();
},
rendered: function() {
this.inherited(arguments), enyo.makeBubble(this, "scroll");
},
domScroll: function(e, t) {
this.hasNode() && this.node.scrollLeft > 0 && (this.node.scrollLeft = 0);
},
initComponents: function() {
this.createChrome(this.tools), this.inherited(arguments);
},
arrangerKindChanged: function() {
this.setLayoutKind(this.arrangerKind);
},
narrowFitChanged: function() {
this.addRemoveClass("enyo-panels-fit-narrow", this.narrowFit);
},
destroy: function() {
this.destroying = !0, this.inherited(arguments);
},
removeControl: function(e) {
this.inherited(arguments), this.destroying && this.controls.length > 0 && this.isPanel(e) && (this.setIndex(Math.max(this.index - 1, 0)), this.flow(), this.reflow());
},
isPanel: function() {
return !0;
},
flow: function() {
this.arrangements = [], this.inherited(arguments);
},
reflow: function() {
this.arrangements = [], this.inherited(arguments), this.refresh();
},
getPanels: function() {
var e = this.controlParent || this;
return e.children;
},
getActive: function() {
var e = this.getPanels(), t = this.index % e.length;
return t < 0 && (t += e.length), e[t];
},
getAnimator: function() {
return this.$.animator;
},
setIndex: function(e) {
this.setPropertyValue("index", e, "indexChanged");
},
setIndexDirect: function(e) {
this.setIndex(e), this.completed();
},
previous: function() {
this.setIndex(this.index - 1);
},
next: function() {
this.setIndex(this.index + 1);
},
clamp: function(e) {
var t = this.getPanels().length - 1;
return this.wrap ? e : Math.max(0, Math.min(e, t));
},
indexChanged: function(e) {
this.lastIndex = e, this.index = this.clamp(this.index), !this.dragging && this.$.animator && (this.$.animator.isAnimating() && this.completed(), this.$.animator.stop(), this.hasNode() && (this.animate ? (this.startTransition(), this.$.animator.play({
startValue: this.fraction
})) : this.refresh()));
},
step: function(e) {
this.fraction = e.value, this.stepTransition();
},
completed: function() {
this.$.animator.isAnimating() && this.$.animator.stop(), this.fraction = 1, this.stepTransition(), this.finishTransition();
},
dragstart: function(e, t) {
if (this.draggable && this.layout && this.layout.canDragEvent(t)) return t.preventDefault(), this.dragstartTransition(t), this.dragging = !0, this.$.animator.stop(), !0;
},
drag: function(e, t) {
this.dragging && (t.preventDefault(), this.dragTransition(t));
},
dragfinish: function(e, t) {
this.dragging && (this.dragging = !1, t.preventTap(), this.dragfinishTransition(t));
},
dragstartTransition: function(e) {
if (!this.$.animator.isAnimating()) {
var t = this.fromIndex = this.index;
this.toIndex = t - (this.layout ? this.layout.calcDragDirection(e) : 0);
} else this.verifyDragTransition(e);
this.fromIndex = this.clamp(this.fromIndex), this.toIndex = this.clamp(this.toIndex), this.fireTransitionStart(), this.layout && this.layout.start();
},
dragTransition: function(e) {
var t = this.layout ? this.layout.calcDrag(e) : 0, n = this.transitionPoints, r = n[0], i = n[n.length - 1], s = this.fetchArrangement(r), o = this.fetchArrangement(i), u = this.layout ? this.layout.drag(t, r, s, i, o) : 0, a = t && !u;
a, this.fraction += u;
var f = this.fraction;
if (f > 1 || f < 0 || a) (f > 0 || a) && this.dragfinishTransition(e), this.dragstartTransition(e), this.fraction = 0;
this.stepTransition();
},
dragfinishTransition: function(e) {
this.verifyDragTransition(e), this.setIndex(this.toIndex), this.dragging && this.fireTransitionFinish();
},
verifyDragTransition: function(e) {
var t = this.layout ? this.layout.calcDragDirection(e) : 0, n = Math.min(this.fromIndex, this.toIndex), r = Math.max(this.fromIndex, this.toIndex);
if (t > 0) {
var i = n;
n = r, r = i;
}
n != this.fromIndex && (this.fraction = 1 - this.fraction), this.fromIndex = n, this.toIndex = r;
},
refresh: function() {
this.$.animator && this.$.animator.isAnimating() && this.$.animator.stop(), this.startTransition(), this.fraction = 1, this.stepTransition(), this.finishTransition();
},
startTransition: function() {
this.fromIndex = this.fromIndex != null ? this.fromIndex : this.lastIndex || 0, this.toIndex = this.toIndex != null ? this.toIndex : this.index, this.layout && this.layout.start(), this.fireTransitionStart();
},
finishTransition: function() {
this.layout && this.layout.finish(), this.transitionPoints = [], this.fraction = 0, this.fromIndex = this.toIndex = null, this.fireTransitionFinish();
},
fireTransitionStart: function() {
var e = this.startTransitionInfo;
this.hasNode() && (!e || e.fromIndex != this.fromIndex || e.toIndex != this.toIndex) && (this.startTransitionInfo = {
fromIndex: this.fromIndex,
toIndex: this.toIndex
}, this.doTransitionStart(enyo.clone(this.startTransitionInfo)));
},
fireTransitionFinish: function() {
var e = this.finishTransitionInfo;
this.hasNode() && (!e || e.fromIndex != this.lastIndex || e.toIndex != this.index) && (this.finishTransitionInfo = {
fromIndex: this.lastIndex,
toIndex: this.index
}, this.doTransitionFinish(enyo.clone(this.finishTransitionInfo))), this.lastIndex = this.index;
},
stepTransition: function() {
if (this.hasNode()) {
var e = this.transitionPoints, t = (this.fraction || 0) * (e.length - 1), n = Math.floor(t);
t -= n;
var r = e[n], i = e[n + 1], s = this.fetchArrangement(r), o = this.fetchArrangement(i);
this.arrangement = s && o ? enyo.Panels.lerp(s, o, t) : s || o, this.arrangement && this.layout && this.layout.flowArrangement();
}
},
fetchArrangement: function(e) {
return e != null && !this.arrangements[e] && this.layout && (this.layout._arrange(e), this.arrangements[e] = this.readArrangement(this.getPanels())), this.arrangements[e];
},
readArrangement: function(e) {
var t = [];
for (var n = 0, r = e, i; i = r[n]; n++) t.push(enyo.clone(i._arranger));
return t;
},
statics: {
isScreenNarrow: function() {
return enyo.dom.getWindowWidth() <= 800;
},
lerp: function(e, t, n) {
var r = [];
for (var i = 0, s = enyo.keys(e), o; o = s[i]; i++) r.push(this.lerpObject(e[o], t[o], n));
return r;
},
lerpObject: function(e, t, n) {
var r = enyo.clone(e), i, s;
if (t) for (var o in e) i = e[o], s = t[o], i != s && (r[o] = i - (i - s) * n);
return r;
}
}
});

// Node.js

enyo.kind({
name: "enyo.Node",
published: {
expandable: !1,
expanded: !1,
icon: "",
onlyIconExpands: !1,
selected: !1
},
style: "padding: 0 0 0 16px;",
content: "Node",
defaultKind: "Node",
classes: "enyo-node",
components: [ {
name: "icon",
kind: "Image",
showing: !1
}, {
kind: "Control",
name: "caption",
Xtag: "span",
style: "display: inline-block; padding: 4px;",
allowHtml: !0
}, {
kind: "Control",
name: "extra",
tag: "span",
allowHtml: !0
} ],
childClient: [ {
kind: "Control",
name: "box",
classes: "enyo-node-box",
Xstyle: "border: 1px solid orange;",
components: [ {
kind: "Control",
name: "client",
classes: "enyo-node-client",
Xstyle: "border: 1px solid lightblue;"
} ]
} ],
handlers: {
ondblclick: "dblclick"
},
events: {
onNodeTap: "nodeTap",
onNodeDblClick: "nodeDblClick",
onExpand: "nodeExpand",
onDestroyed: "nodeDestroyed"
},
create: function() {
this.inherited(arguments), this.selectedChanged(), this.iconChanged();
},
destroy: function() {
this.doDestroyed(), this.inherited(arguments);
},
initComponents: function() {
this.expandable && (this.kindComponents = this.kindComponents.concat(this.childClient)), this.inherited(arguments);
},
contentChanged: function() {
this.$.caption.setContent(this.content);
},
iconChanged: function() {
this.$.icon.setSrc(this.icon), this.$.icon.setShowing(Boolean(this.icon));
},
selectedChanged: function() {
this.addRemoveClass("enyo-selected", this.selected);
},
rendered: function() {
this.inherited(arguments), this.expandable && !this.expanded && this.quickCollapse();
},
addNodes: function(e) {
this.destroyClientControls();
for (var t = 0, n; n = e[t]; t++) this.createComponent(n);
this.$.client.render();
},
addTextNodes: function(e) {
this.destroyClientControls();
for (var t = 0, n; n = e[t]; t++) this.createComponent({
content: n
});
this.$.client.render();
},
tap: function(e, t) {
return this.onlyIconExpands ? t.target == this.$.icon.hasNode() ? this.toggleExpanded() : this.doNodeTap() : (this.toggleExpanded(), this.doNodeTap()), !0;
},
dblclick: function(e, t) {
return this.doNodeDblClick(), !0;
},
toggleExpanded: function() {
this.setExpanded(!this.expanded);
},
quickCollapse: function() {
this.removeClass("enyo-animate"), this.$.box.applyStyle("height", "0");
var e = this.$.client.getBounds().height;
this.$.client.setBounds({
top: -e
});
},
_expand: function() {
this.addClass("enyo-animate");
var e = this.$.client.getBounds().height;
this.$.box.setBounds({
height: e
}), this.$.client.setBounds({
top: 0
}), setTimeout(enyo.bind(this, function() {
this.expanded && (this.removeClass("enyo-animate"), this.$.box.applyStyle("height", "auto"));
}), 225);
},
_collapse: function() {
this.removeClass("enyo-animate");
var e = this.$.client.getBounds().height;
this.$.box.setBounds({
height: e
}), setTimeout(enyo.bind(this, function() {
this.addClass("enyo-animate"), this.$.box.applyStyle("height", "0"), this.$.client.setBounds({
top: -e
});
}), 25);
},
expandedChanged: function(e) {
if (!this.expandable) this.expanded = !1; else {
var t = {
expanded: this.expanded
};
this.doExpand(t), t.wait || this.effectExpanded();
}
},
effectExpanded: function() {
this.$.client && (this.expanded ? this._expand() : this._collapse());
}
});

// ImageViewPin.js

enyo.kind({
name: "enyo.ImageViewPin",
kind: "enyo.Control",
published: {
highlightAnchorPoint: !1,
anchor: {
top: 0,
left: 0
},
position: {
top: 0,
left: 0
}
},
style: "position:absolute;z-index:1000;width:0px;height:0px;",
handlers: {
onPositionPin: "reAnchor"
},
create: function() {
this.inherited(arguments), this.styleClientControls(), this.positionClientControls(), this.highlightAnchorPointChanged(), this.anchorChanged();
},
styleClientControls: function() {
var e = this.getClientControls();
for (var t = 0; t < e.length; t++) e[t].applyStyle("position", "absolute");
},
positionClientControls: function() {
var e = this.getClientControls();
for (var t = 0; t < e.length; t++) for (var n in this.position) e[t].applyStyle(n, this.position[n] + "px");
},
highlightAnchorPointChanged: function() {
this.addRemoveClass("pinDebug", this.highlightAnchorPoint);
},
anchorChanged: function() {
var e = null, t = null;
for (t in this.anchor) {
e = this.anchor[t].toString().match(/^(\d+(?:\.\d+)?)(.*)$/);
if (!e) continue;
this.anchor[t + "Coords"] = {
value: e[1],
units: e[2] || "px"
};
}
},
reAnchor: function(e, t) {
var n = t.scale, r = t.bounds, i = this.anchor.right ? this.anchor.rightCoords.units == "px" ? r.width + r.x - this.anchor.rightCoords.value * n : r.width * (100 - this.anchor.rightCoords.value) / 100 + r.x : this.anchor.leftCoords.units == "px" ? this.anchor.leftCoords.value * n + r.x : r.width * this.anchor.leftCoords.value / 100 + r.x, s = this.anchor.bottom ? this.anchor.bottomCoords.units == "px" ? r.height + r.y - this.anchor.bottomCoords.value * n : r.height * (100 - this.anchor.bottomCoords.value) / 100 + r.y : this.anchor.topCoords.units == "px" ? this.anchor.topCoords.value * n + r.y : r.height * this.anchor.topCoords.value / 100 + r.y;
this.applyStyle("left", i + "px"), this.applyStyle("top", s + "px");
}
});

// ImageView.js

enyo.kind({
name: "enyo.ImageView",
kind: enyo.Scroller,
touchOverscroll: !1,
thumb: !1,
animate: !0,
verticalDragPropagation: !0,
horizontalDragPropagation: !0,
published: {
scale: "auto",
disableZoom: !1,
src: undefined
},
events: {
onZoom: ""
},
touch: !0,
preventDragPropagation: !1,
handlers: {
ondragstart: "dragPropagation"
},
components: [ {
name: "animator",
kind: "Animator",
onStep: "zoomAnimationStep",
onEnd: "zoomAnimationEnd"
}, {
name: "viewport",
style: "overflow:hidden;min-height:100%;min-width:100%;",
classes: "enyo-fit",
ongesturechange: "gestureTransform",
ongestureend: "saveState",
ontap: "singleTap",
ondblclick: "doubleClick",
onmousewheel: "mousewheel",
components: [ {
kind: "Image",
ondown: "down"
} ]
} ],
create: function() {
this.inherited(arguments), this.canTransform = enyo.dom.canTransform(), this.canTransform || this.$.image.applyStyle("position", "relative"), this.canAccelerate = enyo.dom.canAccelerate(), this.bufferImage = new Image, this.bufferImage.onload = enyo.bind(this, "imageLoaded"), this.bufferImage.onerror = enyo.bind(this, "imageError"), this.srcChanged(), this.getStrategy().setDragDuringGesture(!1), this.getStrategy().$.scrollMath && this.getStrategy().$.scrollMath.start();
},
down: function(e, t) {
t.preventDefault();
},
dragPropagation: function(e, t) {
var n = this.getStrategy().getScrollBounds(), r = n.top === 0 && t.dy > 0 || n.top >= n.maxTop - 2 && t.dy < 0, i = n.left === 0 && t.dx > 0 || n.left >= n.maxLeft - 2 && t.dx < 0;
return !(r && this.verticalDragPropagation || i && this.horizontalDragPropagation);
},
mousewheel: function(e, t) {
t.pageX |= t.clientX + t.target.scrollLeft, t.pageY |= t.clientY + t.target.scrollTop;
var n = (this.maxScale - this.minScale) / 10, r = this.scale;
if (t.wheelDelta > 0 || t.detail < 0) this.scale = this.limitScale(this.scale + n); else if (t.wheelDelta < 0 || t.detail > 0) this.scale = this.limitScale(this.scale - n);
return this.eventPt = this.calcEventLocation(t), this.transformImage(this.scale), r != this.scale && this.doZoom({
scale: this.scale
}), this.ratioX = this.ratioY = null, t.preventDefault(), !0;
},
srcChanged: function() {
this.src && this.src.length > 0 && this.bufferImage && this.src != this.bufferImage.src && (this.bufferImage.src = this.src);
},
imageLoaded: function(e) {
this.originalWidth = this.bufferImage.width, this.originalHeight = this.bufferImage.height, this.scaleChanged(), this.$.image.setSrc(this.bufferImage.src), enyo.dom.transformValue(this.getStrategy().$.client, "translate3d", "0px, 0px, 0"), this.positionClientControls(this.scale), this.alignImage();
},
resizeHandler: function() {
this.inherited(arguments), this.$.image.src && this.scaleChanged();
},
scaleChanged: function() {
var e = this.hasNode();
if (e) {
this.containerWidth = e.clientWidth, this.containerHeight = e.clientHeight;
var t = this.containerWidth / this.originalWidth, n = this.containerHeight / this.originalHeight;
this.minScale = Math.min(t, n), this.maxScale = this.minScale * 3 < 1 ? 1 : this.minScale * 3, this.scale == "auto" ? this.scale = this.minScale : this.scale == "width" ? this.scale = t : this.scale == "height" ? this.scale = n : this.scale == "fit" ? (this.fitAlignment = "center", this.scale = Math.max(t, n)) : (this.maxScale = Math.max(this.maxScale, this.scale), this.scale = this.limitScale(this.scale));
}
this.eventPt = this.calcEventLocation(), this.transformImage(this.scale);
},
imageError: function(e) {
enyo.error("Error loading image: " + this.src), this.bubble("onerror", e);
},
alignImage: function() {
if (this.fitAlignment && this.fitAlignment === "center") {
var e = this.getScrollBounds();
this.setScrollLeft(e.maxLeft / 2), this.setScrollTop(e.maxTop / 2);
}
},
gestureTransform: function(e, t) {
this.eventPt = this.calcEventLocation(t), this.transformImage(this.limitScale(this.scale * t.scale));
},
calcEventLocation: function(e) {
var t = {
x: 0,
y: 0
};
if (e && this.hasNode()) {
var n = this.node.getBoundingClientRect();
t.x = Math.round(e.pageX - n.left - this.imageBounds.x), t.x = Math.max(0, Math.min(this.imageBounds.width, t.x)), t.y = Math.round(e.pageY - n.top - this.imageBounds.y), t.y = Math.max(0, Math.min(this.imageBounds.height, t.y));
}
return t;
},
transformImage: function(e) {
this.tapped = !1;
var t = this.imageBounds || this.innerImageBounds(e);
this.imageBounds = this.innerImageBounds(e), this.scale > this.minScale ? this.$.viewport.applyStyle("cursor", "move") : this.$.viewport.applyStyle("cursor", null), this.$.viewport.setBounds({
width: this.imageBounds.width + "px",
height: this.imageBounds.height + "px"
}), this.ratioX = this.ratioX || (this.eventPt.x + this.getScrollLeft()) / t.width, this.ratioY = this.ratioY || (this.eventPt.y + this.getScrollTop()) / t.height;
var n, r;
this.$.animator.ratioLock ? (n = this.$.animator.ratioLock.x * this.imageBounds.width - this.containerWidth / 2, r = this.$.animator.ratioLock.y * this.imageBounds.height - this.containerHeight / 2) : (n = this.ratioX * this.imageBounds.width - this.eventPt.x, r = this.ratioY * this.imageBounds.height - this.eventPt.y), n = Math.max(0, Math.min(this.imageBounds.width - this.containerWidth, n)), r = Math.max(0, Math.min(this.imageBounds.height - this.containerHeight, r));
if (this.canTransform) {
var i = {
scale: e
};
this.canAccelerate ? i = enyo.mixin({
translate3d: Math.round(this.imageBounds.left) + "px, " + Math.round(this.imageBounds.top) + "px, 0px"
}, i) : i = enyo.mixin({
translate: this.imageBounds.left + "px, " + this.imageBounds.top + "px"
}, i), enyo.dom.transform(this.$.image, i);
} else this.$.image.setBounds({
width: this.imageBounds.width + "px",
height: this.imageBounds.height + "px",
left: this.imageBounds.left + "px",
top: this.imageBounds.top + "px"
});
this.setScrollLeft(n), this.setScrollTop(r), this.positionClientControls(e);
},
limitScale: function(e) {
return this.disableZoom ? e = this.scale : e > this.maxScale ? e = this.maxScale : e < this.minScale && (e = this.minScale), e;
},
innerImageBounds: function(e) {
var t = this.originalWidth * e, n = this.originalHeight * e, r = {
x: 0,
y: 0,
transX: 0,
transY: 0
};
return t < this.containerWidth && (r.x += (this.containerWidth - t) / 2), n < this.containerHeight && (r.y += (this.containerHeight - n) / 2), this.canTransform && (r.transX -= (this.originalWidth - t) / 2, r.transY -= (this.originalHeight - n) / 2), {
left: r.x + r.transX,
top: r.y + r.transY,
width: t,
height: n,
x: r.x,
y: r.y
};
},
saveState: function(e, t) {
var n = this.scale;
this.scale *= t.scale, this.scale = this.limitScale(this.scale), n != this.scale && this.doZoom({
scale: this.scale
}), this.ratioX = this.ratioY = null;
},
doubleClick: function(e, t) {
enyo.platform.ie == 8 && (this.tapped = !0, t.pageX = t.clientX + t.target.scrollLeft, t.pageY = t.clientY + t.target.scrollTop, this.singleTap(e, t), t.preventDefault());
},
singleTap: function(e, t) {
setTimeout(enyo.bind(this, function() {
this.tapped = !1;
}), 300), this.tapped ? (this.tapped = !1, this.smartZoom(e, t)) : this.tapped = !0;
},
smartZoom: function(e, t) {
var n = this.hasNode(), r = this.$.image.hasNode();
if (n && r && this.hasNode() && !this.disableZoom) {
var i = this.scale;
this.scale != this.minScale ? this.scale = this.minScale : this.scale = this.maxScale, this.eventPt = this.calcEventLocation(t);
if (this.animate) {
var s = {
x: (this.eventPt.x + this.getScrollLeft()) / this.imageBounds.width,
y: (this.eventPt.y + this.getScrollTop()) / this.imageBounds.height
};
this.$.animator.play({
duration: 350,
ratioLock: s,
baseScale: i,
deltaScale: this.scale - i
});
} else this.transformImage(this.scale), this.doZoom({
scale: this.scale
});
}
},
zoomAnimationStep: function(e, t) {
var n = this.$.animator.baseScale + this.$.animator.deltaScale * this.$.animator.value;
this.transformImage(n);
},
zoomAnimationEnd: function(e, t) {
this.doZoom({
scale: this.scale
}), this.$.animator.ratioLock = undefined;
},
positionClientControls: function(e) {
this.waterfallDown("onPositionPin", {
scale: e,
bounds: this.imageBounds
});
}
});

// ImageCarousel.js

enyo.kind({
name: "enyo.ImageCarousel",
kind: enyo.Panels,
arrangerKind: "enyo.CarouselArranger",
defaultScale: "auto",
disableZoom: !1,
lowMemory: !1,
published: {
images: []
},
handlers: {
onTransitionStart: "transitionStart",
onTransitionFinish: "transitionFinish"
},
create: function() {
this.inherited(arguments), this.imageCount = this.images.length, this.images.length > 0 && (this.initContainers(), this.loadNearby());
},
initContainers: function() {
for (var e = 0; e < this.images.length; e++) this.$["container" + e] || (this.createComponent({
name: "container" + e,
style: "height:100%; width:100%;"
}), this.$["container" + e].render());
for (e = this.images.length; e < this.imageCount; e++) this.$["image" + e] && this.$["image" + e].destroy(), this.$["container" + e].destroy();
this.imageCount = this.images.length;
},
loadNearby: function() {
var e = this.getBufferRange();
for (var t in e) this.loadImageView(e[t]);
},
getBufferRange: function() {
var e = [];
if (this.layout.containerBounds) {
var t = 1, n = this.layout.containerBounds, r, i, s, o, u, a;
o = this.index - 1, u = 0, a = n.width * t;
while (o >= 0 && u <= a) s = this.$["container" + o], u += s.width + s.marginWidth, e.unshift(o), o--;
o = this.index, u = 0, a = n.width * (t + 1);
while (o < this.images.length && u <= a) s = this.$["container" + o], u += s.width + s.marginWidth, e.push(o), o++;
}
return e;
},
reflow: function() {
this.inherited(arguments), this.loadNearby();
},
loadImageView: function(e) {
return this.wrap && (e = (e % this.images.length + this.images.length) % this.images.length), e >= 0 && e <= this.images.length - 1 && (this.$["image" + e] ? this.$["image" + e].src != this.images[e] && (this.$["image" + e].setSrc(this.images[e]), this.$["image" + e].setScale(this.defaultScale), this.$["image" + e].setDisableZoom(this.disableZoom)) : (this.$["container" + e].createComponent({
name: "image" + e,
kind: "ImageView",
scale: this.defaultScale,
disableZoom: this.disableZoom,
src: this.images[e],
verticalDragPropagation: !1,
style: "height:100%; width:100%;"
}, {
owner: this
}), this.$["image" + e].render())), this.$["image" + e];
},
setImages: function(e) {
this.setPropertyValue("images", e, "imagesChanged");
},
imagesChanged: function() {
this.initContainers(), this.loadNearby();
},
indexChanged: function() {
this.loadNearby(), this.lowMemory && this.cleanupMemory(), this.inherited(arguments);
},
transitionStart: function(e, t) {
if (t.fromIndex == t.toIndex) return !0;
},
transitionFinish: function(e, t) {
this.loadNearby(), this.lowMemory && this.cleanupMemory();
},
getActiveImage: function() {
return this.getImageByIndex(this.index);
},
getImageByIndex: function(e) {
return this.$["image" + e] || this.loadImageView(e);
},
cleanupMemory: function() {
var e = getBufferRange();
for (var t = 0; t < this.images.length; t++) enyo.indexOf(t, e) === -1 && this.$["image" + t] && this.$["image" + t].destroy();
}
});

// Icon.js

enyo.kind({
name: "onyx.Icon",
published: {
src: "",
disabled: !1
},
classes: "onyx-icon",
create: function() {
this.inherited(arguments), this.src && this.srcChanged(), this.disabledChanged();
},
disabledChanged: function() {
this.addRemoveClass("disabled", this.disabled);
},
srcChanged: function() {
this.applyStyle("background-image", "url(" + enyo.path.rewrite(this.src) + ")");
}
});

// Button.js

enyo.kind({
name: "onyx.Button",
kind: "enyo.Button",
classes: "onyx-button enyo-unselectable",
create: function() {
enyo.platform.firefoxOS && (this.handlers.ondown = "down", this.handlers.onleave = "leave"), this.inherited(arguments);
},
down: function(e, t) {
this.addClass("pressed");
},
leave: function(e, t) {
this.removeClass("pressed");
}
});

// IconButton.js

enyo.kind({
name: "onyx.IconButton",
kind: "onyx.Icon",
published: {
active: !1
},
classes: "onyx-icon-button",
create: function() {
enyo.platform.firefoxOS && (this.handlers.ondown = "down", this.handlers.onleave = "leave"), this.inherited(arguments);
},
down: function(e, t) {
this.addClass("pressed");
},
leave: function(e, t) {
this.removeClass("pressed");
},
rendered: function() {
this.inherited(arguments), this.activeChanged();
},
tap: function() {
if (this.disabled) return !0;
this.setActive(!0);
},
activeChanged: function() {
this.bubble("onActivate");
}
});

// Checkbox.js

enyo.kind({
name: "onyx.Checkbox",
classes: "onyx-checkbox",
kind: enyo.Checkbox,
tag: "div",
handlers: {
onclick: ""
},
tap: function(e, t) {
return this.disabled || (this.setChecked(!this.getChecked()), this.bubble("onchange")), !this.disabled;
},
dragstart: function() {}
});

// Drawer.js

enyo.kind({
name: "onyx.Drawer",
published: {
open: !0,
orient: "v",
animated: !0
},
style: "overflow: hidden; position: relative;",
tools: [ {
kind: "Animator",
onStep: "animatorStep",
onEnd: "animatorEnd"
}, {
name: "client",
style: "position: relative;",
classes: "enyo-border-box"
} ],
create: function() {
this.inherited(arguments), this.animatedChanged(), this.openChanged();
},
initComponents: function() {
this.createChrome(this.tools), this.inherited(arguments);
},
animatedChanged: function() {
!this.animated && this.hasNode() && this.$.animator.isAnimating() && (this.$.animator.stop(), this.animatorEnd());
},
openChanged: function() {
this.$.client.show();
if (this.hasNode()) if (this.$.animator.isAnimating()) this.$.animator.reverse(); else {
var e = this.orient == "v", t = e ? "height" : "width", n = e ? "top" : "left";
this.applyStyle(t, null);
var r = this.hasNode()[e ? "scrollHeight" : "scrollWidth"];
this.animated ? this.$.animator.play({
startValue: this.open ? 0 : r,
endValue: this.open ? r : 0,
dimension: t,
position: n
}) : this.animatorEnd();
} else this.$.client.setShowing(this.open);
},
animatorStep: function(e) {
if (this.hasNode()) {
var t = e.dimension;
this.node.style[t] = this.domStyles[t] = e.value + "px";
}
var n = this.$.client.hasNode();
if (n) {
var r = e.position, i = this.open ? e.endValue : e.startValue;
n.style[r] = this.$.client.domStyles[r] = e.value - i + "px";
}
this.container && this.container.resized();
},
animatorEnd: function() {
if (!this.open) this.$.client.hide(); else {
this.$.client.domCssText = enyo.Control.domStylesToCssText(this.$.client.domStyles);
var e = this.orient == "v", t = e ? "height" : "width", n = e ? "top" : "left", r = this.$.client.hasNode();
r && (r.style[n] = this.$.client.domStyles[n] = null), this.node && (this.node.style[t] = this.domStyles[t] = null);
}
this.container && this.container.resized();
}
});

// Grabber.js

enyo.kind({
name: "onyx.Grabber",
classes: "onyx-grabber"
});

// Groupbox.js

enyo.kind({
name: "onyx.Groupbox",
classes: "onyx-groupbox"
}), enyo.kind({
name: "onyx.GroupboxHeader",
classes: "onyx-groupbox-header"
});

// Input.js

enyo.kind({
name: "onyx.Input",
kind: "enyo.Input",
classes: "onyx-input"
});

// Popup.js

enyo.kind({
name: "onyx.Popup",
kind: "Popup",
classes: "onyx-popup",
published: {
scrimWhenModal: !0,
scrim: !1,
scrimClassName: ""
},
statics: {
count: 0
},
defaultZ: 120,
showingChanged: function() {
this.showing ? (onyx.Popup.count++, this.applyZIndex()) : onyx.Popup.count > 0 && onyx.Popup.count--, this.showHideScrim(this.showing), this.inherited(arguments);
},
showHideScrim: function(e) {
if (this.floating && (this.scrim || this.modal && this.scrimWhenModal)) {
var t = this.getScrim();
if (e) {
var n = this.getScrimZIndex();
this._scrimZ = n, t.showAtZIndex(n);
} else t.hideAtZIndex(this._scrimZ);
enyo.call(t, "addRemoveClass", [ this.scrimClassName, t.showing ]);
}
},
getScrimZIndex: function() {
return this.findZIndex() - 1;
},
getScrim: function() {
return this.modal && this.scrimWhenModal && !this.scrim ? onyx.scrimTransparent.make() : onyx.scrim.make();
},
applyZIndex: function() {
this._zIndex = onyx.Popup.count * 2 + this.findZIndex() + 1, this.applyStyle("z-index", this._zIndex);
},
findZIndex: function() {
var e = this.defaultZ;
return this._zIndex ? e = this._zIndex : this.hasNode() && (e = Number(enyo.dom.getComputedStyleValue(this.node, "z-index")) || e), this._zIndex = e;
}
});

// TextArea.js

enyo.kind({
name: "onyx.TextArea",
kind: "enyo.TextArea",
classes: "onyx-textarea"
});

// RichText.js

enyo.kind({
name: "onyx.RichText",
kind: "enyo.RichText",
classes: "onyx-richtext"
});

// InputDecorator.js

enyo.kind({
name: "onyx.InputDecorator",
kind: "enyo.ToolDecorator",
tag: "label",
classes: "onyx-input-decorator",
published: {
alwaysLooksFocused: !1
},
handlers: {
onDisabledChange: "disabledChange",
onfocus: "receiveFocus",
onblur: "receiveBlur"
},
create: function() {
this.inherited(arguments), this.updateFocus(!1);
},
alwaysLooksFocusedChanged: function(e) {
this.updateFocus(this.focus);
},
updateFocus: function(e) {
this.focused = e, this.addRemoveClass("onyx-focused", this.alwaysLooksFocused || this.focused);
},
receiveFocus: function() {
this.updateFocus(!0);
},
receiveBlur: function() {
this.updateFocus(!1);
},
disabledChange: function(e, t) {
this.addRemoveClass("onyx-disabled", t.originator.disabled);
}
});

// Tooltip.js

enyo.kind({
name: "onyx.Tooltip",
kind: "onyx.Popup",
classes: "onyx-tooltip below left-arrow",
autoDismiss: !1,
showDelay: 500,
defaultLeft: -6,
handlers: {
onRequestShowTooltip: "requestShow",
onRequestHideTooltip: "requestHide"
},
requestShow: function() {
return this.showJob = setTimeout(enyo.bind(this, "show"), this.showDelay), !0;
},
cancelShow: function() {
clearTimeout(this.showJob);
},
requestHide: function() {
return this.cancelShow(), this.inherited(arguments);
},
showingChanged: function() {
this.cancelShow(), this.adjustPosition(!0), this.inherited(arguments);
},
applyPosition: function(e) {
var t = "";
for (var n in e) t += n + ":" + e[n] + (isNaN(e[n]) ? "; " : "px; ");
this.addStyles(t);
},
adjustPosition: function(e) {
if (this.showing && this.hasNode()) {
var t = this.node.getBoundingClientRect();
t.top + t.height > window.innerHeight ? (this.addRemoveClass("below", !1), this.addRemoveClass("above", !0)) : (this.addRemoveClass("above", !1), this.addRemoveClass("below", !0)), t.left + t.width > window.innerWidth && (this.applyPosition({
"margin-left": -t.width,
bottom: "auto"
}), this.addRemoveClass("left-arrow", !1), this.addRemoveClass("right-arrow", !0));
}
},
resizeHandler: function() {
this.applyPosition({
"margin-left": this.defaultLeft,
bottom: "auto"
}), this.addRemoveClass("left-arrow", !0), this.addRemoveClass("right-arrow", !1), this.adjustPosition(!0), this.inherited(arguments);
}
});

// TooltipDecorator.js

enyo.kind({
name: "onyx.TooltipDecorator",
defaultKind: "onyx.Button",
classes: "onyx-popup-decorator",
handlers: {
onenter: "enter",
onleave: "leave"
},
enter: function() {
this.requestShowTooltip();
},
leave: function() {
this.requestHideTooltip();
},
tap: function() {
this.requestHideTooltip();
},
requestShowTooltip: function() {
this.waterfallDown("onRequestShowTooltip");
},
requestHideTooltip: function() {
this.waterfallDown("onRequestHideTooltip");
}
});

// MenuDecorator.js

enyo.kind({
name: "onyx.MenuDecorator",
kind: "onyx.TooltipDecorator",
defaultKind: "onyx.Button",
classes: "onyx-popup-decorator enyo-unselectable",
handlers: {
onActivate: "activated",
onHide: "menuHidden"
},
activated: function(e, t) {
this.requestHideTooltip(), t.originator.active && (this.menuActive = !0, this.activator = t.originator, this.activator.addClass("active"), this.requestShowMenu());
},
requestShowMenu: function() {
this.waterfallDown("onRequestShowMenu", {
activator: this.activator
});
},
requestHideMenu: function() {
this.waterfallDown("onRequestHideMenu");
},
menuHidden: function() {
this.menuActive = !1, this.activator && (this.activator.setActive(!1), this.activator.removeClass("active"));
},
enter: function(e) {
this.menuActive || this.inherited(arguments);
},
leave: function(e, t) {
this.menuActive || this.inherited(arguments);
}
});

// Menu.js

enyo.kind({
name: "onyx.Menu",
kind: "onyx.Popup",
modal: !0,
defaultKind: "onyx.MenuItem",
classes: "onyx-menu",
published: {
maxHeight: 200,
scrolling: !0
},
handlers: {
onActivate: "itemActivated",
onRequestShowMenu: "requestMenuShow",
onRequestHideMenu: "requestHide"
},
childComponents: [ {
name: "client",
kind: "enyo.Scroller",
strategyKind: "TouchScrollStrategy"
} ],
showOnTop: !1,
scrollerName: "client",
create: function() {
this.inherited(arguments), this.maxHeightChanged();
},
initComponents: function() {
this.scrolling && this.createComponents(this.childComponents, {
isChrome: !0
}), this.inherited(arguments);
},
getScroller: function() {
return this.$[this.scrollerName];
},
maxHeightChanged: function() {
this.scrolling && this.getScroller().setMaxHeight(this.maxHeight + "px");
},
itemActivated: function(e, t) {
return t.originator.setActive(!1), !0;
},
showingChanged: function() {
this.inherited(arguments), this.scrolling && this.getScroller().setShowing(this.showing), this.adjustPosition(!0);
},
requestMenuShow: function(e, t) {
if (this.floating) {
var n = t.activator.hasNode();
if (n) {
var r = this.activatorOffset = this.getPageOffset(n);
this.applyPosition({
top: r.top + (this.showOnTop ? 0 : r.height),
left: r.left,
width: r.width
});
}
}
return this.show(), !0;
},
applyPosition: function(e) {
var t = "";
for (var n in e) t += n + ":" + e[n] + (isNaN(e[n]) ? "; " : "px; ");
this.addStyles(t);
},
getPageOffset: function(e) {
var t = e.getBoundingClientRect(), n = window.pageYOffset === undefined ? document.documentElement.scrollTop : window.pageYOffset, r = window.pageXOffset === undefined ? document.documentElement.scrollLeft : window.pageXOffset, i = t.height === undefined ? t.bottom - t.top : t.height, s = t.width === undefined ? t.right - t.left : t.width;
return {
top: t.top + n,
left: t.left + r,
height: i,
width: s
};
},
adjustPosition: function() {
if (this.showing && this.hasNode()) {
this.scrolling && !this.showOnTop && this.getScroller().setMaxHeight(this.maxHeight + "px"), this.removeClass("onyx-menu-up"), this.floating || this.applyPosition({
left: "auto"
});
var e = this.node.getBoundingClientRect(), t = e.height === undefined ? e.bottom - e.top : e.height, n = window.innerHeight === undefined ? document.documentElement.clientHeight : window.innerHeight, r = window.innerWidth === undefined ? document.documentElement.clientWidth : window.innerWidth;
this.menuUp = e.top + t > n && n - e.bottom < e.top - t, this.addRemoveClass("onyx-menu-up", this.menuUp);
if (this.floating) {
var i = this.activatorOffset;
this.menuUp ? this.applyPosition({
top: i.top - t + (this.showOnTop ? i.height : 0),
bottom: "auto"
}) : e.top < i.top && i.top + (this.showOnTop ? 0 : i.height) + t < n && this.applyPosition({
top: i.top + (this.showOnTop ? 0 : i.height),
bottom: "auto"
});
}
e.right > r && (this.floating ? this.applyPosition({
left: r - e.width
}) : this.applyPosition({
left: -(e.right - r)
})), e.left < 0 && (this.floating ? this.applyPosition({
left: 0,
right: "auto"
}) : this.getComputedStyleValue("right") == "auto" ? this.applyPosition({
left: -e.left
}) : this.applyPosition({
right: e.left
}));
if (this.scrolling && !this.showOnTop) {
e = this.node.getBoundingClientRect();
var s;
this.menuUp ? s = this.maxHeight < e.bottom ? this.maxHeight : e.bottom : s = e.top + this.maxHeight < n ? this.maxHeight : n - e.top, this.getScroller().setMaxHeight(s + "px");
}
}
},
resizeHandler: function() {
this.inherited(arguments), this.adjustPosition();
},
requestHide: function() {
this.setShowing(!1);
}
});

// MenuItem.js

enyo.kind({
name: "onyx.MenuItem",
kind: "enyo.Button",
events: {
onSelect: "",
onItemContentChange: ""
},
classes: "onyx-menu-item",
tag: "div",
create: function() {
this.inherited(arguments), this.active && this.bubble("onActivate");
},
tap: function(e) {
this.inherited(arguments), this.bubble("onRequestHideMenu"), this.doSelect({
selected: this,
content: this.content
});
},
contentChanged: function(e) {
this.inherited(arguments), this.doItemContentChange({
content: this.content
});
}
});

// PickerDecorator.js

enyo.kind({
name: "onyx.PickerDecorator",
kind: "onyx.MenuDecorator",
classes: "onyx-picker-decorator",
defaultKind: "onyx.PickerButton",
handlers: {
onChange: "change"
},
change: function(e, t) {
this.waterfallDown("onChange", t);
}
});

// PickerButton.js

enyo.kind({
name: "onyx.PickerButton",
kind: "onyx.Button",
handlers: {
onChange: "change"
},
change: function(e, t) {
t.content !== undefined && this.setContent(t.content);
}
});

// Picker.js

enyo.kind({
name: "onyx.Picker",
kind: "onyx.Menu",
classes: "onyx-picker enyo-unselectable",
published: {
selected: null
},
events: {
onChange: ""
},
handlers: {
onItemContentChange: "itemContentChange"
},
floating: !0,
showOnTop: !0,
initComponents: function() {
this.setScrolling(!0), this.inherited(arguments);
},
showingChanged: function() {
this.getScroller().setShowing(this.showing), this.inherited(arguments), this.showing && this.selected && this.scrollToSelected();
},
scrollToSelected: function() {
this.getScroller().scrollToControl(this.selected, !this.menuUp);
},
itemActivated: function(e, t) {
return this.processActivatedItem(t.originator), this.inherited(arguments);
},
processActivatedItem: function(e) {
e.active && this.setSelected(e);
},
selectedChanged: function(e) {
e && e.removeClass("selected"), this.selected && (this.selected.addClass("selected"), this.doChange({
selected: this.selected,
content: this.selected.content
}));
},
itemContentChange: function(e, t) {
t.originator == this.selected && this.doChange({
selected: this.selected,
content: this.selected.content
});
},
resizeHandler: function() {
this.inherited(arguments), this.adjustPosition();
}
});

// FlyweightPicker.js

enyo.kind({
name: "onyx.FlyweightPicker",
kind: "onyx.Picker",
classes: "onyx-flyweight-picker",
published: {
count: 0
},
events: {
onSetupItem: "",
onSelect: ""
},
handlers: {
onSelect: "itemSelect"
},
components: [ {
name: "scroller",
kind: "enyo.Scroller",
strategyKind: "TouchScrollStrategy",
components: [ {
name: "flyweight",
kind: "FlyweightRepeater",
noSelect: !0,
ontap: "itemTap"
} ]
} ],
scrollerName: "scroller",
initComponents: function() {
this.controlParentName = "flyweight", this.inherited(arguments), this.$.flyweight.$.client.children[0].setActive(!0);
},
create: function() {
this.inherited(arguments), this.countChanged();
},
rendered: function() {
this.inherited(arguments), this.selectedChanged();
},
scrollToSelected: function() {
var e = this.$.flyweight.fetchRowNode(this.selected);
this.getScroller().scrollToNode(e, !this.menuUp);
},
countChanged: function() {
this.$.flyweight.count = this.count;
},
processActivatedItem: function(e) {
this.item = e;
},
selectedChanged: function(e) {
if (!this.item) return;
e != null && (this.item.removeClass("selected"), this.$.flyweight.renderRow(e));
var t;
this.selected != null && (this.item.addClass("selected"), this.$.flyweight.renderRow(this.selected), this.item.removeClass("selected"), t = this.$.flyweight.fetchRowNode(this.selected)), this.doChange({
selected: this.selected,
content: t && t.textContent || this.item.content
});
},
itemTap: function(e, t) {
this.setSelected(t.rowIndex), this.doSelect({
selected: this.item,
content: this.item.content
});
},
itemSelect: function(e, t) {
if (t.originator != this) return !0;
}
});

// DatePicker.js

enyo.kind({
name: "onyx.DatePicker",
classes: "onyx-toolbar-inline",
published: {
disabled: !1,
locale: "en_us",
dayHidden: !1,
monthHidden: !1,
yearHidden: !1,
minYear: 1900,
maxYear: 2099,
value: null
},
events: {
onSelect: ""
},
create: function() {
this.inherited(arguments), enyo.g11n && (this.locale = enyo.g11n.currentLocale().getLocale()), this.initDefaults();
},
initDefaults: function() {
var e = [ "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC" ];
enyo.g11n && (this._tf = new enyo.g11n.Fmts({
locale: this.locale
}), e = this._tf.getMonthFields()), this.setupPickers(this._tf ? this._tf.getDateFieldOrder() : "mdy"), this.dayHiddenChanged(), this.monthHiddenChanged(), this.yearHiddenChanged();
var t = this.value = this.value || new Date;
for (var n = 0, r; r = e[n]; n++) this.$.monthPicker.createComponent({
content: r,
value: n,
active: n == t.getMonth()
});
var i = t.getFullYear();
this.$.yearPicker.setSelected(i - this.minYear);
for (n = 1; n <= this.monthLength(t.getYear(), t.getMonth()); n++) this.$.dayPicker.createComponent({
content: n,
value: n,
active: n == t.getDate()
});
},
monthLength: function(e, t) {
return 32 - (new Date(e, t, 32)).getDate();
},
setupYear: function(e, t) {
this.$.year.setContent(this.minYear + t.index);
},
setupPickers: function(e) {
var t = e.split(""), n, r, i;
for (r = 0, i = t.length; r < i; r++) {
n = t[r];
switch (n) {
case "d":
this.createDay();
break;
case "m":
this.createMonth();
break;
case "y":
this.createYear();
break;
default:
}
}
},
createYear: function() {
var e = this.maxYear - this.minYear;
this.createComponent({
kind: "onyx.PickerDecorator",
onSelect: "updateYear",
components: [ {
classes: "onyx-datepicker-year",
name: "yearPickerButton",
disabled: this.disabled
}, {
name: "yearPicker",
kind: "onyx.FlyweightPicker",
count: ++e,
onSetupItem: "setupYear",
components: [ {
name: "year"
} ]
} ]
});
},
createMonth: function() {
this.createComponent({
kind: "onyx.PickerDecorator",
onSelect: "updateMonth",
components: [ {
classes: "onyx-datepicker-month",
name: "monthPickerButton",
disabled: this.disabled
}, {
name: "monthPicker",
kind: "onyx.Picker"
} ]
});
},
createDay: function() {
this.createComponent({
kind: "onyx.PickerDecorator",
onSelect: "updateDay",
components: [ {
classes: "onyx-datepicker-day",
name: "dayPickerButton",
disabled: this.disabled
}, {
name: "dayPicker",
kind: "onyx.Picker"
} ]
});
},
localeChanged: function() {
this.refresh();
},
dayHiddenChanged: function() {
this.$.dayPicker.getParent().setShowing(this.dayHidden ? !1 : !0);
},
monthHiddenChanged: function() {
this.$.monthPicker.getParent().setShowing(this.monthHidden ? !1 : !0);
},
yearHiddenChanged: function() {
this.$.yearPicker.getParent().setShowing(this.yearHidden ? !1 : !0);
},
minYearChanged: function() {
this.refresh();
},
maxYearChanged: function() {
this.refresh();
},
valueChanged: function() {
this.refresh();
},
disabledChanged: function() {
this.$.yearPickerButton.setDisabled(this.disabled), this.$.monthPickerButton.setDisabled(this.disabled), this.$.dayPickerButton.setDisabled(this.disabled);
},
updateDay: function(e, t) {
var n = this.calcDate(this.value.getFullYear(), this.value.getMonth(), t.selected.value);
return this.doSelect({
name: this.name,
value: n
}), this.setValue(n), !0;
},
updateMonth: function(e, t) {
var n = this.calcDate(this.value.getFullYear(), t.selected.value, this.value.getDate());
return this.doSelect({
name: this.name,
value: n
}), this.setValue(n), !0;
},
updateYear: function(e, t) {
if (t.originator.selected != -1) {
var n = this.calcDate(this.minYear + t.originator.selected, this.value.getMonth(), this.value.getDate());
this.doSelect({
name: this.name,
value: n
}), this.setValue(n);
}
return !0;
},
calcDate: function(e, t, n) {
return new Date(e, t, n, this.value.getHours(), this.value.getMinutes(), this.value.getSeconds(), this.value.getMilliseconds());
},
refresh: function() {
this.destroyClientControls(), this.initDefaults(), this.render();
}
});

// TimePicker.js

enyo.kind({
name: "onyx.TimePicker",
classes: "onyx-toolbar-inline",
published: {
disabled: !1,
locale: "en_us",
is24HrMode: null,
value: null
},
events: {
onSelect: ""
},
create: function() {
this.inherited(arguments), enyo.g11n && (this.locale = enyo.g11n.currentLocale().getLocale()), this.initDefaults();
},
initDefaults: function() {
var e = "AM", t = "PM";
this.is24HrMode == null && (this.is24HrMode = !1), enyo.g11n && (this._tf = new enyo.g11n.Fmts({
locale: this.locale
}), e = this._tf.getAmCaption(), t = this._tf.getPmCaption(), this.is24HrMode == null && (this.is24HrMode = !this._tf.isAmPm())), this.setupPickers(this._tf ? this._tf.getTimeFieldOrder() : "hma");
var n = this.value = this.value || new Date, r;
if (!this.is24HrMode) {
var i = n.getHours();
i = i === 0 ? 12 : i;
for (r = 1; r <= 12; r++) this.$.hourPicker.createComponent({
content: r,
value: r,
active: r == (i > 12 ? i % 12 : i)
});
} else for (r = 0; r < 24; r++) this.$.hourPicker.createComponent({
content: r,
value: r,
active: r == n.getHours()
});
for (r = 0; r <= 59; r++) this.$.minutePicker.createComponent({
content: r < 10 ? "0" + r : r,
value: r,
active: r == n.getMinutes()
});
n.getHours() >= 12 ? this.$.ampmPicker.createComponents([ {
content: e
}, {
content: t,
active: !0
} ]) : this.$.ampmPicker.createComponents([ {
content: e,
active: !0
}, {
content: t
} ]), this.$.ampmPicker.getParent().setShowing(!this.is24HrMode);
},
setupPickers: function(e) {
var t = e.split(""), n, r, i;
for (r = 0, i = t.length; r < i; r++) {
n = t[r];
switch (n) {
case "h":
this.createHour();
break;
case "m":
this.createMinute();
break;
case "a":
this.createAmPm();
break;
default:
}
}
},
createHour: function() {
this.createComponent({
kind: "onyx.PickerDecorator",
onSelect: "updateHour",
components: [ {
classes: "onyx-timepicker-hour",
name: "hourPickerButton",
disabled: this.disabled
}, {
name: "hourPicker",
kind: "onyx.Picker"
} ]
});
},
createMinute: function() {
this.createComponent({
kind: "onyx.PickerDecorator",
onSelect: "updateMinute",
components: [ {
classes: "onyx-timepicker-minute",
name: "minutePickerButton",
disabled: this.disabled
}, {
name: "minutePicker",
kind: "onyx.Picker"
} ]
});
},
createAmPm: function() {
this.createComponent({
kind: "onyx.PickerDecorator",
onSelect: "updateAmPm",
components: [ {
classes: "onyx-timepicker-ampm",
name: "ampmPickerButton",
disabled: this.disabled
}, {
name: "ampmPicker",
kind: "onyx.Picker"
} ]
});
},
disabledChanged: function() {
this.$.hourPickerButton.setDisabled(this.disabled), this.$.minutePickerButton.setDisabled(this.disabled), this.$.ampmPickerButton.setDisabled(this.disabled);
},
localeChanged: function() {
this.is24HrMode = null, this.refresh();
},
is24HrModeChanged: function() {
this.refresh();
},
valueChanged: function() {
this.refresh();
},
updateHour: function(e, t) {
var n = t.selected.value;
if (!this.is24HrMode) {
var r = this.$.ampmPicker.getParent().controlAtIndex(0).content;
n = n + (n == 12 ? -12 : 0) + (this.isAm(r) ? 0 : 12);
}
return this.value = this.calcTime(n, this.value.getMinutes()), this.doSelect({
name: this.name,
value: this.value
}), !0;
},
updateMinute: function(e, t) {
return this.value = this.calcTime(this.value.getHours(), t.selected.value), this.doSelect({
name: this.name,
value: this.value
}), !0;
},
updateAmPm: function(e, t) {
var n = this.value.getHours();
return this.is24HrMode || (n += n > 11 ? this.isAm(t.content) ? -12 : 0 : this.isAm(t.content) ? 0 : 12), this.value = this.calcTime(n, this.value.getMinutes()), this.doSelect({
name: this.name,
value: this.value
}), !0;
},
calcTime: function(e, t) {
return new Date(this.value.getFullYear(), this.value.getMonth(), this.value.getDate(), e, t, this.value.getSeconds(), this.value.getMilliseconds());
},
isAm: function(e) {
var t, n, r;
try {
t = this._tf.getAmCaption(), n = this._tf.getPmCaption();
} catch (i) {
t = "AM", n = "PM";
}
return e == t ? !0 : !1;
},
refresh: function() {
this.destroyClientControls(), this.initDefaults(), this.render();
}
});

// RadioButton.js

enyo.kind({
name: "onyx.RadioButton",
kind: "Button",
classes: "onyx-radiobutton"
});

// RadioGroup.js

enyo.kind({
name: "onyx.RadioGroup",
kind: "Group",
defaultKind: "onyx.RadioButton",
highlander: !0
});

// ToggleButton.js

enyo.kind({
name: "onyx.ToggleButton",
classes: "onyx-toggle-button",
published: {
active: !1,
value: !1,
onContent: "On",
offContent: "Off",
disabled: !1
},
events: {
onChange: ""
},
handlers: {
ondragstart: "dragstart",
ondrag: "drag",
ondragfinish: "dragfinish"
},
components: [ {
name: "contentOn",
classes: "onyx-toggle-content on"
}, {
name: "contentOff",
classes: "onyx-toggle-content off"
}, {
classes: "onyx-toggle-button-knob"
} ],
create: function() {
this.inherited(arguments), this.value = Boolean(this.value || this.active), this.onContentChanged(), this.offContentChanged(), this.disabledChanged();
},
rendered: function() {
this.inherited(arguments), this.updateVisualState();
},
updateVisualState: function() {
this.addRemoveClass("off", !this.value), this.$.contentOn.setShowing(this.value), this.$.contentOff.setShowing(!this.value), this.setActive(this.value);
},
valueChanged: function() {
this.updateVisualState(), this.doChange({
value: this.value
});
},
activeChanged: function() {
this.setValue(this.active), this.bubble("onActivate");
},
onContentChanged: function() {
this.$.contentOn.setContent(this.onContent || ""), this.$.contentOn.addRemoveClass("empty", !this.onContent);
},
offContentChanged: function() {
this.$.contentOff.setContent(this.offContent || ""), this.$.contentOff.addRemoveClass("empty", !this.onContent);
},
disabledChanged: function() {
this.addRemoveClass("disabled", this.disabled);
},
updateValue: function(e) {
this.disabled || this.setValue(e);
},
tap: function() {
this.updateValue(!this.value);
},
dragstart: function(e, t) {
if (t.horizontal) return t.preventDefault(), this.dragging = !0, this.dragged = !1, !0;
},
drag: function(e, t) {
if (this.dragging) {
var n = t.dx;
return Math.abs(n) > 10 && (this.updateValue(n > 0), this.dragged = !0), !0;
}
},
dragfinish: function(e, t) {
this.dragging = !1, this.dragged && t.preventTap();
}
});

// ToggleIconButton.js

enyo.kind({
name: "onyx.ToggleIconButton",
kind: "onyx.Icon",
published: {
active: !1,
value: !1
},
events: {
onChange: ""
},
classes: "onyx-icon-button onyx-icon-toggle",
activeChanged: function() {
this.addRemoveClass("active", this.value), this.bubble("onActivate");
},
updateValue: function(e) {
this.disabled || (this.setValue(e), this.doChange({
value: this.value
}));
},
tap: function() {
this.updateValue(!this.value);
},
valueChanged: function() {
this.setActive(this.value);
},
create: function() {
this.inherited(arguments), this.value = Boolean(this.value || this.active);
},
rendered: function() {
this.inherited(arguments), this.valueChanged(), this.removeClass("onyx-icon");
}
});

// Toolbar.js

enyo.kind({
name: "onyx.Toolbar",
classes: "onyx onyx-toolbar onyx-toolbar-inline",
create: function() {
this.inherited(arguments), this.hasClass("onyx-menu-toolbar") && enyo.platform.android >= 4 && this.applyStyle("position", "static");
}
});

// Tooltip.js

enyo.kind({
name: "onyx.Tooltip",
kind: "onyx.Popup",
classes: "onyx-tooltip below left-arrow",
autoDismiss: !1,
showDelay: 500,
defaultLeft: -6,
handlers: {
onRequestShowTooltip: "requestShow",
onRequestHideTooltip: "requestHide"
},
requestShow: function() {
return this.showJob = setTimeout(enyo.bind(this, "show"), this.showDelay), !0;
},
cancelShow: function() {
clearTimeout(this.showJob);
},
requestHide: function() {
return this.cancelShow(), this.inherited(arguments);
},
showingChanged: function() {
this.cancelShow(), this.adjustPosition(!0), this.inherited(arguments);
},
applyPosition: function(e) {
var t = "";
for (var n in e) t += n + ":" + e[n] + (isNaN(e[n]) ? "; " : "px; ");
this.addStyles(t);
},
adjustPosition: function(e) {
if (this.showing && this.hasNode()) {
var t = this.node.getBoundingClientRect();
t.top + t.height > window.innerHeight ? (this.addRemoveClass("below", !1), this.addRemoveClass("above", !0)) : (this.addRemoveClass("above", !1), this.addRemoveClass("below", !0)), t.left + t.width > window.innerWidth && (this.applyPosition({
"margin-left": -t.width,
bottom: "auto"
}), this.addRemoveClass("left-arrow", !1), this.addRemoveClass("right-arrow", !0));
}
},
resizeHandler: function() {
this.applyPosition({
"margin-left": this.defaultLeft,
bottom: "auto"
}), this.addRemoveClass("left-arrow", !0), this.addRemoveClass("right-arrow", !1), this.adjustPosition(!0), this.inherited(arguments);
}
});

// TooltipDecorator.js

enyo.kind({
name: "onyx.TooltipDecorator",
defaultKind: "onyx.Button",
classes: "onyx-popup-decorator",
handlers: {
onenter: "enter",
onleave: "leave"
},
enter: function() {
this.requestShowTooltip();
},
leave: function() {
this.requestHideTooltip();
},
tap: function() {
this.requestHideTooltip();
},
requestShowTooltip: function() {
this.waterfallDown("onRequestShowTooltip");
},
requestHideTooltip: function() {
this.waterfallDown("onRequestHideTooltip");
}
});

// ProgressBar.js

enyo.kind({
name: "onyx.ProgressBar",
classes: "onyx-progress-bar",
published: {
progress: 0,
min: 0,
max: 100,
barClasses: "",
showStripes: !0,
animateStripes: !0,
increment: 0
},
events: {
onAnimateProgressFinish: ""
},
components: [ {
name: "progressAnimator",
kind: "Animator",
onStep: "progressAnimatorStep",
onEnd: "progressAnimatorComplete"
}, {
name: "bar",
classes: "onyx-progress-bar-bar"
} ],
create: function() {
this.inherited(arguments), this.progressChanged(), this.barClassesChanged(), this.showStripesChanged(), this.animateStripesChanged();
},
barClassesChanged: function(e) {
this.$.bar.removeClass(e), this.$.bar.addClass(this.barClasses);
},
showStripesChanged: function() {
this.$.bar.addRemoveClass("striped", this.showStripes);
},
animateStripesChanged: function() {
this.$.bar.addRemoveClass("animated", this.animateStripes);
},
progressChanged: function() {
this.progress = this.clampValue(this.min, this.max, this.progress);
var e = this.calcPercent(this.progress);
this.updateBarPosition(e);
},
calcIncrement: function(e) {
return Math.round(e / this.increment) * this.increment;
},
clampValue: function(e, t, n) {
return Math.max(e, Math.min(n, t));
},
calcRatio: function(e) {
return (e - this.min) / (this.max - this.min);
},
calcPercent: function(e) {
return this.calcRatio(e) * 100;
},
updateBarPosition: function(e) {
this.$.bar.applyStyle("width", e + "%");
},
animateProgressTo: function(e) {
this.$.progressAnimator.play({
startValue: this.progress,
endValue: e,
node: this.hasNode()
});
},
progressAnimatorStep: function(e) {
return this.setProgress(e.value), !0;
},
progressAnimatorComplete: function(e) {
return this.doAnimateProgressFinish(e), !0;
}
});

// ProgressButton.js

enyo.kind({
name: "onyx.ProgressButton",
kind: "onyx.ProgressBar",
classes: "onyx-progress-button",
events: {
onCancel: ""
},
components: [ {
name: "progressAnimator",
kind: "Animator",
onStep: "progressAnimatorStep",
onEnd: "progressAnimatorComplete"
}, {
name: "bar",
classes: "onyx-progress-bar-bar onyx-progress-button-bar"
}, {
name: "client",
classes: "onyx-progress-button-client"
}, {
kind: "onyx.Icon",
src: "$lib/onyx/images/progress-button-cancel.png",
classes: "onyx-progress-button-icon",
ontap: "cancelTap"
} ],
cancelTap: function() {
this.doCancel();
}
});

// Scrim.js

enyo.kind({
name: "onyx.Scrim",
showing: !1,
classes: "onyx-scrim enyo-fit",
floating: !1,
create: function() {
this.inherited(arguments), this.zStack = [], this.floating && this.setParent(enyo.floatingLayer);
},
showingChanged: function() {
this.floating && this.showing && !this.hasNode() && this.render(), this.inherited(arguments);
},
addZIndex: function(e) {
enyo.indexOf(e, this.zStack) < 0 && this.zStack.push(e);
},
removeZIndex: function(e) {
enyo.remove(e, this.zStack);
},
showAtZIndex: function(e) {
this.addZIndex(e), e !== undefined && this.setZIndex(e), this.show();
},
hideAtZIndex: function(e) {
this.removeZIndex(e);
if (!this.zStack.length) this.hide(); else {
var t = this.zStack[this.zStack.length - 1];
this.setZIndex(t);
}
},
setZIndex: function(e) {
this.zIndex = e, this.applyStyle("z-index", e);
},
make: function() {
return this;
}
}), enyo.kind({
name: "onyx.scrimSingleton",
kind: null,
constructor: function(e, t) {
this.instanceName = e, enyo.setObject(this.instanceName, this), this.props = t || {};
},
make: function() {
var e = new onyx.Scrim(this.props);
return enyo.setObject(this.instanceName, e), e;
},
showAtZIndex: function(e) {
var t = this.make();
t.showAtZIndex(e);
},
hideAtZIndex: enyo.nop,
show: function() {
var e = this.make();
e.show();
}
}), new onyx.scrimSingleton("onyx.scrim", {
floating: !0,
classes: "onyx-scrim-translucent"
}), new onyx.scrimSingleton("onyx.scrimTransparent", {
floating: !0,
classes: "onyx-scrim-transparent"
});

// Slider.js

enyo.kind({
name: "onyx.Slider",
kind: "onyx.ProgressBar",
classes: "onyx-slider",
published: {
value: 0,
lockBar: !0,
tappable: !0
},
events: {
onChange: "",
onChanging: "",
onAnimateFinish: ""
},
showStripes: !1,
handlers: {
ondragstart: "dragstart",
ondrag: "drag",
ondragfinish: "dragfinish"
},
moreComponents: [ {
kind: "Animator",
onStep: "animatorStep",
onEnd: "animatorComplete"
}, {
classes: "onyx-slider-taparea"
}, {
name: "knob",
classes: "onyx-slider-knob"
} ],
create: function() {
this.inherited(arguments), enyo.platform.firefoxOS && (this.moreComponents[2].ondown = "down", this.moreComponents[2].onleave = "leave"), this.createComponents(this.moreComponents), this.valueChanged();
},
valueChanged: function() {
this.value = this.clampValue(this.min, this.max, this.value);
var e = this.calcPercent(this.value);
this.updateKnobPosition(e), this.lockBar && this.setProgress(this.value);
},
updateKnobPosition: function(e) {
this.$.knob.applyStyle("left", e + "%");
},
calcKnobPosition: function(e) {
var t = e.clientX - this.hasNode().getBoundingClientRect().left;
return t / this.getBounds().width * (this.max - this.min) + this.min;
},
dragstart: function(e, t) {
if (t.horizontal) return t.preventDefault(), this.dragging = !0, !0;
},
drag: function(e, t) {
if (this.dragging) {
var n = this.calcKnobPosition(t);
return n = this.increment ? this.calcIncrement(n) : n, this.setValue(n), this.doChanging({
value: this.value
}), !0;
}
},
dragfinish: function(e, t) {
return this.dragging = !1, t.preventTap(), this.doChange({
value: this.value
}), !0;
},
tap: function(e, t) {
if (this.tappable) {
var n = this.calcKnobPosition(t);
return n = this.increment ? this.calcIncrement(n) : n, this.tapped = !0, this.animateTo(n), !0;
}
},
down: function(e, t) {
this.addClass("pressed");
},
leave: function(e, t) {
this.removeClass("pressed");
},
animateTo: function(e) {
this.$.animator.play({
startValue: this.value,
endValue: e,
node: this.hasNode()
});
},
animatorStep: function(e) {
return this.setValue(e.value), !0;
},
animatorComplete: function(e) {
return this.tapped && (this.tapped = !1, this.doChange({
value: this.value
})), this.doAnimateFinish(e), !0;
}
});

// RangeSlider.js

enyo.kind({
name: "onyx.RangeSlider",
kind: "onyx.ProgressBar",
classes: "onyx-slider",
published: {
rangeMin: 0,
rangeMax: 100,
rangeStart: 0,
rangeEnd: 100,
beginValue: 0,
endValue: 0
},
events: {
onChange: "",
onChanging: ""
},
showStripes: !1,
showLabels: !1,
handlers: {
ondragstart: "dragstart",
ondrag: "drag",
ondragfinish: "dragfinish",
ondown: "down"
},
moreComponents: [ {
name: "startKnob",
classes: "onyx-slider-knob"
}, {
name: "endKnob",
classes: "onyx-slider-knob onyx-range-slider-knob"
} ],
create: function() {
this.inherited(arguments), this.createComponents(this.moreComponents), this.initControls();
},
rendered: function() {
this.inherited(arguments);
var e = this.calcPercent(this.beginValue);
this.updateBarPosition(e);
},
initControls: function() {
this.$.bar.applyStyle("position", "relative"), this.refreshRangeSlider(), this.showLabels && (this.$.startKnob.createComponent({
name: "startLabel",
kind: "onyx.RangeSliderKnobLabel"
}), this.$.endKnob.createComponent({
name: "endLabel",
kind: "onyx.RangeSliderKnobLabel"
}));
},
refreshRangeSlider: function() {
this.beginValue = this.calcKnobPercent(this.rangeStart), this.endValue = this.calcKnobPercent(this.rangeEnd), this.beginValueChanged(), this.endValueChanged();
},
calcKnobRatio: function(e) {
return (e - this.rangeMin) / (this.rangeMax - this.rangeMin);
},
calcKnobPercent: function(e) {
return this.calcKnobRatio(e) * 100;
},
beginValueChanged: function(e) {
if (e === undefined) {
var t = this.calcPercent(this.beginValue);
this.updateKnobPosition(t, this.$.startKnob);
}
},
endValueChanged: function(e) {
if (e === undefined) {
var t = this.calcPercent(this.endValue);
this.updateKnobPosition(t, this.$.endKnob);
}
},
calcKnobPosition: function(e) {
var t = e.clientX - this.hasNode().getBoundingClientRect().left;
return t / this.getBounds().width * (this.max - this.min) + this.min;
},
updateKnobPosition: function(e, t) {
t.applyStyle("left", e + "%"), this.updateBarPosition();
},
updateBarPosition: function() {
if (this.$.startKnob !== undefined && this.$.endKnob !== undefined) {
var e = this.calcKnobPercent(this.rangeStart), t = this.calcKnobPercent(this.rangeEnd) - e;
this.$.bar.applyStyle("left", e + "%"), this.$.bar.applyStyle("width", t + "%");
}
},
calcRangeRatio: function(e) {
return e / 100 * (this.rangeMax - this.rangeMin) + this.rangeMin - this.increment / 2;
},
swapZIndex: function(e) {
e === "startKnob" ? (this.$.startKnob.applyStyle("z-index", 1), this.$.endKnob.applyStyle("z-index", 0)) : e === "endKnob" && (this.$.startKnob.applyStyle("z-index", 0), this.$.endKnob.applyStyle("z-index", 1));
},
down: function(e, t) {
this.swapZIndex(e.name);
},
dragstart: function(e, t) {
if (t.horizontal) return t.preventDefault(), this.dragging = !0, !0;
},
drag: function(e, t) {
if (this.dragging) {
var n = this.calcKnobPosition(t), r, i, s;
if (e.name === "startKnob" && n >= 0) {
if (!(n <= this.endValue && t.xDirection === -1 || n <= this.endValue)) return this.drag(this.$.endKnob, t);
this.setBeginValue(n), r = this.calcRangeRatio(this.beginValue), i = this.increment ? this.calcIncrement(r + .5 * this.increment) : r, s = this.calcKnobPercent(i), this.updateKnobPosition(s, this.$.startKnob), this.setRangeStart(i), this.doChanging({
value: i
});
} else if (e.name === "endKnob" && n <= 100) {
if (!(n >= this.beginValue && t.xDirection === 1 || n >= this.beginValue)) return this.drag(this.$.startKnob, t);
this.setEndValue(n), r = this.calcRangeRatio(this.endValue), i = this.increment ? this.calcIncrement(r + .5 * this.increment) : r, s = this.calcKnobPercent(i), this.updateKnobPosition(s, this.$.endKnob), this.setRangeEnd(i), this.doChanging({
value: i
});
}
return !0;
}
},
dragfinish: function(e, t) {
this.dragging = !1, t.preventTap();
var n;
return e.name === "startKnob" ? (n = this.calcRangeRatio(this.beginValue), this.doChange({
value: n,
startChanged: !0
})) : e.name === "endKnob" && (n = this.calcRangeRatio(this.endValue), this.doChange({
value: n,
startChanged: !1
})), !0;
},
rangeMinChanged: function() {
this.refreshRangeSlider();
},
rangeMaxChanged: function() {
this.refreshRangeSlider();
},
rangeStartChanged: function() {
this.refreshRangeSlider();
},
rangeEndChanged: function() {
this.refreshRangeSlider();
},
setStartLabel: function(e) {
this.$.startKnob.waterfallDown("onSetLabel", e);
},
setEndLabel: function(e) {
this.$.endKnob.waterfallDown("onSetLabel", e);
}
}), enyo.kind({
name: "onyx.RangeSliderKnobLabel",
classes: "onyx-range-slider-label",
handlers: {
onSetLabel: "setLabel"
},
setLabel: function(e, t) {
this.setContent(t);
}
});

// Item.js

enyo.kind({
name: "onyx.Item",
classes: "onyx-item",
tapHighlight: !0,
handlers: {
onhold: "hold",
onrelease: "release"
},
hold: function(e, t) {
this.tapHighlight && onyx.Item.addRemoveFlyweightClass(this.controlParent || this, "onyx-highlight", !0, t);
},
release: function(e, t) {
this.tapHighlight && onyx.Item.addRemoveFlyweightClass(this.controlParent || this, "onyx-highlight", !1, t);
},
statics: {
addRemoveFlyweightClass: function(e, t, n, r, i) {
var s = r.flyweight;
if (s) {
var o = i !== undefined ? i : r.index;
s.performOnRow(o, function() {
e.addRemoveClass(t, n);
});
}
}
}
});

// Spinner.js

enyo.kind({
name: "onyx.Spinner",
classes: "onyx-spinner",
stop: function() {
this.setShowing(!1);
},
start: function() {
this.setShowing(!0);
},
toggle: function() {
this.setShowing(!this.getShowing());
}
});

// MoreToolbar.js

enyo.kind({
name: "onyx.MoreToolbar",
classes: "onyx-toolbar onyx-more-toolbar",
menuClass: "",
movedClass: "",
layoutKind: "FittableColumnsLayout",
noStretch: !0,
handlers: {
onHide: "reflow"
},
published: {
clientLayoutKind: "FittableColumnsLayout"
},
tools: [ {
name: "client",
noStretch: !0,
fit: !0,
classes: "onyx-toolbar-inline"
}, {
name: "nard",
kind: "onyx.MenuDecorator",
showing: !1,
onActivate: "activated",
components: [ {
kind: "onyx.IconButton",
classes: "onyx-more-button"
}, {
name: "menu",
kind: "onyx.Menu",
scrolling: !1,
classes: "onyx-more-menu"
} ]
} ],
initComponents: function() {
this.menuClass && this.menuClass.length > 0 && !this.$.menu.hasClass(this.menuClass) && this.$.menu.addClass(this.menuClass), this.createChrome(this.tools), this.inherited(arguments), this.$.client.setLayoutKind(this.clientLayoutKind);
},
clientLayoutKindChanged: function() {
this.$.client.setLayoutKind(this.clientLayoutKind);
},
reflow: function() {
this.inherited(arguments), this.isContentOverflowing() ? (this.$.nard.show(), this.popItem() && this.reflow()) : this.tryPushItem() ? this.reflow() : this.$.menu.children.length || (this.$.nard.hide(), this.$.menu.hide());
},
activated: function(e, t) {
this.addRemoveClass("active", t.originator.active);
},
popItem: function() {
var e = this.findCollapsibleItem();
if (e) {
this.movedClass && this.movedClass.length > 0 && !e.hasClass(this.movedClass) && e.addClass(this.movedClass), this.$.menu.addChild(e, null);
var t = this.$.menu.hasNode();
return t && e.hasNode() && e.insertNodeInParent(t), !0;
}
},
pushItem: function() {
var e = this.$.menu.children, t = e[0];
if (t) {
this.movedClass && this.movedClass.length > 0 && t.hasClass(this.movedClass) && t.removeClass(this.movedClass), this.$.client.addChild(t);
var n = this.$.client.hasNode();
if (n && t.hasNode()) {
var r, i;
for (var s = 0; s < this.$.client.children.length; s++) {
var o = this.$.client.children[s];
if (o.toolbarIndex !== undefined && o.toolbarIndex != s) {
r = o, i = s;
break;
}
}
if (r && r.hasNode()) {
t.insertNodeInParent(n, r.node);
var u = this.$.client.children.pop();
this.$.client.children.splice(i, 0, u);
} else t.appendNodeToParent(n);
}
return !0;
}
},
tryPushItem: function() {
if (this.pushItem()) {
if (!this.isContentOverflowing()) return !0;
this.popItem();
}
},
isContentOverflowing: function() {
if (this.$.client.hasNode()) {
var e = this.$.client.children, t = e[e.length - 1].hasNode();
if (t) return this.$.client.reflow(), t.offsetLeft + t.offsetWidth > this.$.client.node.clientWidth;
}
},
findCollapsibleItem: function() {
var e = this.$.client.children;
for (var t = e.length - 1; c = e[t]; t--) {
if (!c.unmoveable) return c;
c.toolbarIndex === undefined && (c.toolbarIndex = t);
}
}
});

// IntegerPicker.js

enyo.kind({
name: "onyx.IntegerPicker",
kind: "onyx.Picker",
published: {
value: 0,
min: 0,
max: 9
},
create: function() {
this.inherited(arguments), this.rangeChanged();
},
minChanged: function() {
this.destroyClientControls(), this.rangeChanged(), this.render();
},
maxChanged: function() {
this.destroyClientControls(), this.rangeChanged(), this.render();
},
rangeChanged: function() {
for (var e = this.min; e <= this.max; e++) this.createComponent({
content: e,
active: e === this.value ? !0 : !1
});
},
valueChanged: function(e) {
var t = this.getClientControls(), n = t.length;
this.value = this.value >= this.min && this.value <= this.max ? this.value : this.min;
for (var r = 0; r < n; r++) if (this.value === parseInt(t[r].content)) {
this.setSelected(t[r]);
break;
}
},
selectedChanged: function(e) {
e && e.removeClass("selected"), this.selected && (this.selected.addClass("selected"), this.doChange({
selected: this.selected,
content: this.selected.content
})), this.value = parseInt(this.selected.content);
}
});

// ContextualPopup.js

enyo.kind({
name: "onyx.ContextualPopup",
kind: "enyo.Popup",
modal: !0,
autoDismiss: !0,
floating: !1,
classes: "onyx-contextual-popup enyo-unselectable",
published: {
maxHeight: 100,
scrolling: !0,
title: undefined,
actionButtons: []
},
vertFlushMargin: 60,
horizFlushMargin: 50,
widePopup: 200,
longPopup: 200,
horizBuffer: 16,
events: {
onTap: ""
},
handlers: {
onActivate: "itemActivated",
onRequestShowMenu: "requestShow",
onRequestHideMenu: "requestHide"
},
components: [ {
name: "title",
classes: "onyx-contextual-popup-title"
}, {
classes: "onyx-contextual-popup-scroller",
components: [ {
name: "client",
kind: "enyo.Scroller",
vertical: "auto",
classes: "enyo-unselectable",
thumb: !1,
strategyKind: "TouchScrollStrategy"
} ]
}, {
name: "actionButtons",
classes: "onyx-contextual-popup-action-buttons"
} ],
scrollerName: "client",
create: function() {
this.inherited(arguments), this.maxHeightChanged(), this.titleChanged(), this.actionButtonsChanged();
},
getScroller: function() {
return this.$[this.scrollerName];
},
titleChanged: function() {
this.$.title.setContent(this.title);
},
actionButtonsChanged: function() {
for (var e = 0; e < this.actionButtons.length; e++) this.$.actionButtons.createComponent({
kind: "onyx.Button",
content: this.actionButtons[e].content,
classes: this.actionButtons[e].classes + " onyx-contextual-popup-action-button",
name: this.actionButtons[e].name ? this.actionButtons[e].name : "ActionButton" + e,
index: e,
tap: enyo.bind(this, this.tapHandler)
});
},
tapHandler: function(e, t) {
return t.actionButton = !0, t.popup = this, this.bubble("ontap", t), !0;
},
maxHeightChanged: function() {
this.scrolling && this.getScroller().setMaxHeight(this.maxHeight + "px");
},
itemActivated: function(e, t) {
return t.originator.setActive(!1), !0;
},
showingChanged: function() {
this.inherited(arguments), this.scrolling && this.getScroller().setShowing(this.showing), this.adjustPosition();
},
requestShow: function(e, t) {
var n = t.activator.hasNode();
return n && (this.activatorOffset = this.getPageOffset(n)), this.show(), !0;
},
applyPosition: function(e) {
var t = "";
for (var n in e) t += n + ":" + e[n] + (isNaN(e[n]) ? "; " : "px; ");
this.addStyles(t);
},
getPageOffset: function(e) {
var t = this.getBoundingRect(e), n = window.pageYOffset === undefined ? document.documentElement.scrollTop : window.pageYOffset, r = window.pageXOffset === undefined ? document.documentElement.scrollLeft : window.pageXOffset, i = t.height === undefined ? t.bottom - t.top : t.height, s = t.width === undefined ? t.right - t.left : t.width;
return {
top: t.top + n,
left: t.left + r,
height: i,
width: s
};
},
adjustPosition: function() {
if (this.showing && this.hasNode()) {
this.resetPositioning();
var e = this.getViewWidth(), t = this.getViewHeight(), n = this.vertFlushMargin, r = t - this.vertFlushMargin, i = this.horizFlushMargin, s = e - this.horizFlushMargin;
if (this.activatorOffset.top + this.activatorOffset.height < n || this.activatorOffset.top > r) {
if (this.applyVerticalFlushPositioning(i, s)) return;
if (this.applyHorizontalFlushPositioning(i, s)) return;
if (this.applyVerticalPositioning()) return;
} else if (this.activatorOffset.left + this.activatorOffset.width < i || this.activatorOffset.left > s) if (this.applyHorizontalPositioning()) return;
var o = this.getBoundingRect(this.node);
if (o.width > this.widePopup) {
if (this.applyVerticalPositioning()) return;
} else if (o.height > this.longPopup && this.applyHorizontalPositioning()) return;
if (this.applyVerticalPositioning()) return;
if (this.applyHorizontalPositioning()) return;
}
},
initVerticalPositioning: function() {
this.resetPositioning(), this.addClass("vertical");
var e = this.getBoundingRect(this.node), t = this.getViewHeight();
return this.floating ? this.activatorOffset.top < t / 2 ? (this.applyPosition({
top: this.activatorOffset.top + this.activatorOffset.height,
bottom: "auto"
}), this.addClass("below")) : (this.applyPosition({
top: this.activatorOffset.top - e.height,
bottom: "auto"
}), this.addClass("above")) : e.top + e.height > t && t - e.bottom < e.top - e.height ? this.addClass("above") : this.addClass("below"), e = this.getBoundingRect(this.node), e.top + e.height > t || e.top < 0 ? !1 : !0;
},
applyVerticalPositioning: function() {
if (!this.initVerticalPositioning()) return !1;
var e = this.getBoundingRect(this.node), t = this.getViewWidth();
if (this.floating) {
var n = this.activatorOffset.left + this.activatorOffset.width / 2 - e.width / 2;
n + e.width > t ? (this.applyPosition({
left: this.activatorOffset.left + this.activatorOffset.width - e.width
}), this.addClass("left")) : n < 0 ? (this.applyPosition({
left: this.activatorOffset.left
}), this.addClass("right")) : this.applyPosition({
left: n
});
} else {
var r = this.activatorOffset.left + this.activatorOffset.width / 2 - e.left - e.width / 2;
e.right + r > t ? (this.applyPosition({
left: this.activatorOffset.left + this.activatorOffset.width - e.right
}), this.addRemoveClass("left", !0)) : e.left + r < 0 ? this.addRemoveClass("right", !0) : this.applyPosition({
left: r
});
}
return !0;
},
applyVerticalFlushPositioning: function(e, t) {
if (!this.initVerticalPositioning()) return !1;
var n = this.getBoundingRect(this.node), r = this.getViewWidth();
return this.activatorOffset.left + this.activatorOffset.width / 2 < e ? (this.activatorOffset.left + this.activatorOffset.width / 2 < this.horizBuffer ? this.applyPosition({
left: this.horizBuffer + (this.floating ? 0 : -n.left)
}) : this.applyPosition({
left: this.activatorOffset.width / 2 + (this.floating ? this.activatorOffset.left : 0)
}), this.addClass("right"), this.addClass("corner"), !0) : this.activatorOffset.left + this.activatorOffset.width / 2 > t ? (this.activatorOffset.left + this.activatorOffset.width / 2 > r - this.horizBuffer ? this.applyPosition({
left: r - this.horizBuffer - n.right
}) : this.applyPosition({
left: this.activatorOffset.left + this.activatorOffset.width / 2 - n.right
}), this.addClass("left"), this.addClass("corner"), !0) : !1;
},
initHorizontalPositioning: function() {
this.resetPositioning();
var e = this.getBoundingRect(this.node), t = this.getViewWidth();
return this.floating ? this.activatorOffset.left + this.activatorOffset.width < t / 2 ? (this.applyPosition({
left: this.activatorOffset.left + this.activatorOffset.width
}), this.addRemoveClass("left", !0)) : (this.applyPosition({
left: this.activatorOffset.left - e.width
}), this.addRemoveClass("right", !0)) : this.activatorOffset.left - e.width > 0 ? (this.applyPosition({
left: this.activatorOffset.left - e.left - e.width
}), this.addRemoveClass("right", !0)) : (this.applyPosition({
left: this.activatorOffset.width
}), this.addRemoveClass("left", !0)), this.addRemoveClass("horizontal", !0), e = this.getBoundingRect(this.node), e.left < 0 || e.left + e.width > t ? !1 : !0;
},
applyHorizontalPositioning: function() {
if (!this.initHorizontalPositioning()) return !1;
var e = this.getBoundingRect(this.node), t = this.getViewHeight(), n = this.activatorOffset.top + this.activatorOffset.height / 2;
return this.floating ? n >= t / 2 - .05 * t && n <= t / 2 + .05 * t ? this.applyPosition({
top: this.activatorOffset.top + this.activatorOffset.height / 2 - e.height / 2,
bottom: "auto"
}) : this.activatorOffset.top + this.activatorOffset.height < t / 2 ? (this.applyPosition({
top: this.activatorOffset.top - this.activatorOffset.height,
bottom: "auto"
}), this.addRemoveClass("high", !0)) : (this.applyPosition({
top: this.activatorOffset.top - e.height + this.activatorOffset.height * 2,
bottom: "auto"
}), this.addRemoveClass("low", !0)) : n >= t / 2 - .05 * t && n <= t / 2 + .05 * t ? this.applyPosition({
top: (this.activatorOffset.height - e.height) / 2
}) : this.activatorOffset.top + this.activatorOffset.height < t / 2 ? (this.applyPosition({
top: -this.activatorOffset.height
}), this.addRemoveClass("high", !0)) : (this.applyPosition({
top: e.top - e.height - this.activatorOffset.top + this.activatorOffset.height
}), this.addRemoveClass("low", !0)), !0;
},
applyHorizontalFlushPositioning: function(e, t) {
if (!this.initHorizontalPositioning()) return !1;
var n = this.getBoundingRect(this.node), r = this.getViewWidth();
return this.floating ? this.activatorOffset.top < innerHeight / 2 ? (this.applyPosition({
top: this.activatorOffset.top + this.activatorOffset.height / 2
}), this.addRemoveClass("high", !0)) : (this.applyPosition({
top: this.activatorOffset.top + this.activatorOffset.height / 2 - n.height
}), this.addRemoveClass("low", !0)) : n.top + n.height > innerHeight && innerHeight - n.bottom < n.top - n.height ? (this.applyPosition({
top: n.top - n.height - this.activatorOffset.top - this.activatorOffset.height / 2
}), this.addRemoveClass("low", !0)) : (this.applyPosition({
top: this.activatorOffset.height / 2
}), this.addRemoveClass("high", !0)), this.activatorOffset.left + this.activatorOffset.width < e ? (this.addClass("left"), this.addClass("corner"), !0) : this.activatorOffset.left > t ? (this.addClass("right"), this.addClass("corner"), !0) : !1;
},
getBoundingRect: function(e) {
var t = e.getBoundingClientRect();
return !t.width || !t.height ? {
left: t.left,
right: t.right,
top: t.top,
bottom: t.bottom,
width: t.right - t.left,
height: t.bottom - t.top
} : t;
},
getViewHeight: function() {
return window.innerHeight === undefined ? document.documentElement.clientHeight : window.innerHeight;
},
getViewWidth: function() {
return window.innerWidth === undefined ? document.documentElement.clientWidth : window.innerWidth;
},
resetPositioning: function() {
this.removeClass("right"), this.removeClass("left"), this.removeClass("high"), this.removeClass("low"), this.removeClass("corner"), this.removeClass("below"), this.removeClass("above"), this.removeClass("vertical"), this.removeClass("horizontal"), this.applyPosition({
left: "auto"
}), this.applyPosition({
top: "auto"
});
},
resizeHandler: function() {
this.inherited(arguments), this.adjustPosition();
},
requestHide: function() {
this.setShowing(!1);
}
});

// App.js

enyo.kind({
name: "App",
kind: "FittableRows",
fit: !0,
components: [ {
kind: "onyx.Toolbar",
content: "Hello World"
}, {
kind: "enyo.Scroller",
fit: !0,
components: [ {
name: "main",
classes: "nice-padding",
allowHtml: !0
} ]
}, {
kind: "onyx.Toolbar",
components: [ {
kind: "onyx.Button",
content: "Tap me",
ontap: "helloWorldTap"
} ]
} ],
helloWorldTap: function(e, t) {
this.$.main.addContent("The button was tapped.<br/>");
}
});
