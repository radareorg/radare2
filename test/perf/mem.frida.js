
var mallocPtr = Module.findExportByName(null, "malloc");
var malloc = new NativeFunction(mallocPtr, 'pointer', ['long']);

var freePtr = Module.findExportByName(null, "free");
var freel = new NativeFunction(freePtr, 'void', ['pointer']);

var reallocPtr = Module.findExportByName(null, "realloc");
var reallocl = new NativeFunction(reallocPtr, 'pointer', ['pointer', 'long']);

Interceptor.replace(mallocPtr, new NativeCallback(function (size) {
    var p = malloc(size);
    console.error("mem::malloc " + size +" = " + p);
    return p;
}, 'pointer', ['int']));

Interceptor.replace(freePtr, new NativeCallback(function (p) {
    freel(p);
    if (+p != 0) console.error("mem::free " + p);
}, 'void', ['pointer']));

Interceptor.replace(reallocPtr, new NativeCallback(function (p, size) {
    var p_ret = reallocl(p, size);
    console.error("mem::realloc " + p + " " + size + " = " + p_ret);
    return p_ret;
}, 'pointer', ['pointer', 'int']));
