/*
 * QuickJS atom definitions
 * 
 * Copyright (c) 2017-2018 Fabrice Bellard
 * Copyright (c) 2017-2018 Charlie Gordon
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifdef DEF

/* Note: first atoms are considered as keywords in the parser */
DEF(null, "null") /* must be first */
DEF(false, "false")
DEF(true, "true")
DEF(if, "if")
DEF(else, "else")
DEF(return, "return")
DEF(var, "var")
DEF(this, "this")
DEF(delete, "delete")
DEF(void, "void")
DEF(typeof, "typeof")
DEF(new, "new")
DEF(in, "in")
DEF(instanceof, "instanceof")
DEF(do, "do")
DEF(while, "while")
DEF(for, "for")
DEF(break, "break")
DEF(continue, "continue")
DEF(switch, "switch")
DEF(case, "case")
DEF(default, "default")
DEF(throw, "throw")
DEF(try, "try")
DEF(catch, "catch")
DEF(finally, "finally")
DEF(function, "function")
DEF(debugger, "debugger")
DEF(with, "with")
/* FutureReservedWord */
DEF(class, "class")
DEF(const, "const")
DEF(enum, "enum")
DEF(export, "export")
DEF(extends, "extends")
DEF(import, "import")
DEF(super, "super")
/* FutureReservedWords when parsing strict mode code */
DEF(implements, "implements")
DEF(interface, "interface")
DEF(let, "let")
DEF(package, "package")
DEF(private, "private")
DEF(protected, "protected")
DEF(public, "public")
DEF(static, "static")
DEF(yield, "yield")
DEF(await, "await")

/* empty string */
DEF(empty_string, "")
/* identifiers */
DEF(length, "length")
DEF(fileName, "fileName")
DEF(lineNumber, "lineNumber")
DEF(message, "message")
DEF(errors, "errors")
DEF(stack, "stack")
DEF(prepareStackTrace, "prepareStackTrace")
DEF(name, "name")
DEF(toString, "toString")
DEF(toLocaleString, "toLocaleString")
DEF(valueOf, "valueOf")
DEF(eval, "eval")
DEF(prototype, "prototype")
DEF(constructor, "constructor")
DEF(configurable, "configurable")
DEF(writable, "writable")
DEF(enumerable, "enumerable")
DEF(value, "value")
DEF(get, "get")
DEF(set, "set")
DEF(of, "of")
DEF(__proto__, "__proto__")
DEF(undefined, "undefined")
DEF(number, "number")
DEF(boolean, "boolean")
DEF(string, "string")
DEF(object, "object")
DEF(symbol, "symbol")
DEF(integer, "integer")
DEF(unknown, "unknown")
DEF(arguments, "arguments")
DEF(callee, "callee")
DEF(caller, "caller")
DEF(_eval_, "<eval>")
DEF(_ret_, "<ret>")
DEF(_var_, "<var>")
DEF(_arg_var_, "<arg_var>")
DEF(_with_, "<with>")
DEF(lastIndex, "lastIndex")
DEF(target, "target")
DEF(index, "index")
DEF(input, "input")
DEF(defineProperties, "defineProperties")
DEF(apply, "apply")
DEF(join, "join")
DEF(concat, "concat")
DEF(split, "split")
DEF(construct, "construct")
DEF(getPrototypeOf, "getPrototypeOf")
DEF(setPrototypeOf, "setPrototypeOf")
DEF(isExtensible, "isExtensible")
DEF(preventExtensions, "preventExtensions")
DEF(has, "has")
DEF(deleteProperty, "deleteProperty")
DEF(defineProperty, "defineProperty")
DEF(getOwnPropertyDescriptor, "getOwnPropertyDescriptor")
DEF(ownKeys, "ownKeys")
DEF(add, "add")
DEF(done, "done")
DEF(next, "next")
DEF(values, "values")
DEF(source, "source")
DEF(flags, "flags")
DEF(global, "global")
DEF(unicode, "unicode")
DEF(raw, "raw")
DEF(new_target, "new.target")
DEF(this_active_func, "this.active_func")
DEF(home_object, "<home_object>")
DEF(computed_field, "<computed_field>")
DEF(static_computed_field, "<static_computed_field>") /* must come after computed_fields */
DEF(class_fields_init, "<class_fields_init>")
DEF(brand, "<brand>")
DEF(hash_constructor, "#constructor")
DEF(as, "as")
DEF(from, "from")
DEF(meta, "meta")
DEF(_default_, "*default*")
DEF(_star_, "*")
DEF(Module, "Module")
DEF(then, "then")
DEF(resolve, "resolve")
DEF(reject, "reject")
DEF(promise, "promise")
DEF(proxy, "proxy")
DEF(revoke, "revoke")
DEF(async, "async")
DEF(exec, "exec")
DEF(groups, "groups")
DEF(status, "status")
DEF(reason, "reason")
DEF(globalThis, "globalThis")
#ifdef CONFIG_BIGNUM
DEF(bigint, "bigint")
DEF(bigfloat, "bigfloat")
DEF(bigdecimal, "bigdecimal")
DEF(roundingMode, "roundingMode")
DEF(maximumSignificantDigits, "maximumSignificantDigits")
DEF(maximumFractionDigits, "maximumFractionDigits")
#endif
#ifdef CONFIG_ATOMICS
DEF(not_equal, "not-equal")
DEF(timed_out, "timed-out")
DEF(ok, "ok")
#endif
DEF(toJSON, "toJSON")
/* class names */
DEF(Object, "Object")
DEF(Array, "Array")
DEF(Error, "Error")
DEF(Number, "Number")
DEF(String, "String")
DEF(Boolean, "Boolean")
DEF(Symbol, "Symbol")
DEF(Arguments, "Arguments")
DEF(Math, "Math")
DEF(JSON, "JSON")
DEF(Date, "Date")
DEF(Function, "Function")
DEF(GeneratorFunction, "GeneratorFunction")
DEF(ForInIterator, "ForInIterator")
DEF(RegExp, "RegExp")
DEF(ArrayBuffer, "ArrayBuffer")
DEF(SharedArrayBuffer, "SharedArrayBuffer")
/* must keep same order as class IDs for typed arrays */
DEF(Uint8ClampedArray, "Uint8ClampedArray") 
DEF(Int8Array, "Int8Array")
DEF(Uint8Array, "Uint8Array")
DEF(Int16Array, "Int16Array")
DEF(Uint16Array, "Uint16Array")
DEF(Int32Array, "Int32Array")
DEF(Uint32Array, "Uint32Array")
#ifdef CONFIG_BIGNUM
DEF(BigInt64Array, "BigInt64Array")
DEF(BigUint64Array, "BigUint64Array")
#endif
DEF(Float32Array, "Float32Array")
DEF(Float64Array, "Float64Array")
DEF(DataView, "DataView")
#ifdef CONFIG_BIGNUM
DEF(BigInt, "BigInt")
DEF(BigFloat, "BigFloat")
DEF(BigFloatEnv, "BigFloatEnv")
DEF(BigDecimal, "BigDecimal")
DEF(OperatorSet, "OperatorSet")
DEF(Operators, "Operators")
#endif
DEF(Map, "Map")
DEF(Set, "Set") /* Map + 1 */
DEF(WeakMap, "WeakMap") /* Map + 2 */
DEF(WeakSet, "WeakSet") /* Map + 3 */
DEF(Map_Iterator, "Map Iterator")
DEF(Set_Iterator, "Set Iterator")
DEF(Array_Iterator, "Array Iterator")
DEF(String_Iterator, "String Iterator")
DEF(RegExp_String_Iterator, "RegExp String Iterator")
DEF(Generator, "Generator")
DEF(Proxy, "Proxy")
DEF(Promise, "Promise")
DEF(PromiseResolveFunction, "PromiseResolveFunction")
DEF(PromiseRejectFunction, "PromiseRejectFunction")
DEF(AsyncFunction, "AsyncFunction")
DEF(AsyncFunctionResolve, "AsyncFunctionResolve")
DEF(AsyncFunctionReject, "AsyncFunctionReject")
DEF(AsyncGeneratorFunction, "AsyncGeneratorFunction")
DEF(AsyncGenerator, "AsyncGenerator")
DEF(EvalError, "EvalError")
DEF(RangeError, "RangeError")
DEF(ReferenceError, "ReferenceError")
DEF(SyntaxError, "SyntaxError")
DEF(TypeError, "TypeError")
DEF(URIError, "URIError")
DEF(InternalError, "InternalError")
/* private symbols */
DEF(Private_brand, "<brand>")
/* symbols */
DEF(Symbol_toPrimitive, "Symbol.toPrimitive")
DEF(Symbol_iterator, "Symbol.iterator")
DEF(Symbol_match, "Symbol.match")
DEF(Symbol_matchAll, "Symbol.matchAll")
DEF(Symbol_replace, "Symbol.replace")
DEF(Symbol_search, "Symbol.search")
DEF(Symbol_split, "Symbol.split")
DEF(Symbol_toStringTag, "Symbol.toStringTag")
DEF(Symbol_isConcatSpreadable, "Symbol.isConcatSpreadable")
DEF(Symbol_hasInstance, "Symbol.hasInstance")
DEF(Symbol_species, "Symbol.species")
DEF(Symbol_unscopables, "Symbol.unscopables")
DEF(Symbol_asyncIterator, "Symbol.asyncIterator")
#ifdef CONFIG_BIGNUM
DEF(Symbol_operatorSet, "Symbol.operatorSet")
#endif
    
#endif /* DEF */
