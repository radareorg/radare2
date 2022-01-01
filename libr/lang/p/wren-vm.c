// MIT License
// 
// Copyright (c) 2013-2021 Robert Nystrom and Wren Contributors
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Begin file "wren.h"
#ifndef wren_h
#define wren_h

#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>

// The Wren semantic version number components.
#define WREN_VERSION_MAJOR 0
#define WREN_VERSION_MINOR 4
#define WREN_VERSION_PATCH 0

// A human-friendly string representation of the version.
#define WREN_VERSION_STRING "0.4.0"

// A monotonically increasing numeric representation of the version number. Use
// this if you want to do range checks over versions.
#define WREN_VERSION_NUMBER (WREN_VERSION_MAJOR * 1000000 +                    \
                             WREN_VERSION_MINOR * 1000 +                       \
                             WREN_VERSION_PATCH)

#ifndef WREN_API
  #if defined(_MSC_VER) && defined(WREN_API_DLLEXPORT)
    #define WREN_API __declspec( dllexport )
  #else
    #define WREN_API
  #endif
#endif //WREN_API

// A single virtual machine for executing Wren code.
//
// Wren has no global state, so all state stored by a running interpreter lives
// here.
typedef struct WrenVM WrenVM;

// A handle to a Wren object.
//
// This lets code outside of the VM hold a persistent reference to an object.
// After a handle is acquired, and until it is released, this ensures the
// garbage collector will not reclaim the object it references.
typedef struct WrenHandle WrenHandle;

// A generic allocation function that handles all explicit memory management
// used by Wren. It's used like so:
//
// - To allocate new memory, [memory] is NULL and [newSize] is the desired
//   size. It should return the allocated memory or NULL on failure.
//
// - To attempt to grow an existing allocation, [memory] is the memory, and
//   [newSize] is the desired size. It should return [memory] if it was able to
//   grow it in place, or a new pointer if it had to move it.
//
// - To shrink memory, [memory] and [newSize] are the same as above but it will
//   always return [memory].
//
// - To free memory, [memory] will be the memory to free and [newSize] will be
//   zero. It should return NULL.
typedef void* (*WrenReallocateFn)(void* memory, size_t newSize, void* userData);

// A function callable from Wren code, but implemented in C.
typedef void (*WrenForeignMethodFn)(WrenVM* vm);

// A finalizer function for freeing resources owned by an instance of a foreign
// class. Unlike most foreign methods, finalizers do not have access to the VM
// and should not interact with it since it's in the middle of a garbage
// collection.
typedef void (*WrenFinalizerFn)(void* data);

// Gives the host a chance to canonicalize the imported module name,
// potentially taking into account the (previously resolved) name of the module
// that contains the import. Typically, this is used to implement relative
// imports.
typedef const char* (*WrenResolveModuleFn)(WrenVM* vm,
    const char* importer, const char* name);

// Forward declare
struct WrenLoadModuleResult;

// Called after loadModuleFn is called for module [name]. The original returned result
// is handed back to you in this callback, so that you can free memory if appropriate.
typedef void (*WrenLoadModuleCompleteFn)(WrenVM* vm, const char* name, struct WrenLoadModuleResult result);

// The result of a loadModuleFn call. 
// [source] is the source code for the module, or NULL if the module is not found.
// [onComplete] an optional callback that will be called once Wren is done with the result.
typedef struct WrenLoadModuleResult
{
  const char* source;
  WrenLoadModuleCompleteFn onComplete;
  void* userData;
} WrenLoadModuleResult;

// Loads and returns the source code for the module [name].
typedef WrenLoadModuleResult (*WrenLoadModuleFn)(WrenVM* vm, const char* name);

// Returns a pointer to a foreign method on [className] in [module] with
// [signature].
typedef WrenForeignMethodFn (*WrenBindForeignMethodFn)(WrenVM* vm,
    const char* module, const char* className, bool isStatic,
    const char* signature);

// Displays a string of text to the user.
typedef void (*WrenWriteFn)(WrenVM* vm, const char* text);

typedef enum
{
  // A syntax or resolution error detected at compile time.
  WREN_ERROR_COMPILE,

  // The error message for a runtime error.
  WREN_ERROR_RUNTIME,

  // One entry of a runtime error's stack trace.
  WREN_ERROR_STACK_TRACE
} WrenErrorType;

// Reports an error to the user.
//
// An error detected during compile time is reported by calling this once with
// [type] `WREN_ERROR_COMPILE`, the resolved name of the [module] and [line]
// where the error occurs, and the compiler's error [message].
//
// A runtime error is reported by calling this once with [type]
// `WREN_ERROR_RUNTIME`, no [module] or [line], and the runtime error's
// [message]. After that, a series of [type] `WREN_ERROR_STACK_TRACE` calls are
// made for each line in the stack trace. Each of those has the resolved
// [module] and [line] where the method or function is defined and [message] is
// the name of the method or function.
typedef void (*WrenErrorFn)(
    WrenVM* vm, WrenErrorType type, const char* module, int line,
    const char* message);

typedef struct
{
  // The callback invoked when the foreign object is created.
  //
  // This must be provided. Inside the body of this, it must call
  // [wrenSetSlotNewForeign()] exactly once.
  WrenForeignMethodFn allocate;

  // The callback invoked when the garbage collector is about to collect a
  // foreign object's memory.
  //
  // This may be `NULL` if the foreign class does not need to finalize.
  WrenFinalizerFn finalize;
} WrenForeignClassMethods;

// Returns a pair of pointers to the foreign methods used to allocate and
// finalize the data for instances of [className] in resolved [module].
typedef WrenForeignClassMethods (*WrenBindForeignClassFn)(
    WrenVM* vm, const char* module, const char* className);

typedef struct
{
  // The callback Wren will use to allocate, reallocate, and deallocate memory.
  //
  // If `NULL`, defaults to a built-in function that uses `realloc` and `free`.
  WrenReallocateFn reallocateFn;

  // The callback Wren uses to resolve a module name.
  //
  // Some host applications may wish to support "relative" imports, where the
  // meaning of an import string depends on the module that contains it. To
  // support that without baking any policy into Wren itself, the VM gives the
  // host a chance to resolve an import string.
  //
  // Before an import is loaded, it calls this, passing in the name of the
  // module that contains the import and the import string. The host app can
  // look at both of those and produce a new "canonical" string that uniquely
  // identifies the module. This string is then used as the name of the module
  // going forward. It is what is passed to [loadModuleFn], how duplicate
  // imports of the same module are detected, and how the module is reported in
  // stack traces.
  //
  // If you leave this function NULL, then the original import string is
  // treated as the resolved string.
  //
  // If an import cannot be resolved by the embedder, it should return NULL and
  // Wren will report that as a runtime error.
  //
  // Wren will take ownership of the string you return and free it for you, so
  // it should be allocated using the same allocation function you provide
  // above.
  WrenResolveModuleFn resolveModuleFn;

  // The callback Wren uses to load a module.
  //
  // Since Wren does not talk directly to the file system, it relies on the
  // embedder to physically locate and read the source code for a module. The
  // first time an import appears, Wren will call this and pass in the name of
  // the module being imported. The method will return a result, which contains
  // the source code for that module. Memory for the source is owned by the 
  // host application, and can be freed using the onComplete callback.
  //
  // This will only be called once for any given module name. Wren caches the
  // result internally so subsequent imports of the same module will use the
  // previous source and not call this.
  //
  // If a module with the given name could not be found by the embedder, it
  // should return NULL and Wren will report that as a runtime error.
  WrenLoadModuleFn loadModuleFn;

  // The callback Wren uses to find a foreign method and bind it to a class.
  //
  // When a foreign method is declared in a class, this will be called with the
  // foreign method's module, class, and signature when the class body is
  // executed. It should return a pointer to the foreign function that will be
  // bound to that method.
  //
  // If the foreign function could not be found, this should return NULL and
  // Wren will report it as runtime error.
  WrenBindForeignMethodFn bindForeignMethodFn;

  // The callback Wren uses to find a foreign class and get its foreign methods.
  //
  // When a foreign class is declared, this will be called with the class's
  // module and name when the class body is executed. It should return the
  // foreign functions uses to allocate and (optionally) finalize the bytes
  // stored in the foreign object when an instance is created.
  WrenBindForeignClassFn bindForeignClassFn;

  // The callback Wren uses to display text when `System.print()` or the other
  // related functions are called.
  //
  // If this is `NULL`, Wren discards any printed text.
  WrenWriteFn writeFn;

  // The callback Wren uses to report errors.
  //
  // When an error occurs, this will be called with the module name, line
  // number, and an error message. If this is `NULL`, Wren doesn't report any
  // errors.
  WrenErrorFn errorFn;

  // The number of bytes Wren will allocate before triggering the first garbage
  // collection.
  //
  // If zero, defaults to 10MB.
  size_t initialHeapSize;

  // After a collection occurs, the threshold for the next collection is
  // determined based on the number of bytes remaining in use. This allows Wren
  // to shrink its memory usage automatically after reclaiming a large amount
  // of memory.
  //
  // This can be used to ensure that the heap does not get too small, which can
  // in turn lead to a large number of collections afterwards as the heap grows
  // back to a usable size.
  //
  // If zero, defaults to 1MB.
  size_t minHeapSize;

  // Wren will resize the heap automatically as the number of bytes
  // remaining in use after a collection changes. This number determines the
  // amount of additional memory Wren will use after a collection, as a
  // percentage of the current heap size.
  //
  // For example, say that this is 50. After a garbage collection, when there
  // are 400 bytes of memory still in use, the next collection will be triggered
  // after a total of 600 bytes are allocated (including the 400 already in
  // use.)
  //
  // Setting this to a smaller number wastes less memory, but triggers more
  // frequent garbage collections.
  //
  // If zero, defaults to 50.
  int heapGrowthPercent;

  // User-defined data associated with the VM.
  void* userData;

} WrenConfiguration;

typedef enum
{
  WREN_RESULT_SUCCESS,
  WREN_RESULT_COMPILE_ERROR,
  WREN_RESULT_RUNTIME_ERROR
} WrenInterpretResult;

// The type of an object stored in a slot.
//
// This is not necessarily the object's *class*, but instead its low level
// representation type.
typedef enum
{
  WREN_TYPE_BOOL,
  WREN_TYPE_NUM,
  WREN_TYPE_FOREIGN,
  WREN_TYPE_LIST,
  WREN_TYPE_MAP,
  WREN_TYPE_NULL,
  WREN_TYPE_STRING,

  // The object is of a type that isn't accessible by the C API.
  WREN_TYPE_UNKNOWN
} WrenType;

// Get the current wren version number.
//
// Can be used to range checks over versions.
WREN_API int wrenGetVersionNumber();

// Initializes [configuration] with all of its default values.
//
// Call this before setting the particular fields you care about.
WREN_API void wrenInitConfiguration(WrenConfiguration* configuration);

// Creates a new Wren virtual machine using the given [configuration]. Wren
// will copy the configuration data, so the argument passed to this can be
// freed after calling this. If [configuration] is `NULL`, uses a default
// configuration.
WREN_API WrenVM* wrenNewVM(WrenConfiguration* configuration);

// Disposes of all resources is use by [vm], which was previously created by a
// call to [wrenNewVM].
WREN_API void wrenFreeVM(WrenVM* vm);

// Immediately run the garbage collector to free unused memory.
WREN_API void wrenCollectGarbage(WrenVM* vm);

// Runs [source], a string of Wren source code in a new fiber in [vm] in the
// context of resolved [module].
WREN_API WrenInterpretResult wrenInterpret(WrenVM* vm, const char* module,
                                  const char* source);

// Creates a handle that can be used to invoke a method with [signature] on
// using a receiver and arguments that are set up on the stack.
//
// This handle can be used repeatedly to directly invoke that method from C
// code using [wrenCall].
//
// When you are done with this handle, it must be released using
// [wrenReleaseHandle].
WREN_API WrenHandle* wrenMakeCallHandle(WrenVM* vm, const char* signature);

// Calls [method], using the receiver and arguments previously set up on the
// stack.
//
// [method] must have been created by a call to [wrenMakeCallHandle]. The
// arguments to the method must be already on the stack. The receiver should be
// in slot 0 with the remaining arguments following it, in order. It is an
// error if the number of arguments provided does not match the method's
// signature.
//
// After this returns, you can access the return value from slot 0 on the stack.
WREN_API WrenInterpretResult wrenCall(WrenVM* vm, WrenHandle* method);

// Releases the reference stored in [handle]. After calling this, [handle] can
// no longer be used.
WREN_API void wrenReleaseHandle(WrenVM* vm, WrenHandle* handle);

// The following functions are intended to be called from foreign methods or
// finalizers. The interface Wren provides to a foreign method is like a
// register machine: you are given a numbered array of slots that values can be
// read from and written to. Values always live in a slot (unless explicitly
// captured using wrenGetSlotHandle(), which ensures the garbage collector can
// find them.
//
// When your foreign function is called, you are given one slot for the receiver
// and each argument to the method. The receiver is in slot 0 and the arguments
// are in increasingly numbered slots after that. You are free to read and
// write to those slots as you want. If you want more slots to use as scratch
// space, you can call wrenEnsureSlots() to add more.
//
// When your function returns, every slot except slot zero is discarded and the
// value in slot zero is used as the return value of the method. If you don't
// store a return value in that slot yourself, it will retain its previous
// value, the receiver.
//
// While Wren is dynamically typed, C is not. This means the C interface has to
// support the various types of primitive values a Wren variable can hold: bool,
// double, string, etc. If we supported this for every operation in the C API,
// there would be a combinatorial explosion of functions, like "get a
// double-valued element from a list", "insert a string key and double value
// into a map", etc.
//
// To avoid that, the only way to convert to and from a raw C value is by going
// into and out of a slot. All other functions work with values already in a
// slot. So, to add an element to a list, you put the list in one slot, and the
// element in another. Then there is a single API function wrenInsertInList()
// that takes the element out of that slot and puts it into the list.
//
// The goal of this API is to be easy to use while not compromising performance.
// The latter means it does not do type or bounds checking at runtime except
// using assertions which are generally removed from release builds. C is an
// unsafe language, so it's up to you to be careful to use it correctly. In
// return, you get a very fast FFI.

// Returns the number of slots available to the current foreign method.
WREN_API int wrenGetSlotCount(WrenVM* vm);

// Ensures that the foreign method stack has at least [numSlots] available for
// use, growing the stack if needed.
//
// Does not shrink the stack if it has more than enough slots.
//
// It is an error to call this from a finalizer.
WREN_API void wrenEnsureSlots(WrenVM* vm, int numSlots);

// Gets the type of the object in [slot].
WREN_API WrenType wrenGetSlotType(WrenVM* vm, int slot);

// Reads a boolean value from [slot].
//
// It is an error to call this if the slot does not contain a boolean value.
WREN_API bool wrenGetSlotBool(WrenVM* vm, int slot);

// Reads a byte array from [slot].
//
// The memory for the returned string is owned by Wren. You can inspect it
// while in your foreign method, but cannot keep a pointer to it after the
// function returns, since the garbage collector may reclaim it.
//
// Returns a pointer to the first byte of the array and fill [length] with the
// number of bytes in the array.
//
// It is an error to call this if the slot does not contain a string.
WREN_API const char* wrenGetSlotBytes(WrenVM* vm, int slot, int* length);

// Reads a number from [slot].
//
// It is an error to call this if the slot does not contain a number.
WREN_API double wrenGetSlotDouble(WrenVM* vm, int slot);

// Reads a foreign object from [slot] and returns a pointer to the foreign data
// stored with it.
//
// It is an error to call this if the slot does not contain an instance of a
// foreign class.
WREN_API void* wrenGetSlotForeign(WrenVM* vm, int slot);

// Reads a string from [slot].
//
// The memory for the returned string is owned by Wren. You can inspect it
// while in your foreign method, but cannot keep a pointer to it after the
// function returns, since the garbage collector may reclaim it.
//
// It is an error to call this if the slot does not contain a string.
WREN_API const char* wrenGetSlotString(WrenVM* vm, int slot);

// Creates a handle for the value stored in [slot].
//
// This will prevent the object that is referred to from being garbage collected
// until the handle is released by calling [wrenReleaseHandle()].
WREN_API WrenHandle* wrenGetSlotHandle(WrenVM* vm, int slot);

// Stores the boolean [value] in [slot].
WREN_API void wrenSetSlotBool(WrenVM* vm, int slot, bool value);

// Stores the array [length] of [bytes] in [slot].
//
// The bytes are copied to a new string within Wren's heap, so you can free
// memory used by them after this is called.
WREN_API void wrenSetSlotBytes(WrenVM* vm, int slot, const char* bytes, size_t length);

// Stores the numeric [value] in [slot].
WREN_API void wrenSetSlotDouble(WrenVM* vm, int slot, double value);

// Creates a new instance of the foreign class stored in [classSlot] with [size]
// bytes of raw storage and places the resulting object in [slot].
//
// This does not invoke the foreign class's constructor on the new instance. If
// you need that to happen, call the constructor from Wren, which will then
// call the allocator foreign method. In there, call this to create the object
// and then the constructor will be invoked when the allocator returns.
//
// Returns a pointer to the foreign object's data.
WREN_API void* wrenSetSlotNewForeign(WrenVM* vm, int slot, int classSlot, size_t size);

// Stores a new empty list in [slot].
WREN_API void wrenSetSlotNewList(WrenVM* vm, int slot);

// Stores a new empty map in [slot].
WREN_API void wrenSetSlotNewMap(WrenVM* vm, int slot);

// Stores null in [slot].
WREN_API void wrenSetSlotNull(WrenVM* vm, int slot);

// Stores the string [text] in [slot].
//
// The [text] is copied to a new string within Wren's heap, so you can free
// memory used by it after this is called. The length is calculated using
// [strlen()]. If the string may contain any null bytes in the middle, then you
// should use [wrenSetSlotBytes()] instead.
WREN_API void wrenSetSlotString(WrenVM* vm, int slot, const char* text);

// Stores the value captured in [handle] in [slot].
//
// This does not release the handle for the value.
WREN_API void wrenSetSlotHandle(WrenVM* vm, int slot, WrenHandle* handle);

// Returns the number of elements in the list stored in [slot].
WREN_API int wrenGetListCount(WrenVM* vm, int slot);

// Reads element [index] from the list in [listSlot] and stores it in
// [elementSlot].
WREN_API void wrenGetListElement(WrenVM* vm, int listSlot, int index, int elementSlot);

// Sets the value stored at [index] in the list at [listSlot], 
// to the value from [elementSlot]. 
WREN_API void wrenSetListElement(WrenVM* vm, int listSlot, int index, int elementSlot);

// Takes the value stored at [elementSlot] and inserts it into the list stored
// at [listSlot] at [index].
//
// As in Wren, negative indexes can be used to insert from the end. To append
// an element, use `-1` for the index.
WREN_API void wrenInsertInList(WrenVM* vm, int listSlot, int index, int elementSlot);

// Returns the number of entries in the map stored in [slot].
WREN_API int wrenGetMapCount(WrenVM* vm, int slot);

// Returns true if the key in [keySlot] is found in the map placed in [mapSlot].
WREN_API bool wrenGetMapContainsKey(WrenVM* vm, int mapSlot, int keySlot);

// Retrieves a value with the key in [keySlot] from the map in [mapSlot] and
// stores it in [valueSlot].
WREN_API void wrenGetMapValue(WrenVM* vm, int mapSlot, int keySlot, int valueSlot);

// Takes the value stored at [valueSlot] and inserts it into the map stored
// at [mapSlot] with key [keySlot].
WREN_API void wrenSetMapValue(WrenVM* vm, int mapSlot, int keySlot, int valueSlot);

// Removes a value from the map in [mapSlot], with the key from [keySlot],
// and place it in [removedValueSlot]. If not found, [removedValueSlot] is
// set to null, the same behaviour as the Wren Map API.
WREN_API void wrenRemoveMapValue(WrenVM* vm, int mapSlot, int keySlot,
                        int removedValueSlot);

// Looks up the top level variable with [name] in resolved [module] and stores
// it in [slot].
WREN_API void wrenGetVariable(WrenVM* vm, const char* module, const char* name,
                     int slot);

// Looks up the top level variable with [name] in resolved [module], 
// returns false if not found. The module must be imported at the time, 
// use wrenHasModule to ensure that before calling.
WREN_API bool wrenHasVariable(WrenVM* vm, const char* module, const char* name);

// Returns true if [module] has been imported/resolved before, false if not.
WREN_API bool wrenHasModule(WrenVM* vm, const char* module);

// Sets the current fiber to be aborted, and uses the value in [slot] as the
// runtime error object.
WREN_API void wrenAbortFiber(WrenVM* vm, int slot);

// Returns the user data associated with the WrenVM.
WREN_API void* wrenGetUserData(WrenVM* vm);

// Sets user data associated with the WrenVM.
WREN_API void wrenSetUserData(WrenVM* vm, void* userData);

#endif
// End file "wren.h"
// Begin file "wren_debug.h"
#ifndef wren_debug_h
#define wren_debug_h

// Begin file "wren_value.h"
#ifndef wren_value_h
#define wren_value_h

#include <stdbool.h>
#include <string.h>

// Begin file "wren_common.h"
#ifndef wren_common_h
#define wren_common_h

// This header contains macros and defines used across the entire Wren
// implementation. In particular, it contains "configuration" defines that
// control how Wren works. Some of these are only used while hacking on Wren
// itself.
//
// This header is *not* intended to be included by code outside of Wren itself.

// Wren pervasively uses the C99 integer types (uint16_t, etc.) along with some
// of the associated limit constants (UINT32_MAX, etc.). The constants are not
// part of standard C++, so aren't included by default by C++ compilers when you
// include <stdint> unless __STDC_LIMIT_MACROS is defined.
#define __STDC_LIMIT_MACROS
#include <stdint.h>

// These flags let you control some details of the interpreter's implementation.
// Usually they trade-off a bit of portability for speed. They default to the
// most efficient behavior.

// If true, then Wren uses a NaN-tagged double for its core value
// representation. Otherwise, it uses a larger more conventional struct. The
// former is significantly faster and more compact. The latter is useful for
// debugging and may be more portable.
//
// Defaults to on.
#ifndef WREN_NAN_TAGGING
  #define WREN_NAN_TAGGING 1
#endif

// If true, the VM's interpreter loop uses computed gotos. See this for more:
// http://gcc.gnu.org/onlinedocs/gcc-3.1.1/gcc/Labels-as-Values.html
// Enabling this speeds up the main dispatch loop a bit, but requires compiler
// support.
// see https://bullno1.com/blog/switched-goto for alternative
// Defaults to true on supported compilers.
#ifndef WREN_COMPUTED_GOTO
  #if defined(_MSC_VER) && !defined(__clang__)
    // No computed gotos in Visual Studio.
    #define WREN_COMPUTED_GOTO 0
  #else
    #define WREN_COMPUTED_GOTO 1
  #endif
#endif

// The VM includes a number of optional modules. You can choose to include
// these or not. By default, they are all available. To disable one, set the
// corresponding `WREN_OPT_<name>` define to `0`.
#ifndef WREN_OPT_META
  #define WREN_OPT_META 1
#endif

#ifndef WREN_OPT_RANDOM
  #define WREN_OPT_RANDOM 1
#endif

// These flags are useful for debugging and hacking on Wren itself. They are not
// intended to be used for production code. They default to off.

// Set this to true to stress test the GC. It will perform a collection before
// every allocation. This is useful to ensure that memory is always correctly
// reachable.
#define WREN_DEBUG_GC_STRESS 0

// Set this to true to log memory operations as they occur.
#define WREN_DEBUG_TRACE_MEMORY 0

// Set this to true to log garbage collections as they occur.
#define WREN_DEBUG_TRACE_GC 0

// Set this to true to print out the compiled bytecode of each function.
#define WREN_DEBUG_DUMP_COMPILED_CODE 0

// Set this to trace each instruction as it's executed.
#define WREN_DEBUG_TRACE_INSTRUCTIONS 0

// The maximum number of module-level variables that may be defined at one time.
// This limitation comes from the 16 bits used for the arguments to
// `CODE_LOAD_MODULE_VAR` and `CODE_STORE_MODULE_VAR`.
#define MAX_MODULE_VARS 65536

// The maximum number of arguments that can be passed to a method. Note that
// this limitation is hardcoded in other places in the VM, in particular, the
// `CODE_CALL_XX` instructions assume a certain maximum number.
#define MAX_PARAMETERS 16

// The maximum name of a method, not including the signature. This is an
// arbitrary but enforced maximum just so we know how long the method name
// strings need to be in the parser.
#define MAX_METHOD_NAME 64

// The maximum length of a method signature. Signatures look like:
//
//     foo        // Getter.
//     foo()      // No-argument method.
//     foo(_)     // One-argument method.
//     foo(_,_)   // Two-argument method.
//     init foo() // Constructor initializer.
//
// The maximum signature length takes into account the longest method name, the
// maximum number of parameters with separators between them, "init ", and "()".
#define MAX_METHOD_SIGNATURE (MAX_METHOD_NAME + (MAX_PARAMETERS * 2) + 6)

// The maximum length of an identifier. The only real reason for this limitation
// is so that error messages mentioning variables can be stack allocated.
#define MAX_VARIABLE_NAME 64

// The maximum number of fields a class can have, including inherited fields.
// This is explicit in the bytecode since `CODE_CLASS` and `CODE_SUBCLASS` take
// a single byte for the number of fields. Note that it's 255 and not 256
// because creating a class takes the *number* of fields, not the *highest
// field index*.
#define MAX_FIELDS 255

// Use the VM's allocator to allocate an object of [type].
#define ALLOCATE(vm, type)                                                     \
    ((type*)wrenReallocate(vm, NULL, 0, sizeof(type)))

// Use the VM's allocator to allocate an object of [mainType] containing a
// flexible array of [count] objects of [arrayType].
#define ALLOCATE_FLEX(vm, mainType, arrayType, count)                          \
    ((mainType*)wrenReallocate(vm, NULL, 0,                                    \
        sizeof(mainType) + sizeof(arrayType) * (count)))

// Use the VM's allocator to allocate an array of [count] elements of [type].
#define ALLOCATE_ARRAY(vm, type, count)                                        \
    ((type*)wrenReallocate(vm, NULL, 0, sizeof(type) * (count)))

// Use the VM's allocator to free the previously allocated memory at [pointer].
#define DEALLOCATE(vm, pointer) wrenReallocate(vm, pointer, 0, 0)

// The Microsoft compiler does not support the "inline" modifier when compiling
// as plain C.
#if defined( _MSC_VER ) && !defined(__cplusplus)
  #define inline _inline
#endif

// This is used to clearly mark flexible-sized arrays that appear at the end of
// some dynamically-allocated structs, known as the "struct hack".
#if __STDC_VERSION__ >= 199901L
  // In C99, a flexible array member is just "[]".
  #define FLEXIBLE_ARRAY
#else
  // Elsewhere, use a zero-sized array. It's technically undefined behavior,
  // but works reliably in most known compilers.
  #define FLEXIBLE_ARRAY 0
#endif

// Assertions are used to validate program invariants. They indicate things the
// program expects to be true about its internal state during execution. If an
// assertion fails, there is a bug in Wren.
//
// Assertions add significant overhead, so are only enabled in debug builds.
#ifdef DEBUG

  #include <stdio.h>

  #define ASSERT(condition, message)                                           \
      do                                                                       \
      {                                                                        \
        if (!(condition))                                                      \
        {                                                                      \
          fprintf(stderr, "[%s:%d] Assert failed in %s(): %s\n",               \
              __FILE__, __LINE__, __func__, message);                          \
          abort();                                                             \
        }                                                                      \
      } while (false)

  // Indicates that we know execution should never reach this point in the
  // program. In debug mode, we assert this fact because it's a bug to get here.
  //
  // In release mode, we use compiler-specific built in functions to tell the
  // compiler the code can't be reached. This avoids "missing return" warnings
  // in some cases and also lets it perform some optimizations by assuming the
  // code is never reached.
  #define UNREACHABLE()                                                        \
      do                                                                       \
      {                                                                        \
        fprintf(stderr, "[%s:%d] This code should not be reached in %s()\n",   \
            __FILE__, __LINE__, __func__);                                     \
        abort();                                                               \
      } while (false)

#else

  #define ASSERT(condition, message) do { } while (false)

  // Tell the compiler that this part of the code will never be reached.
  #if defined( _MSC_VER )
    #define UNREACHABLE() __assume(0)
  #elif (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5))
    #define UNREACHABLE() __builtin_unreachable()
  #else
    #define UNREACHABLE()
  #endif

#endif

#endif
// End file "wren_common.h"
// Begin file "wren_math.h"
#ifndef wren_math_h
#define wren_math_h

#include <math.h>
#include <stdint.h>

// A union to let us reinterpret a double as raw bits and back.
typedef union
{
  uint64_t bits64;
  uint32_t bits32[2];
  double num;
} WrenDoubleBits;

#define WREN_DOUBLE_QNAN_POS_MIN_BITS (UINT64_C(0x7FF8000000000000))
#define WREN_DOUBLE_QNAN_POS_MAX_BITS (UINT64_C(0x7FFFFFFFFFFFFFFF))

#define WREN_DOUBLE_NAN (wrenDoubleFromBits(WREN_DOUBLE_QNAN_POS_MIN_BITS))

static inline double wrenDoubleFromBits(uint64_t bits)
{
  WrenDoubleBits data;
  data.bits64 = bits;
  return data.num;
}

static inline uint64_t wrenDoubleToBits(double num)
{
  WrenDoubleBits data;
  data.num = num;
  return data.bits64;
}

#endif
// End file "wren_math.h"
// Begin file "wren_utils.h"
#ifndef wren_utils_h
#define wren_utils_h


// Reusable data structures and other utility functions.

// Forward declare this here to break a cycle between wren_utils.h and
// wren_value.h.
typedef struct sObjString ObjString;

// We need buffers of a few different types. To avoid lots of casting between
// void* and back, we'll use the preprocessor as a poor man's generics and let
// it generate a few type-specific ones.
#define DECLARE_BUFFER(name, type)                                             \
    typedef struct                                                             \
    {                                                                          \
      type* data;                                                              \
      int count;                                                               \
      int capacity;                                                            \
    } name##Buffer;                                                            \
    void wren##name##BufferInit(name##Buffer* buffer);                         \
    void wren##name##BufferClear(WrenVM* vm, name##Buffer* buffer);            \
    void wren##name##BufferFill(WrenVM* vm, name##Buffer* buffer, type data,   \
                                int count);                                    \
    void wren##name##BufferWrite(WrenVM* vm, name##Buffer* buffer, type data)

// This should be used once for each type instantiation, somewhere in a .c file.
#define DEFINE_BUFFER(name, type)                                              \
    void wren##name##BufferInit(name##Buffer* buffer)                          \
    {                                                                          \
      buffer->data = NULL;                                                     \
      buffer->capacity = 0;                                                    \
      buffer->count = 0;                                                       \
    }                                                                          \
                                                                               \
    void wren##name##BufferClear(WrenVM* vm, name##Buffer* buffer)             \
    {                                                                          \
      wrenReallocate(vm, buffer->data, 0, 0);                                  \
      wren##name##BufferInit(buffer);                                          \
    }                                                                          \
                                                                               \
    void wren##name##BufferFill(WrenVM* vm, name##Buffer* buffer, type data,   \
                                int count)                                     \
    {                                                                          \
      if (buffer->capacity < buffer->count + count)                            \
      {                                                                        \
        int capacity = wrenPowerOf2Ceil(buffer->count + count);                \
        buffer->data = (type*)wrenReallocate(vm, buffer->data,                 \
            buffer->capacity * sizeof(type), capacity * sizeof(type));         \
        buffer->capacity = capacity;                                           \
      }                                                                        \
                                                                               \
      for (int i = 0; i < count; i++)                                          \
      {                                                                        \
        buffer->data[buffer->count++] = data;                                  \
      }                                                                        \
    }                                                                          \
                                                                               \
    void wren##name##BufferWrite(WrenVM* vm, name##Buffer* buffer, type data)  \
    {                                                                          \
      wren##name##BufferFill(vm, buffer, data, 1);                             \
    }

DECLARE_BUFFER(Byte, uint8_t);
DECLARE_BUFFER(Int, int);
DECLARE_BUFFER(String, ObjString*);

// TODO: Change this to use a map.
typedef StringBuffer SymbolTable;

// Initializes the symbol table.
void wrenSymbolTableInit(SymbolTable* symbols);

// Frees all dynamically allocated memory used by the symbol table, but not the
// SymbolTable itself.
void wrenSymbolTableClear(WrenVM* vm, SymbolTable* symbols);

// Adds name to the symbol table. Returns the index of it in the table.
int wrenSymbolTableAdd(WrenVM* vm, SymbolTable* symbols,
                       const char* name, size_t length);

// Adds name to the symbol table. Returns the index of it in the table. Will
// use an existing symbol if already present.
int wrenSymbolTableEnsure(WrenVM* vm, SymbolTable* symbols,
                          const char* name, size_t length);

// Looks up name in the symbol table. Returns its index if found or -1 if not.
int wrenSymbolTableFind(const SymbolTable* symbols,
                        const char* name, size_t length);

void wrenBlackenSymbolTable(WrenVM* vm, SymbolTable* symbolTable);

// Returns the number of bytes needed to encode [value] in UTF-8.
//
// Returns 0 if [value] is too large to encode.
int wrenUtf8EncodeNumBytes(int value);

// Encodes value as a series of bytes in [bytes], which is assumed to be large
// enough to hold the encoded result.
//
// Returns the number of written bytes.
int wrenUtf8Encode(int value, uint8_t* bytes);

// Decodes the UTF-8 sequence starting at [bytes] (which has max [length]),
// returning the code point.
//
// Returns -1 if the bytes are not a valid UTF-8 sequence.
int wrenUtf8Decode(const uint8_t* bytes, uint32_t length);

// Returns the number of bytes in the UTF-8 sequence starting with [byte].
//
// If the character at that index is not the beginning of a UTF-8 sequence,
// returns 0.
int wrenUtf8DecodeNumBytes(uint8_t byte);

// Returns the smallest power of two that is equal to or greater than [n].
int wrenPowerOf2Ceil(int n);

// Validates that [value] is within `[0, count)`. Also allows
// negative indices which map backwards from the end. Returns the valid positive
// index value. If invalid, returns `UINT32_MAX`.
uint32_t wrenValidateIndex(uint32_t count, int64_t value);

#endif
// End file "wren_utils.h"

// This defines the built-in types and their core representations in memory.
// Since Wren is dynamically typed, any variable can hold a value of any type,
// and the type can change at runtime. Implementing this efficiently is
// critical for performance.
//
// The main type exposed by this is [Value]. A C variable of that type is a
// storage location that can hold any Wren value. The stack, module variables,
// and instance fields are all implemented in C as variables of type Value.
//
// The built-in types for booleans, numbers, and null are unboxed: their value
// is stored directly in the Value, and copying a Value copies the value. Other
// types--classes, instances of classes, functions, lists, and strings--are all
// reference types. They are stored on the heap and the Value just stores a
// pointer to it. Copying the Value copies a reference to the same object. The
// Wren implementation calls these "Obj", or objects, though to a user, all
// values are objects.
//
// There is also a special singleton value "undefined". It is used internally
// but never appears as a real value to a user. It has two uses:
//
// - It is used to identify module variables that have been implicitly declared
//   by use in a forward reference but not yet explicitly declared. These only
//   exist during compilation and do not appear at runtime.
//
// - It is used to represent unused map entries in an ObjMap.
//
// There are two supported Value representations. The main one uses a technique
// called "NaN tagging" (explained in detail below) to store a number, any of
// the value types, or a pointer, all inside one double-precision floating
// point number. A larger, slower, Value type that uses a struct to store these
// is also supported, and is useful for debugging the VM.
//
// The representation is controlled by the `WREN_NAN_TAGGING` define. If that's
// defined, Nan tagging is used.

// These macros cast a Value to one of the specific object types. These do *not*
// perform any validation, so must only be used after the Value has been
// ensured to be the right type.
#define AS_CLASS(value)     ((ObjClass*)AS_OBJ(value))          // ObjClass*
#define AS_CLOSURE(value)   ((ObjClosure*)AS_OBJ(value))        // ObjClosure*
#define AS_FIBER(v)         ((ObjFiber*)AS_OBJ(v))              // ObjFiber*
#define AS_FN(value)        ((ObjFn*)AS_OBJ(value))             // ObjFn*
#define AS_FOREIGN(v)       ((ObjForeign*)AS_OBJ(v))            // ObjForeign*
#define AS_INSTANCE(value)  ((ObjInstance*)AS_OBJ(value))       // ObjInstance*
#define AS_LIST(value)      ((ObjList*)AS_OBJ(value))           // ObjList*
#define AS_MAP(value)       ((ObjMap*)AS_OBJ(value))            // ObjMap*
#define AS_MODULE(value)    ((ObjModule*)AS_OBJ(value))         // ObjModule*
#define AS_NUM(value)       (wrenValueToNum(value))             // double
#define AS_RANGE(v)         ((ObjRange*)AS_OBJ(v))              // ObjRange*
#define AS_STRING(v)        ((ObjString*)AS_OBJ(v))             // ObjString*
#define AS_CSTRING(v)       (AS_STRING(v)->value)               // const char*

// These macros promote a primitive C value to a full Wren Value. There are
// more defined below that are specific to the Nan tagged or other
// representation.
#define BOOL_VAL(boolean) ((boolean) ? TRUE_VAL : FALSE_VAL)    // boolean
#define NUM_VAL(num) (wrenNumToValue(num))                      // double
#define OBJ_VAL(obj) (wrenObjectToValue((Obj*)(obj)))           // Any Obj___*

// These perform type tests on a Value, returning `true` if the Value is of the
// given type.
#define IS_BOOL(value) (wrenIsBool(value))                      // Bool
#define IS_CLASS(value) (wrenIsObjType(value, OBJ_CLASS))       // ObjClass
#define IS_CLOSURE(value) (wrenIsObjType(value, OBJ_CLOSURE))   // ObjClosure
#define IS_FIBER(value) (wrenIsObjType(value, OBJ_FIBER))       // ObjFiber
#define IS_FN(value) (wrenIsObjType(value, OBJ_FN))             // ObjFn
#define IS_FOREIGN(value) (wrenIsObjType(value, OBJ_FOREIGN))   // ObjForeign
#define IS_INSTANCE(value) (wrenIsObjType(value, OBJ_INSTANCE)) // ObjInstance
#define IS_LIST(value) (wrenIsObjType(value, OBJ_LIST))         // ObjList
#define IS_MAP(value) (wrenIsObjType(value, OBJ_MAP))           // ObjMap
#define IS_RANGE(value) (wrenIsObjType(value, OBJ_RANGE))       // ObjRange
#define IS_STRING(value) (wrenIsObjType(value, OBJ_STRING))     // ObjString

// Creates a new string object from [text], which should be a bare C string
// literal. This determines the length of the string automatically at compile
// time based on the size of the character array (-1 for the terminating '\0').
#define CONST_STRING(vm, text) wrenNewStringLength((vm), (text), sizeof(text) - 1)

// Identifies which specific type a heap-allocated object is.
typedef enum {
  OBJ_CLASS,
  OBJ_CLOSURE,
  OBJ_FIBER,
  OBJ_FN,
  OBJ_FOREIGN,
  OBJ_INSTANCE,
  OBJ_LIST,
  OBJ_MAP,
  OBJ_MODULE,
  OBJ_RANGE,
  OBJ_STRING,
  OBJ_UPVALUE
} ObjType;

typedef struct sObjClass ObjClass;

// Base struct for all heap-allocated objects.
typedef struct sObj Obj;
struct sObj
{
  ObjType type;
  bool isDark;

  // The object's class.
  ObjClass* classObj;

  // The next object in the linked list of all currently allocated objects.
  struct sObj* next;
};

#if WREN_NAN_TAGGING

typedef uint64_t Value;

#else

typedef enum
{
  VAL_FALSE,
  VAL_NULL,
  VAL_NUM,
  VAL_TRUE,
  VAL_UNDEFINED,
  VAL_OBJ
} ValueType;

typedef struct
{
  ValueType type;
  union
  {
    double num;
    Obj* obj;
  } as;
} Value;

#endif

DECLARE_BUFFER(Value, Value);

// A heap-allocated string object.
struct sObjString
{
  Obj obj;

  // Number of bytes in the string, not including the null terminator.
  uint32_t length;

  // The hash value of the string's contents.
  uint32_t hash;

  // Inline array of the string's bytes followed by a null terminator.
  char value[FLEXIBLE_ARRAY];
};

// The dynamically allocated data structure for a variable that has been used
// by a closure. Whenever a function accesses a variable declared in an
// enclosing function, it will get to it through this.
//
// An upvalue can be either "closed" or "open". An open upvalue points directly
// to a [Value] that is still stored on the fiber's stack because the local
// variable is still in scope in the function where it's declared.
//
// When that local variable goes out of scope, the upvalue pointing to it will
// be closed. When that happens, the value gets copied off the stack into the
// upvalue itself. That way, it can have a longer lifetime than the stack
// variable.
typedef struct sObjUpvalue
{
  // The object header. Note that upvalues have this because they are garbage
  // collected, but they are not first class Wren objects.
  Obj obj;

  // Pointer to the variable this upvalue is referencing.
  Value* value;

  // If the upvalue is closed (i.e. the local variable it was pointing to has
  // been popped off the stack) then the closed-over value will be hoisted out
  // of the stack into here. [value] will then be changed to point to this.
  Value closed;

  // Open upvalues are stored in a linked list by the fiber. This points to the
  // next upvalue in that list.
  struct sObjUpvalue* next;
} ObjUpvalue;

// The type of a primitive function.
//
// Primitives are similar to foreign functions, but have more direct access to
// VM internals. It is passed the arguments in [args]. If it returns a value,
// it places it in `args[0]` and returns `true`. If it causes a runtime error
// or modifies the running fiber, it returns `false`.
typedef bool (*Primitive)(WrenVM* vm, Value* args);

// TODO: See if it's actually a perf improvement to have this in a separate
// struct instead of in ObjFn.
// Stores debugging information for a function used for things like stack
// traces.
typedef struct
{
  // The name of the function. Heap allocated and owned by the FnDebug.
  char* name;

  // An array of line numbers. There is one element in this array for each
  // bytecode in the function's bytecode array. The value of that element is
  // the line in the source code that generated that instruction.
  IntBuffer sourceLines;
} FnDebug;

// A loaded module and the top-level variables it defines.
//
// While this is an Obj and is managed by the GC, it never appears as a
// first-class object in Wren.
typedef struct
{
  Obj obj;

  // The currently defined top-level variables.
  ValueBuffer variables;

  // Symbol table for the names of all module variables. Indexes here directly
  // correspond to entries in [variables].
  SymbolTable variableNames;

  // The name of the module.
  ObjString* name;
} ObjModule;

// A function object. It wraps and owns the bytecode and other debug information
// for a callable chunk of code.
//
// Function objects are not passed around and invoked directly. Instead, they
// are always referenced by an [ObjClosure] which is the real first-class
// representation of a function. This isn't strictly necessary if they function
// has no upvalues, but lets the rest of the VM assume all called objects will
// be closures.
typedef struct
{
  Obj obj;
  
  ByteBuffer code;
  ValueBuffer constants;
  
  // The module where this function was defined.
  ObjModule* module;

  // The maximum number of stack slots this function may use.
  int maxSlots;
  
  // The number of upvalues this function closes over.
  int numUpvalues;
  
  // The number of parameters this function expects. Used to ensure that .call
  // handles a mismatch between number of parameters and arguments. This will
  // only be set for fns, and not ObjFns that represent methods or scripts.
  int arity;
  FnDebug* debug;
} ObjFn;

// An instance of a first-class function and the environment it has closed over.
// Unlike [ObjFn], this has captured the upvalues that the function accesses.
typedef struct
{
  Obj obj;

  // The function that this closure is an instance of.
  ObjFn* fn;

  // The upvalues this function has closed over.
  ObjUpvalue* upvalues[FLEXIBLE_ARRAY];
} ObjClosure;

typedef struct
{
  // Pointer to the current (really next-to-be-executed) instruction in the
  // function's bytecode.
  uint8_t* ip;
  
  // The closure being executed.
  ObjClosure* closure;
  
  // Pointer to the first stack slot used by this call frame. This will contain
  // the receiver, followed by the function's parameters, then local variables
  // and temporaries.
  Value* stackStart;
} CallFrame;

// Tracks how this fiber has been invoked, aside from the ways that can be
// detected from the state of other fields in the fiber.
typedef enum
{
  // The fiber is being run from another fiber using a call to `try()`.
  FIBER_TRY,
  
  // The fiber was directly invoked by `runInterpreter()`. This means it's the
  // initial fiber used by a call to `wrenCall()` or `wrenInterpret()`.
  FIBER_ROOT,
  
  // The fiber is invoked some other way. If [caller] is `NULL` then the fiber
  // was invoked using `call()`. If [numFrames] is zero, then the fiber has
  // finished running and is done. If [numFrames] is one and that frame's `ip`
  // points to the first byte of code, the fiber has not been started yet.
  FIBER_OTHER,
} FiberState;

typedef struct sObjFiber
{
  Obj obj;
  
  // The stack of value slots. This is used for holding local variables and
  // temporaries while the fiber is executing. It is heap-allocated and grown
  // as needed.
  Value* stack;
  
  // A pointer to one past the top-most value on the stack.
  Value* stackTop;
  
  // The number of allocated slots in the stack array.
  int stackCapacity;
  
  // The stack of call frames. This is a dynamic array that grows as needed but
  // never shrinks.
  CallFrame* frames;
  
  // The number of frames currently in use in [frames].
  int numFrames;
  
  // The number of [frames] allocated.
  int frameCapacity;
  
  // Pointer to the first node in the linked list of open upvalues that are
  // pointing to values still on the stack. The head of the list will be the
  // upvalue closest to the top of the stack, and then the list works downwards.
  ObjUpvalue* openUpvalues;
  
  // The fiber that ran this one. If this fiber is yielded, control will resume
  // to this one. May be `NULL`.
  struct sObjFiber* caller;
  
  // If the fiber failed because of a runtime error, this will contain the
  // error object. Otherwise, it will be null.
  Value error;
  
  FiberState state;
} ObjFiber;

typedef enum
{
  // A primitive method implemented in C in the VM. Unlike foreign methods,
  // this can directly manipulate the fiber's stack.
  METHOD_PRIMITIVE,

  // A primitive that handles .call on Fn.
  METHOD_FUNCTION_CALL,

  // A externally-defined C method.
  METHOD_FOREIGN,

  // A normal user-defined method.
  METHOD_BLOCK,
  
  // No method for the given symbol.
  METHOD_NONE
} MethodType;

typedef struct
{
  MethodType type;

  // The method function itself. The [type] determines which field of the union
  // is used.
  union
  {
    Primitive primitive;
    WrenForeignMethodFn foreign;
    ObjClosure* closure;
  } as;
} Method;

DECLARE_BUFFER(Method, Method);

struct sObjClass
{
  Obj obj;
  ObjClass* superclass;

  // The number of fields needed for an instance of this class, including all
  // of its superclass fields.
  int numFields;

  // The table of methods that are defined in or inherited by this class.
  // Methods are called by symbol, and the symbol directly maps to an index in
  // this table. This makes method calls fast at the expense of empty cells in
  // the list for methods the class doesn't support.
  //
  // You can think of it as a hash table that never has collisions but has a
  // really low load factor. Since methods are pretty small (just a type and a
  // pointer), this should be a worthwhile trade-off.
  MethodBuffer methods;

  // The name of the class.
  ObjString* name;
  
  // The ClassAttribute for the class, if any
  Value attributes;
};

typedef struct
{
  Obj obj;
  uint8_t data[FLEXIBLE_ARRAY];
} ObjForeign;

typedef struct
{
  Obj obj;
  Value fields[FLEXIBLE_ARRAY];
} ObjInstance;

typedef struct
{
  Obj obj;

  // The elements in the list.
  ValueBuffer elements;
} ObjList;

typedef struct
{
  // The entry's key, or UNDEFINED_VAL if the entry is not in use.
  Value key;

  // The value associated with the key. If the key is UNDEFINED_VAL, this will
  // be false to indicate an open available entry or true to indicate a
  // tombstone -- an entry that was previously in use but was then deleted.
  Value value;
} MapEntry;

// A hash table mapping keys to values.
//
// We use something very simple: open addressing with linear probing. The hash
// table is an array of entries. Each entry is a key-value pair. If the key is
// the special UNDEFINED_VAL, it indicates no value is currently in that slot.
// Otherwise, it's a valid key, and the value is the value associated with it.
//
// When entries are added, the array is dynamically scaled by GROW_FACTOR to
// keep the number of filled slots under MAP_LOAD_PERCENT. Likewise, if the map
// gets empty enough, it will be resized to a smaller array. When this happens,
// all existing entries are rehashed and re-added to the new array.
//
// When an entry is removed, its slot is replaced with a "tombstone". This is an
// entry whose key is UNDEFINED_VAL and whose value is TRUE_VAL. When probing
// for a key, we will continue past tombstones, because the desired key may be
// found after them if the key that was removed was part of a prior collision.
// When the array gets resized, all tombstones are discarded.
typedef struct
{
  Obj obj;

  // The number of entries allocated.
  uint32_t capacity;

  // The number of entries in the map.
  uint32_t count;

  // Pointer to a contiguous array of [capacity] entries.
  MapEntry* entries;
} ObjMap;

typedef struct
{
  Obj obj;

  // The beginning of the range.
  double from;

  // The end of the range. May be greater or less than [from].
  double to;

  // True if [to] is included in the range.
  bool isInclusive;
} ObjRange;

// An IEEE 754 double-precision float is a 64-bit value with bits laid out like:
//
// 1 Sign bit
// | 11 Exponent bits
// | |          52 Mantissa (i.e. fraction) bits
// | |          |
// S[Exponent-][Mantissa------------------------------------------]
//
// The details of how these are used to represent numbers aren't really
// relevant here as long we don't interfere with them. The important bit is NaN.
//
// An IEEE double can represent a few magical values like NaN ("not a number"),
// Infinity, and -Infinity. A NaN is any value where all exponent bits are set:
//
//  v--NaN bits
// -11111111111----------------------------------------------------
//
// Here, "-" means "doesn't matter". Any bit sequence that matches the above is
// a NaN. With all of those "-", it obvious there are a *lot* of different
// bit patterns that all mean the same thing. NaN tagging takes advantage of
// this. We'll use those available bit patterns to represent things other than
// numbers without giving up any valid numeric values.
//
// NaN values come in two flavors: "signalling" and "quiet". The former are
// intended to halt execution, while the latter just flow through arithmetic
// operations silently. We want the latter. Quiet NaNs are indicated by setting
// the highest mantissa bit:
//
//             v--Highest mantissa bit
// -[NaN      ]1---------------------------------------------------
//
// If all of the NaN bits are set, it's not a number. Otherwise, it is.
// That leaves all of the remaining bits as available for us to play with. We
// stuff a few different kinds of things here: special singleton values like
// "true", "false", and "null", and pointers to objects allocated on the heap.
// We'll use the sign bit to distinguish singleton values from pointers. If
// it's set, it's a pointer.
//
// v--Pointer or singleton?
// S[NaN      ]1---------------------------------------------------
//
// For singleton values, we just enumerate the different values. We'll use the
// low bits of the mantissa for that, and only need a few:
//
//                                                 3 Type bits--v
// 0[NaN      ]1------------------------------------------------[T]
//
// For pointers, we are left with 51 bits of mantissa to store an address.
// That's more than enough room for a 32-bit address. Even 64-bit machines
// only actually use 48 bits for addresses, so we've got plenty. We just stuff
// the address right into the mantissa.
//
// Ta-da, double precision numbers, pointers, and a bunch of singleton values,
// all stuffed into a single 64-bit sequence. Even better, we don't have to
// do any masking or work to extract number values: they are unmodified. This
// means math on numbers is fast.
#if WREN_NAN_TAGGING

// A mask that selects the sign bit.
#define SIGN_BIT ((uint64_t)1 << 63)

// The bits that must be set to indicate a quiet NaN.
#define QNAN ((uint64_t)0x7ffc000000000000)

// If the NaN bits are set, it's not a number.
#define IS_NUM(value) (((value) & QNAN) != QNAN)

// An object pointer is a NaN with a set sign bit.
#define IS_OBJ(value) (((value) & (QNAN | SIGN_BIT)) == (QNAN | SIGN_BIT))

#define IS_FALSE(value)     ((value) == FALSE_VAL)
#define IS_NULL(value)      ((value) == NULL_VAL)
#define IS_UNDEFINED(value) ((value) == UNDEFINED_VAL)

// Masks out the tag bits used to identify the singleton value.
#define MASK_TAG (7)

// Tag values for the different singleton values.
#define TAG_NAN       (0)
#define TAG_NULL      (1)
#define TAG_FALSE     (2)
#define TAG_TRUE      (3)
#define TAG_UNDEFINED (4)
#define TAG_UNUSED2   (5)
#define TAG_UNUSED3   (6)
#define TAG_UNUSED4   (7)

// Value -> 0 or 1.
#define AS_BOOL(value) ((value) == TRUE_VAL)

// Value -> Obj*.
#define AS_OBJ(value) ((Obj*)(uintptr_t)((value) & ~(SIGN_BIT | QNAN)))

// Singleton values.
#define NULL_VAL      ((Value)(uint64_t)(QNAN | TAG_NULL))
#define FALSE_VAL     ((Value)(uint64_t)(QNAN | TAG_FALSE))
#define TRUE_VAL      ((Value)(uint64_t)(QNAN | TAG_TRUE))
#define UNDEFINED_VAL ((Value)(uint64_t)(QNAN | TAG_UNDEFINED))

// Gets the singleton type tag for a Value (which must be a singleton).
#define GET_TAG(value) ((int)((value) & MASK_TAG))

#else

// Value -> 0 or 1.
#define AS_BOOL(value) ((value).type == VAL_TRUE)

// Value -> Obj*.
#define AS_OBJ(v) ((v).as.obj)

// Determines if [value] is a garbage-collected object or not.
#define IS_OBJ(value) ((value).type == VAL_OBJ)

#define IS_FALSE(value)     ((value).type == VAL_FALSE)
#define IS_NULL(value)      ((value).type == VAL_NULL)
#define IS_NUM(value)       ((value).type == VAL_NUM)
#define IS_UNDEFINED(value) ((value).type == VAL_UNDEFINED)

// Singleton values.
#define FALSE_VAL     ((Value){ VAL_FALSE, { 0 } })
#define NULL_VAL      ((Value){ VAL_NULL, { 0 } })
#define TRUE_VAL      ((Value){ VAL_TRUE, { 0 } })
#define UNDEFINED_VAL ((Value){ VAL_UNDEFINED, { 0 } })

#endif

// Creates a new "raw" class. It has no metaclass or superclass whatsoever.
// This is only used for bootstrapping the initial Object and Class classes,
// which are a little special.
ObjClass* wrenNewSingleClass(WrenVM* vm, int numFields, ObjString* name);

// Makes [superclass] the superclass of [subclass], and causes subclass to
// inherit its methods. This should be called before any methods are defined
// on subclass.
void wrenBindSuperclass(WrenVM* vm, ObjClass* subclass, ObjClass* superclass);

// Creates a new class object as well as its associated metaclass.
ObjClass* wrenNewClass(WrenVM* vm, ObjClass* superclass, int numFields,
                       ObjString* name);

void wrenBindMethod(WrenVM* vm, ObjClass* classObj, int symbol, Method method);

// Creates a new closure object that invokes [fn]. Allocates room for its
// upvalues, but assumes outside code will populate it.
ObjClosure* wrenNewClosure(WrenVM* vm, ObjFn* fn);

// Creates a new fiber object that will invoke [closure].
ObjFiber* wrenNewFiber(WrenVM* vm, ObjClosure* closure);

// Adds a new [CallFrame] to [fiber] invoking [closure] whose stack starts at
// [stackStart].
static inline void wrenAppendCallFrame(WrenVM* vm, ObjFiber* fiber,
                                       ObjClosure* closure, Value* stackStart)
{
  // The caller should have ensured we already have enough capacity.
  ASSERT(fiber->frameCapacity > fiber->numFrames, "No memory for call frame.");
  
  CallFrame* frame = &fiber->frames[fiber->numFrames++];
  frame->stackStart = stackStart;
  frame->closure = closure;
  frame->ip = closure->fn->code.data;
}

// Ensures [fiber]'s stack has at least [needed] slots.
void wrenEnsureStack(WrenVM* vm, ObjFiber* fiber, int needed);

static inline bool wrenHasError(const ObjFiber* fiber)
{
  return !IS_NULL(fiber->error);
}

ObjForeign* wrenNewForeign(WrenVM* vm, ObjClass* classObj, size_t size);

// Creates a new empty function. Before being used, it must have code,
// constants, etc. added to it.
ObjFn* wrenNewFunction(WrenVM* vm, ObjModule* module, int maxSlots);

void wrenFunctionBindName(WrenVM* vm, ObjFn* fn, const char* name, int length);

// Creates a new instance of the given [classObj].
Value wrenNewInstance(WrenVM* vm, ObjClass* classObj);

// Creates a new list with [numElements] elements (which are left
// uninitialized.)
ObjList* wrenNewList(WrenVM* vm, uint32_t numElements);

// Inserts [value] in [list] at [index], shifting down the other elements.
void wrenListInsert(WrenVM* vm, ObjList* list, Value value, uint32_t index);

// Removes and returns the item at [index] from [list].
Value wrenListRemoveAt(WrenVM* vm, ObjList* list, uint32_t index);

// Searches for [value] in [list], returns the index or -1 if not found.
int wrenListIndexOf(WrenVM* vm, ObjList* list, Value value);

// Creates a new empty map.
ObjMap* wrenNewMap(WrenVM* vm);

// Validates that [arg] is a valid object for use as a map key. Returns true if
// it is and returns false otherwise. Use validateKey usually, for a runtime error.
// This separation exists to aid the API in surfacing errors to the developer as well.
static inline bool wrenMapIsValidKey(Value arg);

// Looks up [key] in [map]. If found, returns the value. Otherwise, returns
// `UNDEFINED_VAL`.
Value wrenMapGet(ObjMap* map, Value key);

// Associates [key] with [value] in [map].
void wrenMapSet(WrenVM* vm, ObjMap* map, Value key, Value value);

void wrenMapClear(WrenVM* vm, ObjMap* map);

// Removes [key] from [map], if present. Returns the value for the key if found
// or `NULL_VAL` otherwise.
Value wrenMapRemoveKey(WrenVM* vm, ObjMap* map, Value key);

// Creates a new module.
ObjModule* wrenNewModule(WrenVM* vm, ObjString* name);

// Creates a new range from [from] to [to].
Value wrenNewRange(WrenVM* vm, double from, double to, bool isInclusive);

// Creates a new string object and copies [text] into it.
//
// [text] must be non-NULL.
Value wrenNewString(WrenVM* vm, const char* text);

// Creates a new string object of [length] and copies [text] into it.
//
// [text] may be NULL if [length] is zero.
Value wrenNewStringLength(WrenVM* vm, const char* text, size_t length);

// Creates a new string object by taking a range of characters from [source].
// The range starts at [start], contains [count] bytes, and increments by
// [step].
Value wrenNewStringFromRange(WrenVM* vm, ObjString* source, int start,
                             uint32_t count, int step);

// Produces a string representation of [value].
Value wrenNumToString(WrenVM* vm, double value);

// Creates a new formatted string from [format] and any additional arguments
// used in the format string.
//
// This is a very restricted flavor of formatting, intended only for internal
// use by the VM. Two formatting characters are supported, each of which reads
// the next argument as a certain type:
//
// $ - A C string.
// @ - A Wren string object.
Value wrenStringFormat(WrenVM* vm, const char* format, ...);

// Creates a new string containing the UTF-8 encoding of [value].
Value wrenStringFromCodePoint(WrenVM* vm, int value);

// Creates a new string from the integer representation of a byte
Value wrenStringFromByte(WrenVM* vm, uint8_t value);

// Creates a new string containing the code point in [string] starting at byte
// [index]. If [index] points into the middle of a UTF-8 sequence, returns an
// empty string.
Value wrenStringCodePointAt(WrenVM* vm, ObjString* string, uint32_t index);

// Search for the first occurence of [needle] within [haystack] and returns its
// zero-based offset. Returns `UINT32_MAX` if [haystack] does not contain
// [needle].
uint32_t wrenStringFind(ObjString* haystack, ObjString* needle,
                        uint32_t startIndex);

// Returns true if [a] and [b] represent the same string.
static inline bool wrenStringEqualsCString(const ObjString* a,
                                           const char* b, size_t length)
{
  return a->length == length && memcmp(a->value, b, length) == 0;
}

// Creates a new open upvalue pointing to [value] on the stack.
ObjUpvalue* wrenNewUpvalue(WrenVM* vm, Value* value);

// Mark [obj] as reachable and still in use. This should only be called
// during the sweep phase of a garbage collection.
void wrenGrayObj(WrenVM* vm, Obj* obj);

// Mark [value] as reachable and still in use. This should only be called
// during the sweep phase of a garbage collection.
void wrenGrayValue(WrenVM* vm, Value value);

// Mark the values in [buffer] as reachable and still in use. This should only
// be called during the sweep phase of a garbage collection.
void wrenGrayBuffer(WrenVM* vm, ValueBuffer* buffer);

// Processes every object in the gray stack until all reachable objects have
// been marked. After that, all objects are either white (freeable) or black
// (in use and fully traversed).
void wrenBlackenObjects(WrenVM* vm);

// Releases all memory owned by [obj], including [obj] itself.
void wrenFreeObj(WrenVM* vm, Obj* obj);

// Returns the class of [value].
//
// Unlike wrenGetClassInline in wren_vm.h, this is not inlined. Inlining helps
// performance (significantly) in some cases, but degrades it in others. The
// ones used by the implementation were chosen to give the best results in the
// benchmarks.
ObjClass* wrenGetClass(WrenVM* vm, Value value);

// Returns true if [a] and [b] are strictly the same value. This is identity
// for object values, and value equality for unboxed values.
static inline bool wrenValuesSame(Value a, Value b)
{
#if WREN_NAN_TAGGING
  // Value types have unique bit representations and we compare object types
  // by identity (i.e. pointer), so all we need to do is compare the bits.
  return a == b;
#else
  if (a.type != b.type) return false;
  if (a.type == VAL_NUM) return a.as.num == b.as.num;
  return a.as.obj == b.as.obj;
#endif
}

// Returns true if [a] and [b] are equivalent. Immutable values (null, bools,
// numbers, ranges, and strings) are equal if they have the same data. All
// other values are equal if they are identical objects.
bool wrenValuesEqual(Value a, Value b);

// Returns true if [value] is a bool. Do not call this directly, instead use
// [IS_BOOL].
static inline bool wrenIsBool(Value value)
{
#if WREN_NAN_TAGGING
  return value == TRUE_VAL || value == FALSE_VAL;
#else
  return value.type == VAL_FALSE || value.type == VAL_TRUE;
#endif
}

// Returns true if [value] is an object of type [type]. Do not call this
// directly, instead use the [IS___] macro for the type in question.
static inline bool wrenIsObjType(Value value, ObjType type)
{
  return IS_OBJ(value) && AS_OBJ(value)->type == type;
}

// Converts the raw object pointer [obj] to a [Value].
static inline Value wrenObjectToValue(Obj* obj)
{
#if WREN_NAN_TAGGING
  // The triple casting is necessary here to satisfy some compilers:
  // 1. (uintptr_t) Convert the pointer to a number of the right size.
  // 2. (uint64_t)  Pad it up to 64 bits in 32-bit builds.
  // 3. Or in the bits to make a tagged Nan.
  // 4. Cast to a typedef'd value.
  return (Value)(SIGN_BIT | QNAN | (uint64_t)(uintptr_t)(obj));
#else
  Value value;
  value.type = VAL_OBJ;
  value.as.obj = obj;
  return value;
#endif
}

// Interprets [value] as a [double].
static inline double wrenValueToNum(Value value)
{
#if WREN_NAN_TAGGING
  return wrenDoubleFromBits(value);
#else
  return value.as.num;
#endif
}

// Converts [num] to a [Value].
static inline Value wrenNumToValue(double num)
{
#if WREN_NAN_TAGGING
  return wrenDoubleToBits(num);
#else
  Value value;
  value.type = VAL_NUM;
  value.as.num = num;
  return value;
#endif
}

static inline bool wrenMapIsValidKey(Value arg)
{
  return IS_BOOL(arg)
      || IS_CLASS(arg)
      || IS_NULL(arg)
      || IS_NUM(arg)
      || IS_RANGE(arg)
      || IS_STRING(arg);
}

#endif
// End file "wren_value.h"
// Begin file "wren_vm.h"
#ifndef wren_vm_h
#define wren_vm_h

// Begin file "wren_compiler.h"
#ifndef wren_compiler_h
#define wren_compiler_h


typedef struct sCompiler Compiler;

// This module defines the compiler for Wren. It takes a string of source code
// and lexes, parses, and compiles it. Wren uses a single-pass compiler. It
// does not build an actual AST during parsing and then consume that to
// generate code. Instead, the parser directly emits bytecode.
//
// This forces a few restrictions on the grammar and semantics of the language.
// Things like forward references and arbitrary lookahead are much harder. We
// get a lot in return for that, though.
//
// The implementation is much simpler since we don't need to define a bunch of
// AST data structures. More so, we don't have to deal with managing memory for
// AST objects. The compiler does almost no dynamic allocation while running.
//
// Compilation is also faster since we don't create a bunch of temporary data
// structures and destroy them after generating code.

// Compiles [source], a string of Wren source code located in [module], to an
// [ObjFn] that will execute that code when invoked. Returns `NULL` if the
// source contains any syntax errors.
//
// If [isExpression] is `true`, [source] should be a single expression, and
// this compiles it to a function that evaluates and returns that expression.
// Otherwise, [source] should be a series of top level statements.
//
// If [printErrors] is `true`, any compile errors are output to stderr.
// Otherwise, they are silently discarded.
ObjFn* wrenCompile(WrenVM* vm, ObjModule* module, const char* source,
                   bool isExpression, bool printErrors);

// When a class is defined, its superclass is not known until runtime since
// class definitions are just imperative statements. Most of the bytecode for a
// a method doesn't care, but there are two places where it matters:
//
//   - To load or store a field, we need to know the index of the field in the
//     instance's field array. We need to adjust this so that subclass fields
//     are positioned after superclass fields, and we don't know this until the
//     superclass is known.
//
//   - Superclass calls need to know which superclass to dispatch to.
//
// We could handle this dynamically, but that adds overhead. Instead, when a
// method is bound, we walk the bytecode for the function and patch it up.
void wrenBindMethodCode(ObjClass* classObj, ObjFn* fn);

// Reaches all of the heap-allocated objects in use by [compiler] (and all of
// its parents) so that they are not collected by the GC.
void wrenMarkCompiler(WrenVM* vm, Compiler* compiler);

#endif
// End file "wren_compiler.h"

// The maximum number of temporary objects that can be made visible to the GC
// at one time.
#define WREN_MAX_TEMP_ROOTS 8

typedef enum
{
  #define OPCODE(name, _) CODE_##name,
// Begin file "wren_opcodes.h"
// This defines the bytecode instructions used by the VM. It does so by invoking
// an OPCODE() macro which is expected to be defined at the point that this is
// included. (See: http://en.wikipedia.org/wiki/X_Macro for more.)
//
// The first argument is the name of the opcode. The second is its "stack
// effect" -- the amount that the op code changes the size of the stack. A
// stack effect of 1 means it pushes a value and the stack grows one larger.
// -2 means it pops two values, etc.
//
// Note that the order of instructions here affects the order of the dispatch
// table in the VM's interpreter loop. That in turn affects caching which
// affects overall performance. Take care to run benchmarks if you change the
// order here.

// Load the constant at index [arg].
OPCODE(CONSTANT, 1)

// Push null onto the stack.
OPCODE(NULL, 1)

// Push false onto the stack.
OPCODE(FALSE, 1)

// Push true onto the stack.
OPCODE(TRUE, 1)

// Pushes the value in the given local slot.
OPCODE(LOAD_LOCAL_0, 1)
OPCODE(LOAD_LOCAL_1, 1)
OPCODE(LOAD_LOCAL_2, 1)
OPCODE(LOAD_LOCAL_3, 1)
OPCODE(LOAD_LOCAL_4, 1)
OPCODE(LOAD_LOCAL_5, 1)
OPCODE(LOAD_LOCAL_6, 1)
OPCODE(LOAD_LOCAL_7, 1)
OPCODE(LOAD_LOCAL_8, 1)

// Note: The compiler assumes the following _STORE instructions always
// immediately follow their corresponding _LOAD ones.

// Pushes the value in local slot [arg].
OPCODE(LOAD_LOCAL, 1)

// Stores the top of stack in local slot [arg]. Does not pop it.
OPCODE(STORE_LOCAL, 0)

// Pushes the value in upvalue [arg].
OPCODE(LOAD_UPVALUE, 1)

// Stores the top of stack in upvalue [arg]. Does not pop it.
OPCODE(STORE_UPVALUE, 0)

// Pushes the value of the top-level variable in slot [arg].
OPCODE(LOAD_MODULE_VAR, 1)

// Stores the top of stack in top-level variable slot [arg]. Does not pop it.
OPCODE(STORE_MODULE_VAR, 0)

// Pushes the value of the field in slot [arg] of the receiver of the current
// function. This is used for regular field accesses on "this" directly in
// methods. This instruction is faster than the more general CODE_LOAD_FIELD
// instruction.
OPCODE(LOAD_FIELD_THIS, 1)

// Stores the top of the stack in field slot [arg] in the receiver of the
// current value. Does not pop the value. This instruction is faster than the
// more general CODE_LOAD_FIELD instruction.
OPCODE(STORE_FIELD_THIS, 0)

// Pops an instance and pushes the value of the field in slot [arg] of it.
OPCODE(LOAD_FIELD, 0)

// Pops an instance and stores the subsequent top of stack in field slot
// [arg] in it. Does not pop the value.
OPCODE(STORE_FIELD, -1)

// Pop and discard the top of stack.
OPCODE(POP, -1)

// Invoke the method with symbol [arg]. The number indicates the number of
// arguments (not including the receiver).
OPCODE(CALL_0, 0)
OPCODE(CALL_1, -1)
OPCODE(CALL_2, -2)
OPCODE(CALL_3, -3)
OPCODE(CALL_4, -4)
OPCODE(CALL_5, -5)
OPCODE(CALL_6, -6)
OPCODE(CALL_7, -7)
OPCODE(CALL_8, -8)
OPCODE(CALL_9, -9)
OPCODE(CALL_10, -10)
OPCODE(CALL_11, -11)
OPCODE(CALL_12, -12)
OPCODE(CALL_13, -13)
OPCODE(CALL_14, -14)
OPCODE(CALL_15, -15)
OPCODE(CALL_16, -16)

// Invoke a superclass method with symbol [arg]. The number indicates the
// number of arguments (not including the receiver).
OPCODE(SUPER_0, 0)
OPCODE(SUPER_1, -1)
OPCODE(SUPER_2, -2)
OPCODE(SUPER_3, -3)
OPCODE(SUPER_4, -4)
OPCODE(SUPER_5, -5)
OPCODE(SUPER_6, -6)
OPCODE(SUPER_7, -7)
OPCODE(SUPER_8, -8)
OPCODE(SUPER_9, -9)
OPCODE(SUPER_10, -10)
OPCODE(SUPER_11, -11)
OPCODE(SUPER_12, -12)
OPCODE(SUPER_13, -13)
OPCODE(SUPER_14, -14)
OPCODE(SUPER_15, -15)
OPCODE(SUPER_16, -16)

// Jump the instruction pointer [arg] forward.
OPCODE(JUMP, 0)

// Jump the instruction pointer [arg] backward.
OPCODE(LOOP, 0)

// Pop and if not truthy then jump the instruction pointer [arg] forward.
OPCODE(JUMP_IF, -1)

// If the top of the stack is false, jump [arg] forward. Otherwise, pop and
// continue.
OPCODE(AND, -1)

// If the top of the stack is non-false, jump [arg] forward. Otherwise, pop
// and continue.
OPCODE(OR, -1)

// Close the upvalue for the local on the top of the stack, then pop it.
OPCODE(CLOSE_UPVALUE, -1)

// Exit from the current function and return the value on the top of the
// stack.
OPCODE(RETURN, 0)

// Creates a closure for the function stored at [arg] in the constant table.
//
// Following the function argument is a number of arguments, two for each
// upvalue. The first is true if the variable being captured is a local (as
// opposed to an upvalue), and the second is the index of the local or
// upvalue being captured.
//
// Pushes the created closure.
OPCODE(CLOSURE, 1)

// Creates a new instance of a class.
//
// Assumes the class object is in slot zero, and replaces it with the new
// uninitialized instance of that class. This opcode is only emitted by the
// compiler-generated constructor metaclass methods.
OPCODE(CONSTRUCT, 0)

// Creates a new instance of a foreign class.
//
// Assumes the class object is in slot zero, and replaces it with the new
// uninitialized instance of that class. This opcode is only emitted by the
// compiler-generated constructor metaclass methods.
OPCODE(FOREIGN_CONSTRUCT, 0)

// Creates a class. Top of stack is the superclass. Below that is a string for
// the name of the class. Byte [arg] is the number of fields in the class.
OPCODE(CLASS, -1)

// Ends a class. 
// Atm the stack contains the class and the ClassAttributes (or null).
OPCODE(END_CLASS, -2)

// Creates a foreign class. Top of stack is the superclass. Below that is a
// string for the name of the class.
OPCODE(FOREIGN_CLASS, -1)

// Define a method for symbol [arg]. The class receiving the method is popped
// off the stack, then the function defining the body is popped.
//
// If a foreign method is being defined, the "function" will be a string
// identifying the foreign method. Otherwise, it will be a function or
// closure.
OPCODE(METHOD_INSTANCE, -2)

// Define a method for symbol [arg]. The class whose metaclass will receive
// the method is popped off the stack, then the function defining the body is
// popped.
//
// If a foreign method is being defined, the "function" will be a string
// identifying the foreign method. Otherwise, it will be a function or
// closure.
OPCODE(METHOD_STATIC, -2)

// This is executed at the end of the module's body. Pushes NULL onto the stack
// as the "return value" of the import statement and stores the module as the
// most recently imported one.
OPCODE(END_MODULE, 1)

// Import a module whose name is the string stored at [arg] in the constant
// table.
//
// Pushes null onto the stack so that the fiber for the imported module can
// replace that with a dummy value when it returns. (Fibers always return a
// value when resuming a caller.)
OPCODE(IMPORT_MODULE, 1)

// Import a variable from the most recently imported module. The name of the
// variable to import is at [arg] in the constant table. Pushes the loaded
// variable's value.
OPCODE(IMPORT_VARIABLE, 1)

// This pseudo-instruction indicates the end of the bytecode. It should
// always be preceded by a `CODE_RETURN`, so is never actually executed.
OPCODE(END, 0)
// End file "wren_opcodes.h"
  #undef OPCODE
} Code;

// A handle to a value, basically just a linked list of extra GC roots.
//
// Note that even non-heap-allocated values can be stored here.
struct WrenHandle
{
  Value value;

  WrenHandle* prev;
  WrenHandle* next;
};

struct WrenVM
{
  ObjClass* boolClass;
  ObjClass* classClass;
  ObjClass* fiberClass;
  ObjClass* fnClass;
  ObjClass* listClass;
  ObjClass* mapClass;
  ObjClass* nullClass;
  ObjClass* numClass;
  ObjClass* objectClass;
  ObjClass* rangeClass;
  ObjClass* stringClass;

  // The fiber that is currently running.
  ObjFiber* fiber;

  // The loaded modules. Each key is an ObjString (except for the main module,
  // whose key is null) for the module's name and the value is the ObjModule
  // for the module.
  ObjMap* modules;
  
  // The most recently imported module. More specifically, the module whose
  // code has most recently finished executing.
  //
  // Not treated like a GC root since the module is already in [modules].
  ObjModule* lastModule;

  // Memory management data:

  // The number of bytes that are known to be currently allocated. Includes all
  // memory that was proven live after the last GC, as well as any new bytes
  // that were allocated since then. Does *not* include bytes for objects that
  // were freed since the last GC.
  size_t bytesAllocated;

  // The number of total allocated bytes that will trigger the next GC.
  size_t nextGC;

  // The first object in the linked list of all currently allocated objects.
  Obj* first;

  // The "gray" set for the garbage collector. This is the stack of unprocessed
  // objects while a garbage collection pass is in process.
  Obj** gray;
  int grayCount;
  int grayCapacity;

  // The list of temporary roots. This is for temporary or new objects that are
  // not otherwise reachable but should not be collected.
  //
  // They are organized as a stack of pointers stored in this array. This
  // implies that temporary roots need to have stack semantics: only the most
  // recently pushed object can be released.
  Obj* tempRoots[WREN_MAX_TEMP_ROOTS];

  int numTempRoots;
  
  // Pointer to the first node in the linked list of active handles or NULL if
  // there are none.
  WrenHandle* handles;
  
  // Pointer to the bottom of the range of stack slots available for use from
  // the C API. During a foreign method, this will be in the stack of the fiber
  // that is executing a method.
  //
  // If not in a foreign method, this is initially NULL. If the user requests
  // slots by calling wrenEnsureSlots(), a stack is created and this is
  // initialized.
  Value* apiStack;

  WrenConfiguration config;
  
  // Compiler and debugger data:

  // The compiler that is currently compiling code. This is used so that heap
  // allocated objects used by the compiler can be found if a GC is kicked off
  // in the middle of a compile.
  Compiler* compiler;

  // There is a single global symbol table for all method names on all classes.
  // Method calls are dispatched directly by index in this table.
  SymbolTable methodNames;
};

// A generic allocation function that handles all explicit memory management.
// It's used like so:
//
// - To allocate new memory, [memory] is NULL and [oldSize] is zero. It should
//   return the allocated memory or NULL on failure.
//
// - To attempt to grow an existing allocation, [memory] is the memory,
//   [oldSize] is its previous size, and [newSize] is the desired size.
//   It should return [memory] if it was able to grow it in place, or a new
//   pointer if it had to move it.
//
// - To shrink memory, [memory], [oldSize], and [newSize] are the same as above
//   but it will always return [memory].
//
// - To free memory, [memory] will be the memory to free and [newSize] and
//   [oldSize] will be zero. It should return NULL.
void* wrenReallocate(WrenVM* vm, void* memory, size_t oldSize, size_t newSize);

// Invoke the finalizer for the foreign object referenced by [foreign].
void wrenFinalizeForeign(WrenVM* vm, ObjForeign* foreign);

// Creates a new [WrenHandle] for [value].
WrenHandle* wrenMakeHandle(WrenVM* vm, Value value);

// Compile [source] in the context of [module] and wrap in a fiber that can
// execute it.
//
// Returns NULL if a compile error occurred.
ObjClosure* wrenCompileSource(WrenVM* vm, const char* module,
                              const char* source, bool isExpression,
                              bool printErrors);

// Looks up a variable from a previously-loaded module.
//
// Aborts the current fiber if the module or variable could not be found.
Value wrenGetModuleVariable(WrenVM* vm, Value moduleName, Value variableName);

// Returns the value of the module-level variable named [name] in the main
// module.
Value wrenFindVariable(WrenVM* vm, ObjModule* module, const char* name);

// Adds a new implicitly declared top-level variable named [name] to [module]
// based on a use site occurring on [line].
//
// Does not check to see if a variable with that name is already declared or
// defined. Returns the symbol for the new variable or -2 if there are too many
// variables defined.
int wrenDeclareVariable(WrenVM* vm, ObjModule* module, const char* name,
                        size_t length, int line);

// Adds a new top-level variable named [name] to [module], and optionally
// populates line with the line of the implicit first use (line can be NULL).
//
// Returns the symbol for the new variable, -1 if a variable with the given name
// is already defined, or -2 if there are too many variables defined.
// Returns -3 if this is a top-level lowercase variable (localname) that was
// used before being defined.
int wrenDefineVariable(WrenVM* vm, ObjModule* module, const char* name,
                       size_t length, Value value, int* line);

// Pushes [closure] onto [fiber]'s callstack to invoke it. Expects [numArgs]
// arguments (including the receiver) to be on the top of the stack already.
static inline void wrenCallFunction(WrenVM* vm, ObjFiber* fiber,
                                    ObjClosure* closure, int numArgs)
{
  // Grow the call frame array if needed.
  if (fiber->numFrames + 1 > fiber->frameCapacity)
  {
    int max = fiber->frameCapacity * 2;
    fiber->frames = (CallFrame*)wrenReallocate(vm, fiber->frames,
        sizeof(CallFrame) * fiber->frameCapacity, sizeof(CallFrame) * max);
    fiber->frameCapacity = max;
  }
  
  // Grow the stack if needed.
  int stackSize = (int)(fiber->stackTop - fiber->stack);
  int needed = stackSize + closure->fn->maxSlots;
  wrenEnsureStack(vm, fiber, needed);
  
  wrenAppendCallFrame(vm, fiber, closure, fiber->stackTop - numArgs);
}

// Marks [obj] as a GC root so that it doesn't get collected.
void wrenPushRoot(WrenVM* vm, Obj* obj);

// Removes the most recently pushed temporary root.
void wrenPopRoot(WrenVM* vm);

// Returns the class of [value].
//
// Defined here instead of in wren_value.h because it's critical that this be
// inlined. That means it must be defined in the header, but the wren_value.h
// header doesn't have a full definitely of WrenVM yet.
static inline ObjClass* wrenGetClassInline(WrenVM* vm, Value value)
{
  if (IS_NUM(value)) return vm->numClass;
  if (IS_OBJ(value)) return AS_OBJ(value)->classObj;

#if WREN_NAN_TAGGING
  switch (GET_TAG(value))
  {
    case TAG_FALSE:     return vm->boolClass; break;
    case TAG_NAN:       return vm->numClass; break;
    case TAG_NULL:      return vm->nullClass; break;
    case TAG_TRUE:      return vm->boolClass; break;
    case TAG_UNDEFINED: UNREACHABLE();
  }
#else
  switch (value.type)
  {
    case VAL_FALSE:     return vm->boolClass;
    case VAL_NULL:      return vm->nullClass;
    case VAL_NUM:       return vm->numClass;
    case VAL_TRUE:      return vm->boolClass;
    case VAL_OBJ:       return AS_OBJ(value)->classObj;
    case VAL_UNDEFINED: UNREACHABLE();
  }
#endif

  UNREACHABLE();
  return NULL;
}

// Returns `true` if [name] is a local variable name (starts with a lowercase
// letter).
static inline bool wrenIsLocalName(const char* name)
{
  return name[0] >= 'a' && name[0] <= 'z';
}

static inline bool wrenIsFalsyValue(Value value)
{
  return IS_FALSE(value) || IS_NULL(value);
}

#endif
// End file "wren_vm.h"

// Prints the stack trace for the current fiber.
//
// Used when a fiber throws a runtime error which is not caught.
void wrenDebugPrintStackTrace(WrenVM* vm);

// The "dump" functions are used for debugging Wren itself. Normal code paths
// will not call them unless one of the various DEBUG_ flags is enabled.

// Prints a representation of [value] to stdout.
void wrenDumpValue(Value value);

// Prints a representation of the bytecode for [fn] at instruction [i].
int wrenDumpInstruction(WrenVM* vm, ObjFn* fn, int i);

// Prints the disassembled code for [fn] to stdout.
void wrenDumpCode(WrenVM* vm, ObjFn* fn);

// Prints the contents of the current stack for [fiber] to stdout.
void wrenDumpStack(ObjFiber* fiber);

#endif
// End file "wren_debug.h"
// Begin file "wren_vm.c"
#include <stdarg.h>
#include <string.h>

// Begin file "wren_core.h"
#ifndef wren_core_h
#define wren_core_h


// This module defines the built-in classes and their primitives methods that
// are implemented directly in C code. Some languages try to implement as much
// of the core module itself in the primary language instead of in the host
// language.
//
// With Wren, we try to do as much of it in C as possible. Primitive methods
// are always faster than code written in Wren, and it minimizes startup time
// since we don't have to parse, compile, and execute Wren code.
//
// There is one limitation, though. Methods written in C cannot call Wren ones.
// They can only be the top of the callstack, and immediately return. This
// makes it difficult to have primitive methods that rely on polymorphic
// behavior. For example, `System.print` should call `toString` on its argument,
// including user-defined `toString` methods on user-defined classes.

void wrenInitializeCore(WrenVM* vm);

#endif
// End file "wren_core.h"
// Begin file "wren_primitive.h"
#ifndef wren_primitive_h
#define wren_primitive_h


// Binds a primitive method named [name] (in Wren) implemented using C function
// [fn] to `ObjClass` [cls].
#define PRIMITIVE(cls, name, function)                                         \
    do                                                                         \
    {                                                                          \
      int symbol = wrenSymbolTableEnsure(vm,                                   \
          &vm->methodNames, name, strlen(name));                               \
      Method method;                                                           \
      method.type = METHOD_PRIMITIVE;                                          \
      method.as.primitive = prim_##function;                                   \
      wrenBindMethod(vm, cls, symbol, method);                                 \
    } while (false)

// Binds a primitive method named [name] (in Wren) implemented using C function
// [fn] to `ObjClass` [cls], but as a FN call.
#define FUNCTION_CALL(cls, name, function)                                     \
    do                                                                         \
    {                                                                          \
      int symbol = wrenSymbolTableEnsure(vm,                                   \
          &vm->methodNames, name, strlen(name));                               \
      Method method;                                                           \
      method.type = METHOD_FUNCTION_CALL;                                      \
      method.as.primitive = prim_##function;                                   \
      wrenBindMethod(vm, cls, symbol, method);                                 \
    } while (false)

// Defines a primitive method whose C function name is [name]. This abstracts
// the actual type signature of a primitive function and makes it clear which C
// functions are invoked as primitives.
#define DEF_PRIMITIVE(name)                                                    \
    static bool prim_##name(WrenVM* vm, Value* args)

#define RETURN_VAL(value)                                                      \
    do                                                                         \
    {                                                                          \
      args[0] = value;                                                         \
      return true;                                                             \
    } while (false)

#define RETURN_OBJ(obj)     RETURN_VAL(OBJ_VAL(obj))
#define RETURN_BOOL(value)  RETURN_VAL(BOOL_VAL(value))
#define RETURN_FALSE        RETURN_VAL(FALSE_VAL)
#define RETURN_NULL         RETURN_VAL(NULL_VAL)
#define RETURN_NUM(value)   RETURN_VAL(NUM_VAL(value))
#define RETURN_TRUE         RETURN_VAL(TRUE_VAL)

#define RETURN_ERROR(msg)                                                      \
    do                                                                         \
    {                                                                          \
      vm->fiber->error = wrenNewStringLength(vm, msg, sizeof(msg) - 1);        \
      return false;                                                            \
    } while (false)

#define RETURN_ERROR_FMT(...)                                                  \
    do                                                                         \
    {                                                                          \
      vm->fiber->error = wrenStringFormat(vm, __VA_ARGS__);                    \
      return false;                                                            \
    } while (false)

// Validates that the given [arg] is a function. Returns true if it is. If not,
// reports an error and returns false.
bool validateFn(WrenVM* vm, Value arg, const char* argName);

// Validates that the given [arg] is a Num. Returns true if it is. If not,
// reports an error and returns false.
bool validateNum(WrenVM* vm, Value arg, const char* argName);

// Validates that [value] is an integer. Returns true if it is. If not, reports
// an error and returns false.
bool validateIntValue(WrenVM* vm, double value, const char* argName);

// Validates that the given [arg] is an integer. Returns true if it is. If not,
// reports an error and returns false.
bool validateInt(WrenVM* vm, Value arg, const char* argName);

// Validates that [arg] is a valid object for use as a map key. Returns true if
// it is. If not, reports an error and returns false.
bool validateKey(WrenVM* vm, Value arg);

// Validates that the argument at [argIndex] is an integer within `[0, count)`.
// Also allows negative indices which map backwards from the end. Returns the
// valid positive index value. If invalid, reports an error and returns
// `UINT32_MAX`.
uint32_t validateIndex(WrenVM* vm, Value arg, uint32_t count,
                       const char* argName);

// Validates that the given [arg] is a String. Returns true if it is. If not,
// reports an error and returns false.
bool validateString(WrenVM* vm, Value arg, const char* argName);

// Given a [range] and the [length] of the object being operated on, determines
// the series of elements that should be chosen from the underlying object.
// Handles ranges that count backwards from the end as well as negative ranges.
//
// Returns the index from which the range should start or `UINT32_MAX` if the
// range is invalid. After calling, [length] will be updated with the number of
// elements in the resulting sequence. [step] will be direction that the range
// is going: `1` if the range is increasing from the start index or `-1` if the
// range is decreasing.
uint32_t calculateRange(WrenVM* vm, ObjRange* range, uint32_t* length,
                        int* step);

#endif
// End file "wren_primitive.h"

#if WREN_OPT_META
// Begin file "wren_opt_meta.h"
#ifndef wren_opt_meta_h
#define wren_opt_meta_h


// This module defines the Meta class and its associated methods.
#if WREN_OPT_META

const char* wrenMetaSource();
WrenForeignMethodFn wrenMetaBindForeignMethod(WrenVM* vm,
                                              const char* className,
                                              bool isStatic,
                                              const char* signature);

#endif

#endif
// End file "wren_opt_meta.h"
#endif
#if WREN_OPT_RANDOM
// Begin file "wren_opt_random.h"
#ifndef wren_opt_random_h
#define wren_opt_random_h


#if WREN_OPT_RANDOM

const char* wrenRandomSource();
WrenForeignClassMethods wrenRandomBindForeignClass(WrenVM* vm,
                                                   const char* module,
                                                   const char* className);
WrenForeignMethodFn wrenRandomBindForeignMethod(WrenVM* vm,
                                                const char* className,
                                                bool isStatic,
                                                const char* signature);

#endif

#endif
// End file "wren_opt_random.h"
#endif

#if WREN_DEBUG_TRACE_MEMORY || WREN_DEBUG_TRACE_GC
  #include <time.h>
  #include <stdio.h>
#endif

// The behavior of realloc() when the size is 0 is implementation defined. It
// may return a non-NULL pointer which must not be dereferenced but nevertheless
// should be freed. To prevent that, we avoid calling realloc() with a zero
// size.
static void* defaultReallocate(void* ptr, size_t newSize, void* _)
{
  if (newSize == 0)
  {
    free(ptr);
    return NULL;
  }

  return realloc(ptr, newSize);
}

int wrenGetVersionNumber() 
{ 
  return WREN_VERSION_NUMBER;
}

void wrenInitConfiguration(WrenConfiguration* config)
{
  config->reallocateFn = defaultReallocate;
  config->resolveModuleFn = NULL;
  config->loadModuleFn = NULL;
  config->bindForeignMethodFn = NULL;
  config->bindForeignClassFn = NULL;
  config->writeFn = NULL;
  config->errorFn = NULL;
  config->initialHeapSize = 1024 * 1024 * 10;
  config->minHeapSize = 1024 * 1024;
  config->heapGrowthPercent = 50;
  config->userData = NULL;
}

WrenVM* wrenNewVM(WrenConfiguration* config)
{
  WrenReallocateFn reallocate = defaultReallocate;
  void* userData = NULL;
  if (config != NULL) {
    userData = config->userData;
    reallocate = config->reallocateFn ? config->reallocateFn : defaultReallocate;
  }
  
  WrenVM* vm = (WrenVM*)reallocate(NULL, sizeof(*vm), userData);
  memset(vm, 0, sizeof(WrenVM));

  // Copy the configuration if given one.
  if (config != NULL)
  {
    memcpy(&vm->config, config, sizeof(WrenConfiguration));

    // We choose to set this after copying, 
    // rather than modifying the user config pointer
    vm->config.reallocateFn = reallocate;
  }
  else
  {
    wrenInitConfiguration(&vm->config);
  }

  // TODO: Should we allocate and free this during a GC?
  vm->grayCount = 0;
  // TODO: Tune this.
  vm->grayCapacity = 4;
  vm->gray = (Obj**)reallocate(NULL, vm->grayCapacity * sizeof(Obj*), userData);
  vm->nextGC = vm->config.initialHeapSize;

  wrenSymbolTableInit(&vm->methodNames);

  vm->modules = wrenNewMap(vm);
  wrenInitializeCore(vm);
  return vm;
}

void wrenFreeVM(WrenVM* vm)
{
  ASSERT(vm->methodNames.count > 0, "VM appears to have already been freed.");
  
  // Free all of the GC objects.
  Obj* obj = vm->first;
  while (obj != NULL)
  {
    Obj* next = obj->next;
    wrenFreeObj(vm, obj);
    obj = next;
  }

  // Free up the GC gray set.
  vm->gray = (Obj**)vm->config.reallocateFn(vm->gray, 0, vm->config.userData);

  // Tell the user if they didn't free any handles. We don't want to just free
  // them here because the host app may still have pointers to them that they
  // may try to use. Better to tell them about the bug early.
  ASSERT(vm->handles == NULL, "All handles have not been released.");

  wrenSymbolTableClear(vm, &vm->methodNames);

  DEALLOCATE(vm, vm);
}

void wrenCollectGarbage(WrenVM* vm)
{
#if WREN_DEBUG_TRACE_MEMORY || WREN_DEBUG_TRACE_GC
  printf("-- gc --\n");

  size_t before = vm->bytesAllocated;
  double startTime = (double)clock() / CLOCKS_PER_SEC;
#endif

  // Mark all reachable objects.

  // Reset this. As we mark objects, their size will be counted again so that
  // we can track how much memory is in use without needing to know the size
  // of each *freed* object.
  //
  // This is important because when freeing an unmarked object, we don't always
  // know how much memory it is using. For example, when freeing an instance,
  // we need to know its class to know how big it is, but its class may have
  // already been freed.
  vm->bytesAllocated = 0;

  wrenGrayObj(vm, (Obj*)vm->modules);

  // Temporary roots.
  for (int i = 0; i < vm->numTempRoots; i++)
  {
    wrenGrayObj(vm, vm->tempRoots[i]);
  }

  // The current fiber.
  wrenGrayObj(vm, (Obj*)vm->fiber);

  // The handles.
  for (WrenHandle* handle = vm->handles;
       handle != NULL;
       handle = handle->next)
  {
    wrenGrayValue(vm, handle->value);
  }

  // Any object the compiler is using (if there is one).
  if (vm->compiler != NULL) wrenMarkCompiler(vm, vm->compiler);

  // Method names.
  wrenBlackenSymbolTable(vm, &vm->methodNames);

  // Now that we have grayed the roots, do a depth-first search over all of the
  // reachable objects.
  wrenBlackenObjects(vm);

  // Collect the white objects.
  Obj** obj = &vm->first;
  while (*obj != NULL)
  {
    if (!((*obj)->isDark))
    {
      // This object wasn't reached, so remove it from the list and free it.
      Obj* unreached = *obj;
      *obj = unreached->next;
      wrenFreeObj(vm, unreached);
    }
    else
    {
      // This object was reached, so unmark it (for the next GC) and move on to
      // the next.
      (*obj)->isDark = false;
      obj = &(*obj)->next;
    }
  }

  // Calculate the next gc point, this is the current allocation plus
  // a configured percentage of the current allocation.
  vm->nextGC = vm->bytesAllocated + ((vm->bytesAllocated * vm->config.heapGrowthPercent) / 100);
  if (vm->nextGC < vm->config.minHeapSize) vm->nextGC = vm->config.minHeapSize;

#if WREN_DEBUG_TRACE_MEMORY || WREN_DEBUG_TRACE_GC
  double elapsed = ((double)clock() / CLOCKS_PER_SEC) - startTime;
  // Explicit cast because size_t has different sizes on 32-bit and 64-bit and
  // we need a consistent type for the format string.
  printf("GC %lu before, %lu after (%lu collected), next at %lu. Took %.3fms.\n",
         (unsigned long)before,
         (unsigned long)vm->bytesAllocated,
         (unsigned long)(before - vm->bytesAllocated),
         (unsigned long)vm->nextGC,
         elapsed*1000.0);
#endif
}

void* wrenReallocate(WrenVM* vm, void* memory, size_t oldSize, size_t newSize)
{
#if WREN_DEBUG_TRACE_MEMORY
  // Explicit cast because size_t has different sizes on 32-bit and 64-bit and
  // we need a consistent type for the format string.
  printf("reallocate %p %lu -> %lu\n",
         memory, (unsigned long)oldSize, (unsigned long)newSize);
#endif

  // If new bytes are being allocated, add them to the total count. If objects
  // are being completely deallocated, we don't track that (since we don't
  // track the original size). Instead, that will be handled while marking
  // during the next GC.
  vm->bytesAllocated += newSize - oldSize;

#if WREN_DEBUG_GC_STRESS
  // Since collecting calls this function to free things, make sure we don't
  // recurse.
  if (newSize > 0) wrenCollectGarbage(vm);
#else
  if (newSize > 0 && vm->bytesAllocated > vm->nextGC) wrenCollectGarbage(vm);
#endif

  return vm->config.reallocateFn(memory, newSize, vm->config.userData);
}

// Captures the local variable [local] into an [Upvalue]. If that local is
// already in an upvalue, the existing one will be used. (This is important to
// ensure that multiple closures closing over the same variable actually see
// the same variable.) Otherwise, it will create a new open upvalue and add it
// the fiber's list of upvalues.
static ObjUpvalue* captureUpvalue(WrenVM* vm, ObjFiber* fiber, Value* local)
{
  // If there are no open upvalues at all, we must need a new one.
  if (fiber->openUpvalues == NULL)
  {
    fiber->openUpvalues = wrenNewUpvalue(vm, local);
    return fiber->openUpvalues;
  }

  ObjUpvalue* prevUpvalue = NULL;
  ObjUpvalue* upvalue = fiber->openUpvalues;

  // Walk towards the bottom of the stack until we find a previously existing
  // upvalue or pass where it should be.
  while (upvalue != NULL && upvalue->value > local)
  {
    prevUpvalue = upvalue;
    upvalue = upvalue->next;
  }

  // Found an existing upvalue for this local.
  if (upvalue != NULL && upvalue->value == local) return upvalue;

  // We've walked past this local on the stack, so there must not be an
  // upvalue for it already. Make a new one and link it in in the right
  // place to keep the list sorted.
  ObjUpvalue* createdUpvalue = wrenNewUpvalue(vm, local);
  if (prevUpvalue == NULL)
  {
    // The new one is the first one in the list.
    fiber->openUpvalues = createdUpvalue;
  }
  else
  {
    prevUpvalue->next = createdUpvalue;
  }

  createdUpvalue->next = upvalue;
  return createdUpvalue;
}

// Closes any open upvalues that have been created for stack slots at [last]
// and above.
static void closeUpvalues(ObjFiber* fiber, Value* last)
{
  while (fiber->openUpvalues != NULL &&
         fiber->openUpvalues->value >= last)
  {
    ObjUpvalue* upvalue = fiber->openUpvalues;

    // Move the value into the upvalue itself and point the upvalue to it.
    upvalue->closed = *upvalue->value;
    upvalue->value = &upvalue->closed;

    // Remove it from the open upvalue list.
    fiber->openUpvalues = upvalue->next;
  }
}

// Looks up a foreign method in [moduleName] on [className] with [signature].
//
// This will try the host's foreign method binder first. If that fails, it
// falls back to handling the built-in modules.
static WrenForeignMethodFn findForeignMethod(WrenVM* vm,
                                             const char* moduleName,
                                             const char* className,
                                             bool isStatic,
                                             const char* signature)
{
  WrenForeignMethodFn method = NULL;
  
  if (vm->config.bindForeignMethodFn != NULL)
  {
    method = vm->config.bindForeignMethodFn(vm, moduleName, className, isStatic,
                                            signature);
  }
  
  // If the host didn't provide it, see if it's an optional one.
  if (method == NULL)
  {
#if WREN_OPT_META
    if (strcmp(moduleName, "meta") == 0)
    {
      method = wrenMetaBindForeignMethod(vm, className, isStatic, signature);
    }
#endif
#if WREN_OPT_RANDOM
    if (strcmp(moduleName, "random") == 0)
    {
      method = wrenRandomBindForeignMethod(vm, className, isStatic, signature);
    }
#endif
  }

  return method;
}

// Defines [methodValue] as a method on [classObj].
//
// Handles both foreign methods where [methodValue] is a string containing the
// method's signature and Wren methods where [methodValue] is a function.
//
// Aborts the current fiber if the method is a foreign method that could not be
// found.
static void bindMethod(WrenVM* vm, int methodType, int symbol,
                       ObjModule* module, ObjClass* classObj, Value methodValue)
{
  const char* className = classObj->name->value;
  if (methodType == CODE_METHOD_STATIC) classObj = classObj->obj.classObj;

  Method method;
  if (IS_STRING(methodValue))
  {
    const char* name = AS_CSTRING(methodValue);
    method.type = METHOD_FOREIGN;
    method.as.foreign = findForeignMethod(vm, module->name->value,
                                          className,
                                          methodType == CODE_METHOD_STATIC,
                                          name);

    if (method.as.foreign == NULL)
    {
      vm->fiber->error = wrenStringFormat(vm,
          "Could not find foreign method '@' for class $ in module '$'.",
          methodValue, classObj->name->value, module->name->value);
      return;
    }
  }
  else
  {
    method.as.closure = AS_CLOSURE(methodValue);
    method.type = METHOD_BLOCK;

    // Patch up the bytecode now that we know the superclass.
    wrenBindMethodCode(classObj, method.as.closure->fn);
  }

  wrenBindMethod(vm, classObj, symbol, method);
}

static void callForeign(WrenVM* vm, ObjFiber* fiber,
                        WrenForeignMethodFn foreign, int numArgs)
{
  ASSERT(vm->apiStack == NULL, "Cannot already be in foreign call.");
  vm->apiStack = fiber->stackTop - numArgs;

  foreign(vm);

  // Discard the stack slots for the arguments and temporaries but leave one
  // for the result.
  fiber->stackTop = vm->apiStack + 1;

  vm->apiStack = NULL;
}

// Handles the current fiber having aborted because of an error.
//
// Walks the call chain of fibers, aborting each one until it hits a fiber that
// handles the error. If none do, tells the VM to stop.
static void runtimeError(WrenVM* vm)
{
  ASSERT(wrenHasError(vm->fiber), "Should only call this after an error.");

  ObjFiber* current = vm->fiber;
  Value error = current->error;
  
  while (current != NULL)
  {
    // Every fiber along the call chain gets aborted with the same error.
    current->error = error;

    // If the caller ran this fiber using "try", give it the error and stop.
    if (current->state == FIBER_TRY)
    {
      // Make the caller's try method return the error message.
      current->caller->stackTop[-1] = vm->fiber->error;
      vm->fiber = current->caller;
      return;
    }
    
    // Otherwise, unhook the caller since we will never resume and return to it.
    ObjFiber* caller = current->caller;
    current->caller = NULL;
    current = caller;
  }

  // If we got here, nothing caught the error, so show the stack trace.
  wrenDebugPrintStackTrace(vm);
  vm->fiber = NULL;
  vm->apiStack = NULL;
}

// Aborts the current fiber with an appropriate method not found error for a
// method with [symbol] on [classObj].
static void methodNotFound(WrenVM* vm, ObjClass* classObj, int symbol)
{
  vm->fiber->error = wrenStringFormat(vm, "@ does not implement '$'.",
      OBJ_VAL(classObj->name), vm->methodNames.data[symbol]->value);
}

// Looks up the previously loaded module with [name].
//
// Returns `NULL` if no module with that name has been loaded.
static ObjModule* getModule(WrenVM* vm, Value name)
{
  Value moduleValue = wrenMapGet(vm->modules, name);
  return !IS_UNDEFINED(moduleValue) ? AS_MODULE(moduleValue) : NULL;
}

static ObjClosure* compileInModule(WrenVM* vm, Value name, const char* source,
                                   bool isExpression, bool printErrors)
{
  // See if the module has already been loaded.
  ObjModule* module = getModule(vm, name);
  if (module == NULL)
  {
    module = wrenNewModule(vm, AS_STRING(name));

    // It's possible for the wrenMapSet below to resize the modules map,
    // and trigger a GC while doing so. When this happens it will collect
    // the module we've just created. Once in the map it is safe.
    wrenPushRoot(vm, (Obj*)module);

    // Store it in the VM's module registry so we don't load the same module
    // multiple times.
    wrenMapSet(vm, vm->modules, name, OBJ_VAL(module));

    wrenPopRoot(vm);

    // Implicitly import the core module.
    ObjModule* coreModule = getModule(vm, NULL_VAL);
    for (int i = 0; i < coreModule->variables.count; i++)
    {
      wrenDefineVariable(vm, module,
                         coreModule->variableNames.data[i]->value,
                         coreModule->variableNames.data[i]->length,
                         coreModule->variables.data[i], NULL);
    }
  }

  ObjFn* fn = wrenCompile(vm, module, source, isExpression, printErrors);
  if (fn == NULL)
  {
    // TODO: Should we still store the module even if it didn't compile?
    return NULL;
  }

  // Functions are always wrapped in closures.
  wrenPushRoot(vm, (Obj*)fn);
  ObjClosure* closure = wrenNewClosure(vm, fn);
  wrenPopRoot(vm); // fn.

  return closure;
}

// Verifies that [superclassValue] is a valid object to inherit from. That
// means it must be a class and cannot be the class of any built-in type.
//
// Also validates that it doesn't result in a class with too many fields and
// the other limitations foreign classes have.
//
// If successful, returns `null`. Otherwise, returns a string for the runtime
// error message.
static Value validateSuperclass(WrenVM* vm, Value name, Value superclassValue,
                                int numFields)
{
  // Make sure the superclass is a class.
  if (!IS_CLASS(superclassValue))
  {
    return wrenStringFormat(vm,
        "Class '@' cannot inherit from a non-class object.",
        name);
  }

  // Make sure it doesn't inherit from a sealed built-in type. Primitive methods
  // on these classes assume the instance is one of the other Obj___ types and
  // will fail horribly if it's actually an ObjInstance.
  ObjClass* superclass = AS_CLASS(superclassValue);
  if (superclass == vm->classClass ||
      superclass == vm->fiberClass ||
      superclass == vm->fnClass || // Includes OBJ_CLOSURE.
      superclass == vm->listClass ||
      superclass == vm->mapClass ||
      superclass == vm->rangeClass ||
      superclass == vm->stringClass ||
      superclass == vm->boolClass ||
      superclass == vm->nullClass ||
      superclass == vm->numClass)
  {
    return wrenStringFormat(vm,
        "Class '@' cannot inherit from built-in class '@'.",
        name, OBJ_VAL(superclass->name));
  }

  if (superclass->numFields == -1)
  {
    return wrenStringFormat(vm,
        "Class '@' cannot inherit from foreign class '@'.",
        name, OBJ_VAL(superclass->name));
  }

  if (numFields == -1 && superclass->numFields > 0)
  {
    return wrenStringFormat(vm,
        "Foreign class '@' may not inherit from a class with fields.",
        name);
  }

  if (superclass->numFields + numFields > MAX_FIELDS)
  {
    return wrenStringFormat(vm,
        "Class '@' may not have more than 255 fields, including inherited "
        "ones.", name);
  }

  return NULL_VAL;
}

static void bindForeignClass(WrenVM* vm, ObjClass* classObj, ObjModule* module)
{
  WrenForeignClassMethods methods;
  methods.allocate = NULL;
  methods.finalize = NULL;
  
  // Check the optional built-in module first so the host can override it.
  
  if (vm->config.bindForeignClassFn != NULL)
  {
    methods = vm->config.bindForeignClassFn(vm, module->name->value,
                                            classObj->name->value);
  }

  // If the host didn't provide it, see if it's a built in optional module.
  if (methods.allocate == NULL && methods.finalize == NULL)
  {
#if WREN_OPT_RANDOM
    if (strcmp(module->name->value, "random") == 0)
    {
      methods = wrenRandomBindForeignClass(vm, module->name->value,
                                           classObj->name->value);
    }
#endif
  }
  
  Method method;
  method.type = METHOD_FOREIGN;

  // Add the symbol even if there is no allocator so we can ensure that the
  // symbol itself is always in the symbol table.
  int symbol = wrenSymbolTableEnsure(vm, &vm->methodNames, "<allocate>", 10);
  if (methods.allocate != NULL)
  {
    method.as.foreign = methods.allocate;
    wrenBindMethod(vm, classObj, symbol, method);
  }
  
  // Add the symbol even if there is no finalizer so we can ensure that the
  // symbol itself is always in the symbol table.
  symbol = wrenSymbolTableEnsure(vm, &vm->methodNames, "<finalize>", 10);
  if (methods.finalize != NULL)
  {
    method.as.foreign = (WrenForeignMethodFn)methods.finalize;
    wrenBindMethod(vm, classObj, symbol, method);
  }
}

// Completes the process for creating a new class.
//
// The class attributes instance and the class itself should be on the 
// top of the fiber's stack. 
//
// This process handles moving the attribute data for a class from
// compile time to runtime, since it now has all the attributes associated
// with a class, including for methods.
static void endClass(WrenVM* vm) 
{
  // Pull the attributes and class off the stack
  Value attributes = vm->fiber->stackTop[-2];
  Value classValue = vm->fiber->stackTop[-1];

  // Remove the stack items
  vm->fiber->stackTop -= 2;

  ObjClass* classObj = AS_CLASS(classValue);
    classObj->attributes = attributes;
}

// Creates a new class.
//
// If [numFields] is -1, the class is a foreign class. The name and superclass
// should be on top of the fiber's stack. After calling this, the top of the
// stack will contain the new class.
//
// Aborts the current fiber if an error occurs.
static void createClass(WrenVM* vm, int numFields, ObjModule* module)
{
  // Pull the name and superclass off the stack.
  Value name = vm->fiber->stackTop[-2];
  Value superclass = vm->fiber->stackTop[-1];

  // We have two values on the stack and we are going to leave one, so discard
  // the other slot.
  vm->fiber->stackTop--;

  vm->fiber->error = validateSuperclass(vm, name, superclass, numFields);
  if (wrenHasError(vm->fiber)) return;

  ObjClass* classObj = wrenNewClass(vm, AS_CLASS(superclass), numFields,
                                    AS_STRING(name));
  vm->fiber->stackTop[-1] = OBJ_VAL(classObj);

  if (numFields == -1) bindForeignClass(vm, classObj, module);
}

static void createForeign(WrenVM* vm, ObjFiber* fiber, Value* stack)
{
  ObjClass* classObj = AS_CLASS(stack[0]);
  ASSERT(classObj->numFields == -1, "Class must be a foreign class.");

  // TODO: Don't look up every time.
  int symbol = wrenSymbolTableFind(&vm->methodNames, "<allocate>", 10);
  ASSERT(symbol != -1, "Should have defined <allocate> symbol.");

  ASSERT(classObj->methods.count > symbol, "Class should have allocator.");
  Method* method = &classObj->methods.data[symbol];
  ASSERT(method->type == METHOD_FOREIGN, "Allocator should be foreign.");

  // Pass the constructor arguments to the allocator as well.
  ASSERT(vm->apiStack == NULL, "Cannot already be in foreign call.");
  vm->apiStack = stack;

  method->as.foreign(vm);

  vm->apiStack = NULL;
}

void wrenFinalizeForeign(WrenVM* vm, ObjForeign* foreign)
{
  // TODO: Don't look up every time.
  int symbol = wrenSymbolTableFind(&vm->methodNames, "<finalize>", 10);
  ASSERT(symbol != -1, "Should have defined <finalize> symbol.");

  // If there are no finalizers, don't finalize it.
  if (symbol == -1) return;

  // If the class doesn't have a finalizer, bail out.
  ObjClass* classObj = foreign->obj.classObj;
  if (symbol >= classObj->methods.count) return;

  Method* method = &classObj->methods.data[symbol];
  if (method->type == METHOD_NONE) return;

  ASSERT(method->type == METHOD_FOREIGN, "Finalizer should be foreign.");

  WrenFinalizerFn finalizer = (WrenFinalizerFn)method->as.foreign;
  finalizer(foreign->data);
}

// Let the host resolve an imported module name if it wants to.
static Value resolveModule(WrenVM* vm, Value name)
{
  // If the host doesn't care to resolve, leave the name alone.
  if (vm->config.resolveModuleFn == NULL) return name;

  ObjFiber* fiber = vm->fiber;
  ObjFn* fn = fiber->frames[fiber->numFrames - 1].closure->fn;
  ObjString* importer = fn->module->name;
  
  const char* resolved = vm->config.resolveModuleFn(vm, importer->value,
                                                    AS_CSTRING(name));
  if (resolved == NULL)
  {
    vm->fiber->error = wrenStringFormat(vm,
        "Could not resolve module '@' imported from '@'.",
        name, OBJ_VAL(importer));
    return NULL_VAL;
  }
  
  // If they resolved to the exact same string, we don't need to copy it.
  if (resolved == AS_CSTRING(name)) return name;

  // Copy the string into a Wren String object.
  name = wrenNewString(vm, resolved);
  DEALLOCATE(vm, (char*)resolved);
  return name;
}

static Value importModule(WrenVM* vm, Value name)
{
  name = resolveModule(vm, name);
  
  // If the module is already loaded, we don't need to do anything.
  Value existing = wrenMapGet(vm->modules, name);
  if (!IS_UNDEFINED(existing)) return existing;

  wrenPushRoot(vm, AS_OBJ(name));

  WrenLoadModuleResult result = {0};
  
  // Let the host try to provide the module.
  if (vm->config.loadModuleFn != NULL)
  {
    result = vm->config.loadModuleFn(vm, AS_CSTRING(name));
  }
  
  // If the host didn't provide it, see if it's a built in optional module.
  if (result.source == NULL)
  {
#if WREN_OPT_META || WREN_OPT_RANDOME
    ObjString* nameString = AS_STRING(name);
#endif
    result.onComplete = NULL;
#if WREN_OPT_META
    if (strcmp(nameString->value, "meta") == 0) result.source = wrenMetaSource();
#endif
#if WREN_OPT_RANDOM
    if (strcmp(nameString->value, "random") == 0) result.source = wrenRandomSource();
#endif
  }
  
  if (result.source == NULL)
  {
    vm->fiber->error = wrenStringFormat(vm, "Could not load module '@'.", name);
    wrenPopRoot(vm); // name.
    return NULL_VAL;
  }
  
  ObjClosure* moduleClosure = compileInModule(vm, name, result.source, false, true);
  
  // Now that we're done, give the result back in case there's cleanup to do.
  if(result.onComplete) result.onComplete(vm, AS_CSTRING(name), result);
  
  if (moduleClosure == NULL)
  {
    vm->fiber->error = wrenStringFormat(vm,
                                        "Could not compile module '@'.", name);
    wrenPopRoot(vm); // name.
    return NULL_VAL;
  }

  wrenPopRoot(vm); // name.

  // Return the closure that executes the module.
  return OBJ_VAL(moduleClosure);
}

static Value getModuleVariable(WrenVM* vm, ObjModule* module,
                               Value variableName)
{
  ObjString* variable = AS_STRING(variableName);
  uint32_t variableEntry = wrenSymbolTableFind(&module->variableNames,
                                               variable->value,
                                               variable->length);
  
  // It's a runtime error if the imported variable does not exist.
  if (variableEntry != UINT32_MAX)
  {
    return module->variables.data[variableEntry];
  }
  
  vm->fiber->error = wrenStringFormat(vm,
      "Could not find a variable named '@' in module '@'.",
      variableName, OBJ_VAL(module->name));
  return NULL_VAL;
}

inline static bool checkArity(WrenVM* vm, Value value, int numArgs)
{
  ASSERT(IS_CLOSURE(value), "Receiver must be a closure.");
  ObjFn* fn = AS_CLOSURE(value)->fn;

  // We only care about missing arguments, not extras. The "- 1" is because
  // numArgs includes the receiver, the function itself, which we don't want to
  // count.
  if (numArgs - 1 >= fn->arity) return true;

  vm->fiber->error = CONST_STRING(vm, "Function expects more arguments.");
  return false;
}


// The main bytecode interpreter loop. This is where the magic happens. It is
// also, as you can imagine, highly performance critical.
static WrenInterpretResult runInterpreter(WrenVM* vm, register ObjFiber* fiber)
{
  // Remember the current fiber so we can find it if a GC happens.
  vm->fiber = fiber;
  fiber->state = FIBER_ROOT;

  // Hoist these into local variables. They are accessed frequently in the loop
  // but assigned less frequently. Keeping them in locals and updating them when
  // a call frame has been pushed or popped gives a large speed boost.
  register CallFrame* frame;
  register Value* stackStart;
  register uint8_t* ip;
  register ObjFn* fn;

  // These macros are designed to only be invoked within this function.
  #define PUSH(value)  (*fiber->stackTop++ = value)
  #define POP()        (*(--fiber->stackTop))
  #define DROP()       (fiber->stackTop--)
  #define PEEK()       (*(fiber->stackTop - 1))
  #define PEEK2()      (*(fiber->stackTop - 2))
  #define READ_BYTE()  (*ip++)
  #define READ_SHORT() (ip += 2, (uint16_t)((ip[-2] << 8) | ip[-1]))

  // Use this before a CallFrame is pushed to store the local variables back
  // into the current one.
  #define STORE_FRAME() frame->ip = ip

  // Use this after a CallFrame has been pushed or popped to refresh the local
  // variables.
  #define LOAD_FRAME()                                                         \
      do                                                                       \
      {                                                                        \
        frame = &fiber->frames[fiber->numFrames - 1];                          \
        stackStart = frame->stackStart;                                        \
        ip = frame->ip;                                                        \
        fn = frame->closure->fn;                                               \
      } while (false)

  // Terminates the current fiber with error string [error]. If another calling
  // fiber is willing to catch the error, transfers control to it, otherwise
  // exits the interpreter.
  #define RUNTIME_ERROR()                                                      \
      do                                                                       \
      {                                                                        \
        STORE_FRAME();                                                         \
        runtimeError(vm);                                                      \
        if (vm->fiber == NULL) return WREN_RESULT_RUNTIME_ERROR;               \
        fiber = vm->fiber;                                                     \
        LOAD_FRAME();                                                          \
        DISPATCH();                                                            \
      } while (false)

  #if WREN_DEBUG_TRACE_INSTRUCTIONS
    // Prints the stack and instruction before each instruction is executed.
    #define DEBUG_TRACE_INSTRUCTIONS()                                         \
        do                                                                     \
        {                                                                      \
          wrenDumpStack(fiber);                                                \
          wrenDumpInstruction(vm, fn, (int)(ip - fn->code.data));              \
        } while (false)
  #else
    #define DEBUG_TRACE_INSTRUCTIONS() do { } while (false)
  #endif

  #if WREN_COMPUTED_GOTO

  static void* dispatchTable[] = {
    #define OPCODE(name, _) &&code_##name,
// Begin file "wren_opcodes.h"
// This defines the bytecode instructions used by the VM. It does so by invoking
// an OPCODE() macro which is expected to be defined at the point that this is
// included. (See: http://en.wikipedia.org/wiki/X_Macro for more.)
//
// The first argument is the name of the opcode. The second is its "stack
// effect" -- the amount that the op code changes the size of the stack. A
// stack effect of 1 means it pushes a value and the stack grows one larger.
// -2 means it pops two values, etc.
//
// Note that the order of instructions here affects the order of the dispatch
// table in the VM's interpreter loop. That in turn affects caching which
// affects overall performance. Take care to run benchmarks if you change the
// order here.

// Load the constant at index [arg].
OPCODE(CONSTANT, 1)

// Push null onto the stack.
OPCODE(NULL, 1)

// Push false onto the stack.
OPCODE(FALSE, 1)

// Push true onto the stack.
OPCODE(TRUE, 1)

// Pushes the value in the given local slot.
OPCODE(LOAD_LOCAL_0, 1)
OPCODE(LOAD_LOCAL_1, 1)
OPCODE(LOAD_LOCAL_2, 1)
OPCODE(LOAD_LOCAL_3, 1)
OPCODE(LOAD_LOCAL_4, 1)
OPCODE(LOAD_LOCAL_5, 1)
OPCODE(LOAD_LOCAL_6, 1)
OPCODE(LOAD_LOCAL_7, 1)
OPCODE(LOAD_LOCAL_8, 1)

// Note: The compiler assumes the following _STORE instructions always
// immediately follow their corresponding _LOAD ones.

// Pushes the value in local slot [arg].
OPCODE(LOAD_LOCAL, 1)

// Stores the top of stack in local slot [arg]. Does not pop it.
OPCODE(STORE_LOCAL, 0)

// Pushes the value in upvalue [arg].
OPCODE(LOAD_UPVALUE, 1)

// Stores the top of stack in upvalue [arg]. Does not pop it.
OPCODE(STORE_UPVALUE, 0)

// Pushes the value of the top-level variable in slot [arg].
OPCODE(LOAD_MODULE_VAR, 1)

// Stores the top of stack in top-level variable slot [arg]. Does not pop it.
OPCODE(STORE_MODULE_VAR, 0)

// Pushes the value of the field in slot [arg] of the receiver of the current
// function. This is used for regular field accesses on "this" directly in
// methods. This instruction is faster than the more general CODE_LOAD_FIELD
// instruction.
OPCODE(LOAD_FIELD_THIS, 1)

// Stores the top of the stack in field slot [arg] in the receiver of the
// current value. Does not pop the value. This instruction is faster than the
// more general CODE_LOAD_FIELD instruction.
OPCODE(STORE_FIELD_THIS, 0)

// Pops an instance and pushes the value of the field in slot [arg] of it.
OPCODE(LOAD_FIELD, 0)

// Pops an instance and stores the subsequent top of stack in field slot
// [arg] in it. Does not pop the value.
OPCODE(STORE_FIELD, -1)

// Pop and discard the top of stack.
OPCODE(POP, -1)

// Invoke the method with symbol [arg]. The number indicates the number of
// arguments (not including the receiver).
OPCODE(CALL_0, 0)
OPCODE(CALL_1, -1)
OPCODE(CALL_2, -2)
OPCODE(CALL_3, -3)
OPCODE(CALL_4, -4)
OPCODE(CALL_5, -5)
OPCODE(CALL_6, -6)
OPCODE(CALL_7, -7)
OPCODE(CALL_8, -8)
OPCODE(CALL_9, -9)
OPCODE(CALL_10, -10)
OPCODE(CALL_11, -11)
OPCODE(CALL_12, -12)
OPCODE(CALL_13, -13)
OPCODE(CALL_14, -14)
OPCODE(CALL_15, -15)
OPCODE(CALL_16, -16)

// Invoke a superclass method with symbol [arg]. The number indicates the
// number of arguments (not including the receiver).
OPCODE(SUPER_0, 0)
OPCODE(SUPER_1, -1)
OPCODE(SUPER_2, -2)
OPCODE(SUPER_3, -3)
OPCODE(SUPER_4, -4)
OPCODE(SUPER_5, -5)
OPCODE(SUPER_6, -6)
OPCODE(SUPER_7, -7)
OPCODE(SUPER_8, -8)
OPCODE(SUPER_9, -9)
OPCODE(SUPER_10, -10)
OPCODE(SUPER_11, -11)
OPCODE(SUPER_12, -12)
OPCODE(SUPER_13, -13)
OPCODE(SUPER_14, -14)
OPCODE(SUPER_15, -15)
OPCODE(SUPER_16, -16)

// Jump the instruction pointer [arg] forward.
OPCODE(JUMP, 0)

// Jump the instruction pointer [arg] backward.
OPCODE(LOOP, 0)

// Pop and if not truthy then jump the instruction pointer [arg] forward.
OPCODE(JUMP_IF, -1)

// If the top of the stack is false, jump [arg] forward. Otherwise, pop and
// continue.
OPCODE(AND, -1)

// If the top of the stack is non-false, jump [arg] forward. Otherwise, pop
// and continue.
OPCODE(OR, -1)

// Close the upvalue for the local on the top of the stack, then pop it.
OPCODE(CLOSE_UPVALUE, -1)

// Exit from the current function and return the value on the top of the
// stack.
OPCODE(RETURN, 0)

// Creates a closure for the function stored at [arg] in the constant table.
//
// Following the function argument is a number of arguments, two for each
// upvalue. The first is true if the variable being captured is a local (as
// opposed to an upvalue), and the second is the index of the local or
// upvalue being captured.
//
// Pushes the created closure.
OPCODE(CLOSURE, 1)

// Creates a new instance of a class.
//
// Assumes the class object is in slot zero, and replaces it with the new
// uninitialized instance of that class. This opcode is only emitted by the
// compiler-generated constructor metaclass methods.
OPCODE(CONSTRUCT, 0)

// Creates a new instance of a foreign class.
//
// Assumes the class object is in slot zero, and replaces it with the new
// uninitialized instance of that class. This opcode is only emitted by the
// compiler-generated constructor metaclass methods.
OPCODE(FOREIGN_CONSTRUCT, 0)

// Creates a class. Top of stack is the superclass. Below that is a string for
// the name of the class. Byte [arg] is the number of fields in the class.
OPCODE(CLASS, -1)

// Ends a class. 
// Atm the stack contains the class and the ClassAttributes (or null).
OPCODE(END_CLASS, -2)

// Creates a foreign class. Top of stack is the superclass. Below that is a
// string for the name of the class.
OPCODE(FOREIGN_CLASS, -1)

// Define a method for symbol [arg]. The class receiving the method is popped
// off the stack, then the function defining the body is popped.
//
// If a foreign method is being defined, the "function" will be a string
// identifying the foreign method. Otherwise, it will be a function or
// closure.
OPCODE(METHOD_INSTANCE, -2)

// Define a method for symbol [arg]. The class whose metaclass will receive
// the method is popped off the stack, then the function defining the body is
// popped.
//
// If a foreign method is being defined, the "function" will be a string
// identifying the foreign method. Otherwise, it will be a function or
// closure.
OPCODE(METHOD_STATIC, -2)

// This is executed at the end of the module's body. Pushes NULL onto the stack
// as the "return value" of the import statement and stores the module as the
// most recently imported one.
OPCODE(END_MODULE, 1)

// Import a module whose name is the string stored at [arg] in the constant
// table.
//
// Pushes null onto the stack so that the fiber for the imported module can
// replace that with a dummy value when it returns. (Fibers always return a
// value when resuming a caller.)
OPCODE(IMPORT_MODULE, 1)

// Import a variable from the most recently imported module. The name of the
// variable to import is at [arg] in the constant table. Pushes the loaded
// variable's value.
OPCODE(IMPORT_VARIABLE, 1)

// This pseudo-instruction indicates the end of the bytecode. It should
// always be preceded by a `CODE_RETURN`, so is never actually executed.
OPCODE(END, 0)
// End file "wren_opcodes.h"
    #undef OPCODE
  };

  #define INTERPRET_LOOP    DISPATCH();
  #define CASE_CODE(name)   code_##name

  #define DISPATCH()                                                           \
      do                                                                       \
      {                                                                        \
        DEBUG_TRACE_INSTRUCTIONS();                                            \
        goto *dispatchTable[instruction = (Code)READ_BYTE()];                  \
      } while (false)

  #else

  #define INTERPRET_LOOP                                                       \
      loop:                                                                    \
        DEBUG_TRACE_INSTRUCTIONS();                                            \
        switch (instruction = (Code)READ_BYTE())

  #define CASE_CODE(name)  case CODE_##name
  #define DISPATCH()       goto loop

  #endif

  LOAD_FRAME();

  Code instruction;
  INTERPRET_LOOP
  {
    CASE_CODE(LOAD_LOCAL_0):
    CASE_CODE(LOAD_LOCAL_1):
    CASE_CODE(LOAD_LOCAL_2):
    CASE_CODE(LOAD_LOCAL_3):
    CASE_CODE(LOAD_LOCAL_4):
    CASE_CODE(LOAD_LOCAL_5):
    CASE_CODE(LOAD_LOCAL_6):
    CASE_CODE(LOAD_LOCAL_7):
    CASE_CODE(LOAD_LOCAL_8):
      PUSH(stackStart[instruction - CODE_LOAD_LOCAL_0]);
      DISPATCH();

    CASE_CODE(LOAD_LOCAL):
      PUSH(stackStart[READ_BYTE()]);
      DISPATCH();

    CASE_CODE(LOAD_FIELD_THIS):
    {
      uint8_t field = READ_BYTE();
      Value receiver = stackStart[0];
      ASSERT(IS_INSTANCE(receiver), "Receiver should be instance.");
      ObjInstance* instance = AS_INSTANCE(receiver);
      ASSERT(field < instance->obj.classObj->numFields, "Out of bounds field.");
      PUSH(instance->fields[field]);
      DISPATCH();
    }

    CASE_CODE(POP):   DROP(); DISPATCH();
    CASE_CODE(NULL):  PUSH(NULL_VAL); DISPATCH();
    CASE_CODE(FALSE): PUSH(FALSE_VAL); DISPATCH();
    CASE_CODE(TRUE):  PUSH(TRUE_VAL); DISPATCH();

    CASE_CODE(STORE_LOCAL):
      stackStart[READ_BYTE()] = PEEK();
      DISPATCH();

    CASE_CODE(CONSTANT):
      PUSH(fn->constants.data[READ_SHORT()]);
      DISPATCH();

    {
      // The opcodes for doing method and superclass calls share a lot of code.
      // However, doing an if() test in the middle of the instruction sequence
      // to handle the bit that is special to super calls makes the non-super
      // call path noticeably slower.
      //
      // Instead, we do this old school using an explicit goto to share code for
      // everything at the tail end of the call-handling code that is the same
      // between normal and superclass calls.
      int numArgs;
      int symbol;

      Value* args;
      ObjClass* classObj;

      Method* method;

    CASE_CODE(CALL_0):
    CASE_CODE(CALL_1):
    CASE_CODE(CALL_2):
    CASE_CODE(CALL_3):
    CASE_CODE(CALL_4):
    CASE_CODE(CALL_5):
    CASE_CODE(CALL_6):
    CASE_CODE(CALL_7):
    CASE_CODE(CALL_8):
    CASE_CODE(CALL_9):
    CASE_CODE(CALL_10):
    CASE_CODE(CALL_11):
    CASE_CODE(CALL_12):
    CASE_CODE(CALL_13):
    CASE_CODE(CALL_14):
    CASE_CODE(CALL_15):
    CASE_CODE(CALL_16):
      // Add one for the implicit receiver argument.
      numArgs = instruction - CODE_CALL_0 + 1;
      symbol = READ_SHORT();

      // The receiver is the first argument.
      args = fiber->stackTop - numArgs;
      classObj = wrenGetClassInline(vm, args[0]);
      goto completeCall;

    CASE_CODE(SUPER_0):
    CASE_CODE(SUPER_1):
    CASE_CODE(SUPER_2):
    CASE_CODE(SUPER_3):
    CASE_CODE(SUPER_4):
    CASE_CODE(SUPER_5):
    CASE_CODE(SUPER_6):
    CASE_CODE(SUPER_7):
    CASE_CODE(SUPER_8):
    CASE_CODE(SUPER_9):
    CASE_CODE(SUPER_10):
    CASE_CODE(SUPER_11):
    CASE_CODE(SUPER_12):
    CASE_CODE(SUPER_13):
    CASE_CODE(SUPER_14):
    CASE_CODE(SUPER_15):
    CASE_CODE(SUPER_16):
      // Add one for the implicit receiver argument.
      numArgs = instruction - CODE_SUPER_0 + 1;
      symbol = READ_SHORT();

      // The receiver is the first argument.
      args = fiber->stackTop - numArgs;

      // The superclass is stored in a constant.
      classObj = AS_CLASS(fn->constants.data[READ_SHORT()]);
      goto completeCall;

    completeCall:
      // If the class's method table doesn't include the symbol, bail.
      if (symbol >= classObj->methods.count ||
          (method = &classObj->methods.data[symbol])->type == METHOD_NONE)
      {
        methodNotFound(vm, classObj, symbol);
        RUNTIME_ERROR();
      }

      switch (method->type)
      {
        case METHOD_PRIMITIVE:
          if (method->as.primitive(vm, args))
          {
            // The result is now in the first arg slot. Discard the other
            // stack slots.
            fiber->stackTop -= numArgs - 1;
          } else {
            // An error, fiber switch, or call frame change occurred.
            STORE_FRAME();

            // If we don't have a fiber to switch to, stop interpreting.
            fiber = vm->fiber;
            if (fiber == NULL) return WREN_RESULT_SUCCESS;
            if (wrenHasError(fiber)) RUNTIME_ERROR();
            LOAD_FRAME();
          }
          break;

        case METHOD_FUNCTION_CALL: 
          if (!checkArity(vm, args[0], numArgs)) {
            RUNTIME_ERROR();
            break;
          }

          STORE_FRAME();
          method->as.primitive(vm, args);
          LOAD_FRAME();
          break;

        case METHOD_FOREIGN:
          callForeign(vm, fiber, method->as.foreign, numArgs);
          if (wrenHasError(fiber)) RUNTIME_ERROR();
          break;

        case METHOD_BLOCK:
          STORE_FRAME();
          wrenCallFunction(vm, fiber, (ObjClosure*)method->as.closure, numArgs);
          LOAD_FRAME();
          break;

        case METHOD_NONE:
          UNREACHABLE();
          break;
      }
      DISPATCH();
    }

    CASE_CODE(LOAD_UPVALUE):
    {
      ObjUpvalue** upvalues = frame->closure->upvalues;
      PUSH(*upvalues[READ_BYTE()]->value);
      DISPATCH();
    }

    CASE_CODE(STORE_UPVALUE):
    {
      ObjUpvalue** upvalues = frame->closure->upvalues;
      *upvalues[READ_BYTE()]->value = PEEK();
      DISPATCH();
    }

    CASE_CODE(LOAD_MODULE_VAR):
      PUSH(fn->module->variables.data[READ_SHORT()]);
      DISPATCH();

    CASE_CODE(STORE_MODULE_VAR):
      fn->module->variables.data[READ_SHORT()] = PEEK();
      DISPATCH();

    CASE_CODE(STORE_FIELD_THIS):
    {
      uint8_t field = READ_BYTE();
      Value receiver = stackStart[0];
      ASSERT(IS_INSTANCE(receiver), "Receiver should be instance.");
      ObjInstance* instance = AS_INSTANCE(receiver);
      ASSERT(field < instance->obj.classObj->numFields, "Out of bounds field.");
      instance->fields[field] = PEEK();
      DISPATCH();
    }

    CASE_CODE(LOAD_FIELD):
    {
      uint8_t field = READ_BYTE();
      Value receiver = POP();
      ASSERT(IS_INSTANCE(receiver), "Receiver should be instance.");
      ObjInstance* instance = AS_INSTANCE(receiver);
      ASSERT(field < instance->obj.classObj->numFields, "Out of bounds field.");
      PUSH(instance->fields[field]);
      DISPATCH();
    }

    CASE_CODE(STORE_FIELD):
    {
      uint8_t field = READ_BYTE();
      Value receiver = POP();
      ASSERT(IS_INSTANCE(receiver), "Receiver should be instance.");
      ObjInstance* instance = AS_INSTANCE(receiver);
      ASSERT(field < instance->obj.classObj->numFields, "Out of bounds field.");
      instance->fields[field] = PEEK();
      DISPATCH();
    }

    CASE_CODE(JUMP):
    {
      uint16_t offset = READ_SHORT();
      ip += offset;
      DISPATCH();
    }

    CASE_CODE(LOOP):
    {
      // Jump back to the top of the loop.
      uint16_t offset = READ_SHORT();
      ip -= offset;
      DISPATCH();
    }

    CASE_CODE(JUMP_IF):
    {
      uint16_t offset = READ_SHORT();
      Value condition = POP();

      if (wrenIsFalsyValue(condition)) ip += offset;
      DISPATCH();
    }

    CASE_CODE(AND):
    {
      uint16_t offset = READ_SHORT();
      Value condition = PEEK();

      if (wrenIsFalsyValue(condition))
      {
        // Short-circuit the right hand side.
        ip += offset;
      }
      else
      {
        // Discard the condition and evaluate the right hand side.
        DROP();
      }
      DISPATCH();
    }

    CASE_CODE(OR):
    {
      uint16_t offset = READ_SHORT();
      Value condition = PEEK();

      if (wrenIsFalsyValue(condition))
      {
        // Discard the condition and evaluate the right hand side.
        DROP();
      }
      else
      {
        // Short-circuit the right hand side.
        ip += offset;
      }
      DISPATCH();
    }

    CASE_CODE(CLOSE_UPVALUE):
      // Close the upvalue for the local if we have one.
      closeUpvalues(fiber, fiber->stackTop - 1);
      DROP();
      DISPATCH();

    CASE_CODE(RETURN):
    {
      Value result = POP();
      fiber->numFrames--;

      // Close any upvalues still in scope.
      closeUpvalues(fiber, stackStart);

      // If the fiber is complete, end it.
      if (fiber->numFrames == 0)
      {
        // See if there's another fiber to return to. If not, we're done.
        if (fiber->caller == NULL)
        {
          // Store the final result value at the beginning of the stack so the
          // C API can get it.
          fiber->stack[0] = result;
          fiber->stackTop = fiber->stack + 1;
          return WREN_RESULT_SUCCESS;
        }
        
        ObjFiber* resumingFiber = fiber->caller;
        fiber->caller = NULL;
        fiber = resumingFiber;
        vm->fiber = resumingFiber;
        
        // Store the result in the resuming fiber.
        fiber->stackTop[-1] = result;
      }
      else
      {
        // Store the result of the block in the first slot, which is where the
        // caller expects it.
        stackStart[0] = result;

        // Discard the stack slots for the call frame (leaving one slot for the
        // result).
        fiber->stackTop = frame->stackStart + 1;
      }
      
      LOAD_FRAME();
      DISPATCH();
    }

    CASE_CODE(CONSTRUCT):
      ASSERT(IS_CLASS(stackStart[0]), "'this' should be a class.");
      stackStart[0] = wrenNewInstance(vm, AS_CLASS(stackStart[0]));
      DISPATCH();

    CASE_CODE(FOREIGN_CONSTRUCT):
      ASSERT(IS_CLASS(stackStart[0]), "'this' should be a class.");
      createForeign(vm, fiber, stackStart);
      if (wrenHasError(fiber)) RUNTIME_ERROR();
      DISPATCH();

    CASE_CODE(CLOSURE):
    {
      // Create the closure and push it on the stack before creating upvalues
      // so that it doesn't get collected.
      ObjFn* function = AS_FN(fn->constants.data[READ_SHORT()]);
      ObjClosure* closure = wrenNewClosure(vm, function);
      PUSH(OBJ_VAL(closure));

      // Capture upvalues, if any.
      for (int i = 0; i < function->numUpvalues; i++)
      {
        uint8_t isLocal = READ_BYTE();
        uint8_t index = READ_BYTE();
        if (isLocal)
        {
          // Make an new upvalue to close over the parent's local variable.
          closure->upvalues[i] = captureUpvalue(vm, fiber,
                                                frame->stackStart + index);
        }
        else
        {
          // Use the same upvalue as the current call frame.
          closure->upvalues[i] = frame->closure->upvalues[index];
        }
      }
      DISPATCH();
    }

    CASE_CODE(END_CLASS):
    {
      endClass(vm);
      if (wrenHasError(fiber)) RUNTIME_ERROR();
      DISPATCH();
    }

    CASE_CODE(CLASS):
    {
      createClass(vm, READ_BYTE(), NULL);
      if (wrenHasError(fiber)) RUNTIME_ERROR();
      DISPATCH();
    }

    CASE_CODE(FOREIGN_CLASS):
    {
      createClass(vm, -1, fn->module);
      if (wrenHasError(fiber)) RUNTIME_ERROR();
      DISPATCH();
    }

    CASE_CODE(METHOD_INSTANCE):
    CASE_CODE(METHOD_STATIC):
    {
      uint16_t symbol = READ_SHORT();
      ObjClass* classObj = AS_CLASS(PEEK());
      Value method = PEEK2();
      bindMethod(vm, instruction, symbol, fn->module, classObj, method);
      if (wrenHasError(fiber)) RUNTIME_ERROR();
      DROP();
      DROP();
      DISPATCH();
    }
    
    CASE_CODE(END_MODULE):
    {
      vm->lastModule = fn->module;
      PUSH(NULL_VAL);
      DISPATCH();
    }
    
    CASE_CODE(IMPORT_MODULE):
    {
      // Make a slot on the stack for the module's fiber to place the return
      // value. It will be popped after this fiber is resumed. Store the
      // imported module's closure in the slot in case a GC happens when
      // invoking the closure.
      PUSH(importModule(vm, fn->constants.data[READ_SHORT()]));
      if (wrenHasError(fiber)) RUNTIME_ERROR();
      
      // If we get a closure, call it to execute the module body.
      if (IS_CLOSURE(PEEK()))
      {
        STORE_FRAME();
        ObjClosure* closure = AS_CLOSURE(PEEK());
        wrenCallFunction(vm, fiber, closure, 1);
        LOAD_FRAME();
      }
      else
      {
        // The module has already been loaded. Remember it so we can import
        // variables from it if needed.
        vm->lastModule = AS_MODULE(PEEK());
      }

      DISPATCH();
    }
    
    CASE_CODE(IMPORT_VARIABLE):
    {
      Value variable = fn->constants.data[READ_SHORT()];
      ASSERT(vm->lastModule != NULL, "Should have already imported module.");
      Value result = getModuleVariable(vm, vm->lastModule, variable);
      if (wrenHasError(fiber)) RUNTIME_ERROR();

      PUSH(result);
      DISPATCH();
    }

    CASE_CODE(END):
      // A CODE_END should always be preceded by a CODE_RETURN. If we get here,
      // the compiler generated wrong code.
      UNREACHABLE();
  }

  // We should only exit this function from an explicit return from CODE_RETURN
  // or a runtime error.
  UNREACHABLE();
  return WREN_RESULT_RUNTIME_ERROR;

  #undef READ_BYTE
  #undef READ_SHORT
}

WrenHandle* wrenMakeCallHandle(WrenVM* vm, const char* signature)
{
  ASSERT(signature != NULL, "Signature cannot be NULL.");
  
  int signatureLength = (int)strlen(signature);
  ASSERT(signatureLength > 0, "Signature cannot be empty.");
  
  // Count the number parameters the method expects.
  int numParams = 0;
  if (signature[signatureLength - 1] == ')')
  {
    for (int i = signatureLength - 1; i > 0 && signature[i] != '('; i--)
    {
      if (signature[i] == '_') numParams++;
    }
  }
  
  // Count subscript arguments.
  if (signature[0] == '[')
  {
    for (int i = 0; i < signatureLength && signature[i] != ']'; i++)
    {
      if (signature[i] == '_') numParams++;
    }
  }
  
  // Add the signatue to the method table.
  int method =  wrenSymbolTableEnsure(vm, &vm->methodNames,
                                      signature, signatureLength);
  
  // Create a little stub function that assumes the arguments are on the stack
  // and calls the method.
  ObjFn* fn = wrenNewFunction(vm, NULL, numParams + 1);
  
  // Wrap the function in a closure and then in a handle. Do this here so it
  // doesn't get collected as we fill it in.
  WrenHandle* value = wrenMakeHandle(vm, OBJ_VAL(fn));
  value->value = OBJ_VAL(wrenNewClosure(vm, fn));
  
  wrenByteBufferWrite(vm, &fn->code, (uint8_t)(CODE_CALL_0 + numParams));
  wrenByteBufferWrite(vm, &fn->code, (method >> 8) & 0xff);
  wrenByteBufferWrite(vm, &fn->code, method & 0xff);
  wrenByteBufferWrite(vm, &fn->code, CODE_RETURN);
  wrenByteBufferWrite(vm, &fn->code, CODE_END);
  wrenIntBufferFill(vm, &fn->debug->sourceLines, 0, 5);
  wrenFunctionBindName(vm, fn, signature, signatureLength);

  return value;
}

WrenInterpretResult wrenCall(WrenVM* vm, WrenHandle* method)
{
  ASSERT(method != NULL, "Method cannot be NULL.");
  ASSERT(IS_CLOSURE(method->value), "Method must be a method handle.");
  ASSERT(vm->fiber != NULL, "Must set up arguments for call first.");
  ASSERT(vm->apiStack != NULL, "Must set up arguments for call first.");
  ASSERT(vm->fiber->numFrames == 0, "Can not call from a foreign method.");
  
  ObjClosure* closure = AS_CLOSURE(method->value);
  
  ASSERT(vm->fiber->stackTop - vm->fiber->stack >= closure->fn->arity,
         "Stack must have enough arguments for method.");
  
  // Clear the API stack. Now that wrenCall() has control, we no longer need
  // it. We use this being non-null to tell if re-entrant calls to foreign
  // methods are happening, so it's important to clear it out now so that you
  // can call foreign methods from within calls to wrenCall().
  vm->apiStack = NULL;

  // Discard any extra temporary slots. We take for granted that the stub
  // function has exactly one slot for each argument.
  vm->fiber->stackTop = &vm->fiber->stack[closure->fn->maxSlots];
  
  wrenCallFunction(vm, vm->fiber, closure, 0);
  WrenInterpretResult result = runInterpreter(vm, vm->fiber);
  
  // If the call didn't abort, then set up the API stack to point to the
  // beginning of the stack so the host can access the call's return value.
  if (vm->fiber != NULL) vm->apiStack = vm->fiber->stack;
  
  return result;
}

WrenHandle* wrenMakeHandle(WrenVM* vm, Value value)
{
  if (IS_OBJ(value)) wrenPushRoot(vm, AS_OBJ(value));
  
  // Make a handle for it.
  WrenHandle* handle = ALLOCATE(vm, WrenHandle);
  handle->value = value;

  if (IS_OBJ(value)) wrenPopRoot(vm);

  // Add it to the front of the linked list of handles.
  if (vm->handles != NULL) vm->handles->prev = handle;
  handle->prev = NULL;
  handle->next = vm->handles;
  vm->handles = handle;
  
  return handle;
}

void wrenReleaseHandle(WrenVM* vm, WrenHandle* handle)
{
  ASSERT(handle != NULL, "Handle cannot be NULL.");

  // Update the VM's head pointer if we're releasing the first handle.
  if (vm->handles == handle) vm->handles = handle->next;

  // Unlink it from the list.
  if (handle->prev != NULL) handle->prev->next = handle->next;
  if (handle->next != NULL) handle->next->prev = handle->prev;

  // Clear it out. This isn't strictly necessary since we're going to free it,
  // but it makes for easier debugging.
  handle->prev = NULL;
  handle->next = NULL;
  handle->value = NULL_VAL;
  DEALLOCATE(vm, handle);
}

WrenInterpretResult wrenInterpret(WrenVM* vm, const char* module,
                                  const char* source)
{
  ObjClosure* closure = wrenCompileSource(vm, module, source, false, true);
  if (closure == NULL) return WREN_RESULT_COMPILE_ERROR;
  
  wrenPushRoot(vm, (Obj*)closure);
  ObjFiber* fiber = wrenNewFiber(vm, closure);
  wrenPopRoot(vm); // closure.
  vm->apiStack = NULL;

  return runInterpreter(vm, fiber);
}

ObjClosure* wrenCompileSource(WrenVM* vm, const char* module, const char* source,
                            bool isExpression, bool printErrors)
{
  Value nameValue = NULL_VAL;
  if (module != NULL)
  {
    nameValue = wrenNewString(vm, module);
    wrenPushRoot(vm, AS_OBJ(nameValue));
  }
  
  ObjClosure* closure = compileInModule(vm, nameValue, source,
                                        isExpression, printErrors);

  if (module != NULL) wrenPopRoot(vm); // nameValue.
  return closure;
}

Value wrenGetModuleVariable(WrenVM* vm, Value moduleName, Value variableName)
{
  ObjModule* module = getModule(vm, moduleName);
  if (module == NULL)
  {
    vm->fiber->error = wrenStringFormat(vm, "Module '@' is not loaded.",
                                        moduleName);
    return NULL_VAL;
  }
  
  return getModuleVariable(vm, module, variableName);
}

Value wrenFindVariable(WrenVM* vm, ObjModule* module, const char* name)
{
  int symbol = wrenSymbolTableFind(&module->variableNames, name, strlen(name));
  return module->variables.data[symbol];
}

int wrenDeclareVariable(WrenVM* vm, ObjModule* module, const char* name,
                        size_t length, int line)
{
  if (module->variables.count == MAX_MODULE_VARS) return -2;

  // Implicitly defined variables get a "value" that is the line where the
  // variable is first used. We'll use that later to report an error on the
  // right line.
  wrenValueBufferWrite(vm, &module->variables, NUM_VAL(line));
  return wrenSymbolTableAdd(vm, &module->variableNames, name, length);
}

int wrenDefineVariable(WrenVM* vm, ObjModule* module, const char* name,
                       size_t length, Value value, int* line)
{
  if (module->variables.count == MAX_MODULE_VARS) return -2;

  if (IS_OBJ(value)) wrenPushRoot(vm, AS_OBJ(value));

  // See if the variable is already explicitly or implicitly declared.
  int symbol = wrenSymbolTableFind(&module->variableNames, name, length);

  if (symbol == -1)
  {
    // Brand new variable.
    symbol = wrenSymbolTableAdd(vm, &module->variableNames, name, length);
    wrenValueBufferWrite(vm, &module->variables, value);
  }
  else if (IS_NUM(module->variables.data[symbol]))
  {
    // An implicitly declared variable's value will always be a number.
    // Now we have a real definition.
    if(line) *line = (int)AS_NUM(module->variables.data[symbol]);
    module->variables.data[symbol] = value;

	// If this was a localname we want to error if it was 
	// referenced before this definition.
	if (wrenIsLocalName(name)) symbol = -3;
  }
  else
  {
    // Already explicitly declared.
    symbol = -1;
  }

  if (IS_OBJ(value)) wrenPopRoot(vm);

  return symbol;
}

// TODO: Inline?
void wrenPushRoot(WrenVM* vm, Obj* obj)
{
  ASSERT(obj != NULL, "Can't root NULL.");
  ASSERT(vm->numTempRoots < WREN_MAX_TEMP_ROOTS, "Too many temporary roots.");

  vm->tempRoots[vm->numTempRoots++] = obj;
}

void wrenPopRoot(WrenVM* vm)
{
  ASSERT(vm->numTempRoots > 0, "No temporary roots to release.");
  vm->numTempRoots--;
}

int wrenGetSlotCount(WrenVM* vm)
{
  if (vm->apiStack == NULL) return 0;
  
  return (int)(vm->fiber->stackTop - vm->apiStack);
}

void wrenEnsureSlots(WrenVM* vm, int numSlots)
{
  // If we don't have a fiber accessible, create one for the API to use.
  if (vm->apiStack == NULL)
  {
    vm->fiber = wrenNewFiber(vm, NULL);
    vm->apiStack = vm->fiber->stack;
  }
  
  int currentSize = (int)(vm->fiber->stackTop - vm->apiStack);
  if (currentSize >= numSlots) return;
  
  // Grow the stack if needed.
  int needed = (int)(vm->apiStack - vm->fiber->stack) + numSlots;
  wrenEnsureStack(vm, vm->fiber, needed);
  
  vm->fiber->stackTop = vm->apiStack + numSlots;
}

// Ensures that [slot] is a valid index into the API's stack of slots.
static void validateApiSlot(WrenVM* vm, int slot)
{
  ASSERT(slot >= 0, "Slot cannot be negative.");
  ASSERT(slot < wrenGetSlotCount(vm), "Not that many slots.");
}

// Gets the type of the object in [slot].
WrenType wrenGetSlotType(WrenVM* vm, int slot)
{
  validateApiSlot(vm, slot);
  if (IS_BOOL(vm->apiStack[slot])) return WREN_TYPE_BOOL;
  if (IS_NUM(vm->apiStack[slot])) return WREN_TYPE_NUM;
  if (IS_FOREIGN(vm->apiStack[slot])) return WREN_TYPE_FOREIGN;
  if (IS_LIST(vm->apiStack[slot])) return WREN_TYPE_LIST;
  if (IS_MAP(vm->apiStack[slot])) return WREN_TYPE_MAP;
  if (IS_NULL(vm->apiStack[slot])) return WREN_TYPE_NULL;
  if (IS_STRING(vm->apiStack[slot])) return WREN_TYPE_STRING;
  
  return WREN_TYPE_UNKNOWN;
}

bool wrenGetSlotBool(WrenVM* vm, int slot)
{
  validateApiSlot(vm, slot);
  ASSERT(IS_BOOL(vm->apiStack[slot]), "Slot must hold a bool.");

  return AS_BOOL(vm->apiStack[slot]);
}

const char* wrenGetSlotBytes(WrenVM* vm, int slot, int* length)
{
  validateApiSlot(vm, slot);
  ASSERT(IS_STRING(vm->apiStack[slot]), "Slot must hold a string.");
  
  ObjString* string = AS_STRING(vm->apiStack[slot]);
  *length = string->length;
  return string->value;
}

double wrenGetSlotDouble(WrenVM* vm, int slot)
{
  validateApiSlot(vm, slot);
  ASSERT(IS_NUM(vm->apiStack[slot]), "Slot must hold a number.");

  return AS_NUM(vm->apiStack[slot]);
}

void* wrenGetSlotForeign(WrenVM* vm, int slot)
{
  validateApiSlot(vm, slot);
  ASSERT(IS_FOREIGN(vm->apiStack[slot]),
         "Slot must hold a foreign instance.");

  return AS_FOREIGN(vm->apiStack[slot])->data;
}

const char* wrenGetSlotString(WrenVM* vm, int slot)
{
  validateApiSlot(vm, slot);
  ASSERT(IS_STRING(vm->apiStack[slot]), "Slot must hold a string.");

  return AS_CSTRING(vm->apiStack[slot]);
}

WrenHandle* wrenGetSlotHandle(WrenVM* vm, int slot)
{
  validateApiSlot(vm, slot);
  return wrenMakeHandle(vm, vm->apiStack[slot]);
}

// Stores [value] in [slot] in the foreign call stack.
static void setSlot(WrenVM* vm, int slot, Value value)
{
  validateApiSlot(vm, slot);
  vm->apiStack[slot] = value;
}

void wrenSetSlotBool(WrenVM* vm, int slot, bool value)
{
  setSlot(vm, slot, BOOL_VAL(value));
}

void wrenSetSlotBytes(WrenVM* vm, int slot, const char* bytes, size_t length)
{
  ASSERT(bytes != NULL, "Byte array cannot be NULL.");
  setSlot(vm, slot, wrenNewStringLength(vm, bytes, length));
}

void wrenSetSlotDouble(WrenVM* vm, int slot, double value)
{
  setSlot(vm, slot, NUM_VAL(value));
}

void* wrenSetSlotNewForeign(WrenVM* vm, int slot, int classSlot, size_t size)
{
  validateApiSlot(vm, slot);
  validateApiSlot(vm, classSlot);
  ASSERT(IS_CLASS(vm->apiStack[classSlot]), "Slot must hold a class.");
  
  ObjClass* classObj = AS_CLASS(vm->apiStack[classSlot]);
  ASSERT(classObj->numFields == -1, "Class must be a foreign class.");
  
  ObjForeign* foreign = wrenNewForeign(vm, classObj, size);
  vm->apiStack[slot] = OBJ_VAL(foreign);
  
  return (void*)foreign->data;
}

void wrenSetSlotNewList(WrenVM* vm, int slot)
{
  setSlot(vm, slot, OBJ_VAL(wrenNewList(vm, 0)));
}

void wrenSetSlotNewMap(WrenVM* vm, int slot)
{
  setSlot(vm, slot, OBJ_VAL(wrenNewMap(vm)));
}

void wrenSetSlotNull(WrenVM* vm, int slot)
{
  setSlot(vm, slot, NULL_VAL);
}

void wrenSetSlotString(WrenVM* vm, int slot, const char* text)
{
  ASSERT(text != NULL, "String cannot be NULL.");
  
  setSlot(vm, slot, wrenNewString(vm, text));
}

void wrenSetSlotHandle(WrenVM* vm, int slot, WrenHandle* handle)
{
  ASSERT(handle != NULL, "Handle cannot be NULL.");

  setSlot(vm, slot, handle->value);
}

int wrenGetListCount(WrenVM* vm, int slot)
{
  validateApiSlot(vm, slot);
  ASSERT(IS_LIST(vm->apiStack[slot]), "Slot must hold a list.");
  
  ValueBuffer elements = AS_LIST(vm->apiStack[slot])->elements;
  return elements.count;
}

void wrenGetListElement(WrenVM* vm, int listSlot, int index, int elementSlot)
{
  validateApiSlot(vm, listSlot);
  validateApiSlot(vm, elementSlot);
  ASSERT(IS_LIST(vm->apiStack[listSlot]), "Slot must hold a list.");

  ValueBuffer elements = AS_LIST(vm->apiStack[listSlot])->elements;

  uint32_t usedIndex = wrenValidateIndex(elements.count, index);
  ASSERT(usedIndex != UINT32_MAX, "Index out of bounds.");

  vm->apiStack[elementSlot] = elements.data[usedIndex];
}

void wrenSetListElement(WrenVM* vm, int listSlot, int index, int elementSlot)
{
  validateApiSlot(vm, listSlot);
  validateApiSlot(vm, elementSlot);
  ASSERT(IS_LIST(vm->apiStack[listSlot]), "Slot must hold a list.");

  ObjList* list = AS_LIST(vm->apiStack[listSlot]);

  uint32_t usedIndex = wrenValidateIndex(list->elements.count, index);
  ASSERT(usedIndex != UINT32_MAX, "Index out of bounds.");
  
  list->elements.data[usedIndex] = vm->apiStack[elementSlot];
}

void wrenInsertInList(WrenVM* vm, int listSlot, int index, int elementSlot)
{
  validateApiSlot(vm, listSlot);
  validateApiSlot(vm, elementSlot);
  ASSERT(IS_LIST(vm->apiStack[listSlot]), "Must insert into a list.");
  
  ObjList* list = AS_LIST(vm->apiStack[listSlot]);
  
  // Negative indices count from the end. 
  // We don't use wrenValidateIndex here because insert allows 1 past the end.
  if (index < 0) index = list->elements.count + 1 + index;
  
  ASSERT(index <= list->elements.count, "Index out of bounds.");
  
  wrenListInsert(vm, list, vm->apiStack[elementSlot], index);
}

int wrenGetMapCount(WrenVM* vm, int slot)
{
  validateApiSlot(vm, slot);
  ASSERT(IS_MAP(vm->apiStack[slot]), "Slot must hold a map.");

  ObjMap* map = AS_MAP(vm->apiStack[slot]);
  return map->count;
}

bool wrenGetMapContainsKey(WrenVM* vm, int mapSlot, int keySlot)
{
  validateApiSlot(vm, mapSlot);
  validateApiSlot(vm, keySlot);
  ASSERT(IS_MAP(vm->apiStack[mapSlot]), "Slot must hold a map.");

  Value key = vm->apiStack[keySlot];
  ASSERT(wrenMapIsValidKey(key), "Key must be a value type");
  if (!validateKey(vm, key)) return false;

  ObjMap* map = AS_MAP(vm->apiStack[mapSlot]);
  Value value = wrenMapGet(map, key);

  return !IS_UNDEFINED(value);
}

void wrenGetMapValue(WrenVM* vm, int mapSlot, int keySlot, int valueSlot)
{
  validateApiSlot(vm, mapSlot);
  validateApiSlot(vm, keySlot);
  validateApiSlot(vm, valueSlot);
  ASSERT(IS_MAP(vm->apiStack[mapSlot]), "Slot must hold a map.");

  ObjMap* map = AS_MAP(vm->apiStack[mapSlot]);
  Value value = wrenMapGet(map, vm->apiStack[keySlot]);
  if (IS_UNDEFINED(value)) {
    value = NULL_VAL;
  }

  vm->apiStack[valueSlot] = value;
}

void wrenSetMapValue(WrenVM* vm, int mapSlot, int keySlot, int valueSlot)
{
  validateApiSlot(vm, mapSlot);
  validateApiSlot(vm, keySlot);
  validateApiSlot(vm, valueSlot);
  ASSERT(IS_MAP(vm->apiStack[mapSlot]), "Must insert into a map.");
  
  Value key = vm->apiStack[keySlot];
  ASSERT(wrenMapIsValidKey(key), "Key must be a value type");

  if (!validateKey(vm, key)) {
    return;
  }

  Value value = vm->apiStack[valueSlot];
  ObjMap* map = AS_MAP(vm->apiStack[mapSlot]);
  
  wrenMapSet(vm, map, key, value);
}

void wrenRemoveMapValue(WrenVM* vm, int mapSlot, int keySlot, 
                        int removedValueSlot)
{
  validateApiSlot(vm, mapSlot);
  validateApiSlot(vm, keySlot);
  ASSERT(IS_MAP(vm->apiStack[mapSlot]), "Slot must hold a map.");

  Value key = vm->apiStack[keySlot];
  if (!validateKey(vm, key)) {
    return;
  }

  ObjMap* map = AS_MAP(vm->apiStack[mapSlot]);
  Value removed = wrenMapRemoveKey(vm, map, key);
  setSlot(vm, removedValueSlot, removed);
}

void wrenGetVariable(WrenVM* vm, const char* module, const char* name,
                     int slot)
{
  ASSERT(module != NULL, "Module cannot be NULL.");
  ASSERT(name != NULL, "Variable name cannot be NULL.");  

  Value moduleName = wrenStringFormat(vm, "$", module);
  wrenPushRoot(vm, AS_OBJ(moduleName));
  
  ObjModule* moduleObj = getModule(vm, moduleName);
  ASSERT(moduleObj != NULL, "Could not find module.");
  
  wrenPopRoot(vm); // moduleName.

  int variableSlot = wrenSymbolTableFind(&moduleObj->variableNames,
                                         name, strlen(name));
  ASSERT(variableSlot != -1, "Could not find variable.");
  
  setSlot(vm, slot, moduleObj->variables.data[variableSlot]);
}

bool wrenHasVariable(WrenVM* vm, const char* module, const char* name)
{
  ASSERT(module != NULL, "Module cannot be NULL.");
  ASSERT(name != NULL, "Variable name cannot be NULL.");

  Value moduleName = wrenStringFormat(vm, "$", module);
  wrenPushRoot(vm, AS_OBJ(moduleName));

  //We don't use wrenHasModule since we want to use the module object.
  ObjModule* moduleObj = getModule(vm, moduleName);
  ASSERT(moduleObj != NULL, "Could not find module.");

  wrenPopRoot(vm); // moduleName.

  int variableSlot = wrenSymbolTableFind(&moduleObj->variableNames,
    name, strlen(name));

  return variableSlot != -1;
}

bool wrenHasModule(WrenVM* vm, const char* module)
{
  ASSERT(module != NULL, "Module cannot be NULL.");
  
  Value moduleName = wrenStringFormat(vm, "$", module);
  wrenPushRoot(vm, AS_OBJ(moduleName));

  ObjModule* moduleObj = getModule(vm, moduleName);
  
  wrenPopRoot(vm); // moduleName.

  return moduleObj != NULL;
}

void wrenAbortFiber(WrenVM* vm, int slot)
{
  validateApiSlot(vm, slot);
  vm->fiber->error = vm->apiStack[slot];
}

void* wrenGetUserData(WrenVM* vm)
{
	return vm->config.userData;
}

void wrenSetUserData(WrenVM* vm, void* userData)
{
	vm->config.userData = userData;
}
// End file "wren_vm.c"
// Begin file "wren_value.c"
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>


#if WREN_DEBUG_TRACE_MEMORY
#endif

// TODO: Tune these.
// The initial (and minimum) capacity of a non-empty list or map object.
#define MIN_CAPACITY 16

// The rate at which a collection's capacity grows when the size exceeds the
// current capacity. The new capacity will be determined by *multiplying* the
// old capacity by this. Growing geometrically is necessary to ensure that
// adding to a collection has O(1) amortized complexity.
#define GROW_FACTOR 2

// The maximum percentage of map entries that can be filled before the map is
// grown. A lower load takes more memory but reduces collisions which makes
// lookup faster.
#define MAP_LOAD_PERCENT 75

// The number of call frames initially allocated when a fiber is created. Making
// this smaller makes fibers use less memory (at first) but spends more time
// reallocating when the call stack grows.
#define INITIAL_CALL_FRAMES 4

DEFINE_BUFFER(Value, Value);
DEFINE_BUFFER(Method, Method);

static void initObj(WrenVM* vm, Obj* obj, ObjType type, ObjClass* classObj)
{
  obj->type = type;
  obj->isDark = false;
  obj->classObj = classObj;
  obj->next = vm->first;
  vm->first = obj;
}

ObjClass* wrenNewSingleClass(WrenVM* vm, int numFields, ObjString* name)
{
  ObjClass* classObj = ALLOCATE(vm, ObjClass);
  initObj(vm, &classObj->obj, OBJ_CLASS, NULL);
  classObj->superclass = NULL;
  classObj->numFields = numFields;
  classObj->name = name;
  classObj->attributes = NULL_VAL;

  wrenPushRoot(vm, (Obj*)classObj);
  wrenMethodBufferInit(&classObj->methods);
  wrenPopRoot(vm);

  return classObj;
}

void wrenBindSuperclass(WrenVM* vm, ObjClass* subclass, ObjClass* superclass)
{
  ASSERT(superclass != NULL, "Must have superclass.");

  subclass->superclass = superclass;

  // Include the superclass in the total number of fields.
  if (subclass->numFields != -1)
  {
    subclass->numFields += superclass->numFields;
  }
  else
  {
    ASSERT(superclass->numFields == 0,
           "A foreign class cannot inherit from a class with fields.");
  }

  // Inherit methods from its superclass.
  for (int i = 0; i < superclass->methods.count; i++)
  {
    wrenBindMethod(vm, subclass, i, superclass->methods.data[i]);
  }
}

ObjClass* wrenNewClass(WrenVM* vm, ObjClass* superclass, int numFields,
                       ObjString* name)
{
  // Create the metaclass.
  Value metaclassName = wrenStringFormat(vm, "@ metaclass", OBJ_VAL(name));
  wrenPushRoot(vm, AS_OBJ(metaclassName));

  ObjClass* metaclass = wrenNewSingleClass(vm, 0, AS_STRING(metaclassName));
  metaclass->obj.classObj = vm->classClass;

  wrenPopRoot(vm);

  // Make sure the metaclass isn't collected when we allocate the class.
  wrenPushRoot(vm, (Obj*)metaclass);

  // Metaclasses always inherit Class and do not parallel the non-metaclass
  // hierarchy.
  wrenBindSuperclass(vm, metaclass, vm->classClass);

  ObjClass* classObj = wrenNewSingleClass(vm, numFields, name);

  // Make sure the class isn't collected while the inherited methods are being
  // bound.
  wrenPushRoot(vm, (Obj*)classObj);

  classObj->obj.classObj = metaclass;
  wrenBindSuperclass(vm, classObj, superclass);

  wrenPopRoot(vm);
  wrenPopRoot(vm);

  return classObj;
}

void wrenBindMethod(WrenVM* vm, ObjClass* classObj, int symbol, Method method)
{
  // Make sure the buffer is big enough to contain the symbol's index.
  if (symbol >= classObj->methods.count)
  {
    Method noMethod;
    noMethod.type = METHOD_NONE;
    wrenMethodBufferFill(vm, &classObj->methods, noMethod,
                         symbol - classObj->methods.count + 1);
  }

  classObj->methods.data[symbol] = method;
}

ObjClosure* wrenNewClosure(WrenVM* vm, ObjFn* fn)
{
  ObjClosure* closure = ALLOCATE_FLEX(vm, ObjClosure,
                                      ObjUpvalue*, fn->numUpvalues);
  initObj(vm, &closure->obj, OBJ_CLOSURE, vm->fnClass);

  closure->fn = fn;

  // Clear the upvalue array. We need to do this in case a GC is triggered
  // after the closure is created but before the upvalue array is populated.
  for (int i = 0; i < fn->numUpvalues; i++) closure->upvalues[i] = NULL;

  return closure;
}

ObjFiber* wrenNewFiber(WrenVM* vm, ObjClosure* closure)
{
  // Allocate the arrays before the fiber in case it triggers a GC.
  CallFrame* frames = ALLOCATE_ARRAY(vm, CallFrame, INITIAL_CALL_FRAMES);
  
  // Add one slot for the unused implicit receiver slot that the compiler
  // assumes all functions have.
  int stackCapacity = closure == NULL
      ? 1
      : wrenPowerOf2Ceil(closure->fn->maxSlots + 1);
  Value* stack = ALLOCATE_ARRAY(vm, Value, stackCapacity);
  
  ObjFiber* fiber = ALLOCATE(vm, ObjFiber);
  initObj(vm, &fiber->obj, OBJ_FIBER, vm->fiberClass);

  fiber->stack = stack;
  fiber->stackTop = fiber->stack;
  fiber->stackCapacity = stackCapacity;

  fiber->frames = frames;
  fiber->frameCapacity = INITIAL_CALL_FRAMES;
  fiber->numFrames = 0;

  fiber->openUpvalues = NULL;
  fiber->caller = NULL;
  fiber->error = NULL_VAL;
  fiber->state = FIBER_OTHER;
  
  if (closure != NULL)
  {
    // Initialize the first call frame.
    wrenAppendCallFrame(vm, fiber, closure, fiber->stack);

    // The first slot always holds the closure.
    fiber->stackTop[0] = OBJ_VAL(closure);
    fiber->stackTop++;
  }
  
  return fiber;
}

void wrenEnsureStack(WrenVM* vm, ObjFiber* fiber, int needed)
{
  if (fiber->stackCapacity >= needed) return;
  
  int capacity = wrenPowerOf2Ceil(needed);
  
  Value* oldStack = fiber->stack;
  fiber->stack = (Value*)wrenReallocate(vm, fiber->stack,
                                        sizeof(Value) * fiber->stackCapacity,
                                        sizeof(Value) * capacity);
  fiber->stackCapacity = capacity;
  
  // If the reallocation moves the stack, then we need to recalculate every
  // pointer that points into the old stack to into the same relative distance
  // in the new stack. We have to be a little careful about how these are
  // calculated because pointer subtraction is only well-defined within a
  // single array, hence the slightly redundant-looking arithmetic below.
  if (fiber->stack != oldStack)
  {
    // Top of the stack.
    if (vm->apiStack >= oldStack && vm->apiStack <= fiber->stackTop)
    {
      vm->apiStack = fiber->stack + (vm->apiStack - oldStack);
    }
    
    // Stack pointer for each call frame.
    for (int i = 0; i < fiber->numFrames; i++)
    {
      CallFrame* frame = &fiber->frames[i];
      frame->stackStart = fiber->stack + (frame->stackStart - oldStack);
    }
    
    // Open upvalues.
    for (ObjUpvalue* upvalue = fiber->openUpvalues;
         upvalue != NULL;
         upvalue = upvalue->next)
    {
      upvalue->value = fiber->stack + (upvalue->value - oldStack);
    }
    
    fiber->stackTop = fiber->stack + (fiber->stackTop - oldStack);
  }
}

ObjForeign* wrenNewForeign(WrenVM* vm, ObjClass* classObj, size_t size)
{
  ObjForeign* object = ALLOCATE_FLEX(vm, ObjForeign, uint8_t, size);
  initObj(vm, &object->obj, OBJ_FOREIGN, classObj);

  // Zero out the bytes.
  memset(object->data, 0, size);
  return object;
}

ObjFn* wrenNewFunction(WrenVM* vm, ObjModule* module, int maxSlots)
{
  FnDebug* debug = ALLOCATE(vm, FnDebug);
  debug->name = NULL;
  wrenIntBufferInit(&debug->sourceLines);

  ObjFn* fn = ALLOCATE(vm, ObjFn);
  initObj(vm, &fn->obj, OBJ_FN, vm->fnClass);
  
  wrenValueBufferInit(&fn->constants);
  wrenByteBufferInit(&fn->code);
  fn->module = module;
  fn->maxSlots = maxSlots;
  fn->numUpvalues = 0;
  fn->arity = 0;
  fn->debug = debug;
  
  return fn;
}

void wrenFunctionBindName(WrenVM* vm, ObjFn* fn, const char* name, int length)
{
  fn->debug->name = ALLOCATE_ARRAY(vm, char, length + 1);
  memcpy(fn->debug->name, name, length);
  fn->debug->name[length] = '\0';
}

Value wrenNewInstance(WrenVM* vm, ObjClass* classObj)
{
  ObjInstance* instance = ALLOCATE_FLEX(vm, ObjInstance,
                                        Value, classObj->numFields);
  initObj(vm, &instance->obj, OBJ_INSTANCE, classObj);

  // Initialize fields to null.
  for (int i = 0; i < classObj->numFields; i++)
  {
    instance->fields[i] = NULL_VAL;
  }

  return OBJ_VAL(instance);
}

ObjList* wrenNewList(WrenVM* vm, uint32_t numElements)
{
  // Allocate this before the list object in case it triggers a GC which would
  // free the list.
  Value* elements = NULL;
  if (numElements > 0)
  {
    elements = ALLOCATE_ARRAY(vm, Value, numElements);
  }

  ObjList* list = ALLOCATE(vm, ObjList);
  initObj(vm, &list->obj, OBJ_LIST, vm->listClass);
  list->elements.capacity = numElements;
  list->elements.count = numElements;
  list->elements.data = elements;
  return list;
}

void wrenListInsert(WrenVM* vm, ObjList* list, Value value, uint32_t index)
{
  if (IS_OBJ(value)) wrenPushRoot(vm, AS_OBJ(value));

  // Add a slot at the end of the list.
  wrenValueBufferWrite(vm, &list->elements, NULL_VAL);

  if (IS_OBJ(value)) wrenPopRoot(vm);

  // Shift the existing elements down.
  for (uint32_t i = list->elements.count - 1; i > index; i--)
  {
    list->elements.data[i] = list->elements.data[i - 1];
  }

  // Store the new element.
  list->elements.data[index] = value;
}

int wrenListIndexOf(WrenVM* vm, ObjList* list, Value value)
{
  int count = list->elements.count;
  for (int i = 0; i < count; i++)
  {
    Value item = list->elements.data[i];
    if(wrenValuesEqual(item, value)) {
      return i;
    }
  }
  return -1;
}

Value wrenListRemoveAt(WrenVM* vm, ObjList* list, uint32_t index)
{
  Value removed = list->elements.data[index];

  if (IS_OBJ(removed)) wrenPushRoot(vm, AS_OBJ(removed));

  // Shift items up.
  for (int i = index; i < list->elements.count - 1; i++)
  {
    list->elements.data[i] = list->elements.data[i + 1];
  }

  // If we have too much excess capacity, shrink it.
  if (list->elements.capacity / GROW_FACTOR >= list->elements.count)
  {
    list->elements.data = (Value*)wrenReallocate(vm, list->elements.data,
        sizeof(Value) * list->elements.capacity,
        sizeof(Value) * (list->elements.capacity / GROW_FACTOR));
    list->elements.capacity /= GROW_FACTOR;
  }

  if (IS_OBJ(removed)) wrenPopRoot(vm);

  list->elements.count--;
  return removed;
}

ObjMap* wrenNewMap(WrenVM* vm)
{
  ObjMap* map = ALLOCATE(vm, ObjMap);
  initObj(vm, &map->obj, OBJ_MAP, vm->mapClass);
  map->capacity = 0;
  map->count = 0;
  map->entries = NULL;
  return map;
}

static inline uint32_t hashBits(uint64_t hash)
{
  // From v8's ComputeLongHash() which in turn cites:
  // Thomas Wang, Integer Hash Functions.
  // http://www.concentric.net/~Ttwang/tech/inthash.htm
  hash = ~hash + (hash << 18);  // hash = (hash << 18) - hash - 1;
  hash = hash ^ (hash >> 31);
  hash = hash * 21;  // hash = (hash + (hash << 2)) + (hash << 4);
  hash = hash ^ (hash >> 11);
  hash = hash + (hash << 6);
  hash = hash ^ (hash >> 22);
  return (uint32_t)(hash & 0x3fffffff);
}

// Generates a hash code for [num].
static inline uint32_t hashNumber(double num)
{
  // Hash the raw bits of the value.
  return hashBits(wrenDoubleToBits(num));
}

// Generates a hash code for [object].
static uint32_t hashObject(Obj* object)
{
  switch (object->type)
  {
    case OBJ_CLASS:
      // Classes just use their name.
      return hashObject((Obj*)((ObjClass*)object)->name);
      
      // Allow bare (non-closure) functions so that we can use a map to find
      // existing constants in a function's constant table. This is only used
      // internally. Since user code never sees a non-closure function, they
      // cannot use them as map keys.
    case OBJ_FN:
    {
      ObjFn* fn = (ObjFn*)object;
      return hashNumber(fn->arity) ^ hashNumber(fn->code.count);
    }

    case OBJ_RANGE:
    {
      ObjRange* range = (ObjRange*)object;
      return hashNumber(range->from) ^ hashNumber(range->to);
    }

    case OBJ_STRING:
      return ((ObjString*)object)->hash;

    default:
      ASSERT(false, "Only immutable objects can be hashed.");
      return 0;
  }
}

// Generates a hash code for [value], which must be one of the built-in
// immutable types: null, bool, class, num, range, or string.
static uint32_t hashValue(Value value)
{
  // TODO: We'll probably want to randomize this at some point.

#if WREN_NAN_TAGGING
  if (IS_OBJ(value)) return hashObject(AS_OBJ(value));

  // Hash the raw bits of the unboxed value.
  return hashBits(value);
#else
  switch (value.type)
  {
    case VAL_FALSE: return 0;
    case VAL_NULL:  return 1;
    case VAL_NUM:   return hashNumber(AS_NUM(value));
    case VAL_TRUE:  return 2;
    case VAL_OBJ:   return hashObject(AS_OBJ(value));
    default:        UNREACHABLE();
  }
  
  return 0;
#endif
}

// Looks for an entry with [key] in an array of [capacity] [entries].
//
// If found, sets [result] to point to it and returns `true`. Otherwise,
// returns `false` and points [result] to the entry where the key/value pair
// should be inserted.
static bool findEntry(MapEntry* entries, uint32_t capacity, Value key,
                      MapEntry** result)
{
  // If there is no entry array (an empty map), we definitely won't find it.
  if (capacity == 0) return false;
  
  // Figure out where to insert it in the table. Use open addressing and
  // basic linear probing.
  uint32_t startIndex = hashValue(key) % capacity;
  uint32_t index = startIndex;
  
  // If we pass a tombstone and don't end up finding the key, its entry will
  // be re-used for the insert.
  MapEntry* tombstone = NULL;
  
  // Walk the probe sequence until we've tried every slot.
  do
  {
    MapEntry* entry = &entries[index];
    
    if (IS_UNDEFINED(entry->key))
    {
      // If we found an empty slot, the key is not in the table. If we found a
      // slot that contains a deleted key, we have to keep looking.
      if (IS_FALSE(entry->value))
      {
        // We found an empty slot, so we've reached the end of the probe
        // sequence without finding the key. If we passed a tombstone, then
        // that's where we should insert the item, otherwise, put it here at
        // the end of the sequence.
        *result = tombstone != NULL ? tombstone : entry;
        return false;
      }
      else
      {
        // We found a tombstone. We need to keep looking in case the key is
        // after it, but we'll use this entry as the insertion point if the
        // key ends up not being found.
        if (tombstone == NULL) tombstone = entry;
      }
    }
    else if (wrenValuesEqual(entry->key, key))
    {
      // We found the key.
      *result = entry;
      return true;
    }
    
    // Try the next slot.
    index = (index + 1) % capacity;
  }
  while (index != startIndex);
  
  // If we get here, the table is full of tombstones. Return the first one we
  // found.
  ASSERT(tombstone != NULL, "Map should have tombstones or empty entries.");
  *result = tombstone;
  return false;
}

// Inserts [key] and [value] in the array of [entries] with the given
// [capacity].
//
// Returns `true` if this is the first time [key] was added to the map.
static bool insertEntry(MapEntry* entries, uint32_t capacity,
                        Value key, Value value)
{
  ASSERT(entries != NULL, "Should ensure capacity before inserting.");
  
  MapEntry* entry;
  if (findEntry(entries, capacity, key, &entry))
  {
    // Already present, so just replace the value.
    entry->value = value;
    return false;
  }
  else
  {
    entry->key = key;
    entry->value = value;
    return true;
  }
}

// Updates [map]'s entry array to [capacity].
static void resizeMap(WrenVM* vm, ObjMap* map, uint32_t capacity)
{
  // Create the new empty hash table.
  MapEntry* entries = ALLOCATE_ARRAY(vm, MapEntry, capacity);
  for (uint32_t i = 0; i < capacity; i++)
  {
    entries[i].key = UNDEFINED_VAL;
    entries[i].value = FALSE_VAL;
  }

  // Re-add the existing entries.
  if (map->capacity > 0)
  {
    for (uint32_t i = 0; i < map->capacity; i++)
    {
      MapEntry* entry = &map->entries[i];
      
      // Don't copy empty entries or tombstones.
      if (IS_UNDEFINED(entry->key)) continue;

      insertEntry(entries, capacity, entry->key, entry->value);
    }
  }

  // Replace the array.
  DEALLOCATE(vm, map->entries);
  map->entries = entries;
  map->capacity = capacity;
}

Value wrenMapGet(ObjMap* map, Value key)
{
  MapEntry* entry;
  if (findEntry(map->entries, map->capacity, key, &entry)) return entry->value;

  return UNDEFINED_VAL;
}

void wrenMapSet(WrenVM* vm, ObjMap* map, Value key, Value value)
{
  // If the map is getting too full, make room first.
  if (map->count + 1 > map->capacity * MAP_LOAD_PERCENT / 100)
  {
    // Figure out the new hash table size.
    uint32_t capacity = map->capacity * GROW_FACTOR;
    if (capacity < MIN_CAPACITY) capacity = MIN_CAPACITY;

    resizeMap(vm, map, capacity);
  }

  if (insertEntry(map->entries, map->capacity, key, value))
  {
    // A new key was added.
    map->count++;
  }
}

void wrenMapClear(WrenVM* vm, ObjMap* map)
{
  DEALLOCATE(vm, map->entries);
  map->entries = NULL;
  map->capacity = 0;
  map->count = 0;
}

Value wrenMapRemoveKey(WrenVM* vm, ObjMap* map, Value key)
{
  MapEntry* entry;
  if (!findEntry(map->entries, map->capacity, key, &entry)) return NULL_VAL;

  // Remove the entry from the map. Set this value to true, which marks it as a
  // deleted slot. When searching for a key, we will stop on empty slots, but
  // continue past deleted slots.
  Value value = entry->value;
  entry->key = UNDEFINED_VAL;
  entry->value = TRUE_VAL;

  if (IS_OBJ(value)) wrenPushRoot(vm, AS_OBJ(value));

  map->count--;

  if (map->count == 0)
  {
    // Removed the last item, so free the array.
    wrenMapClear(vm, map);
  }
  else if (map->capacity > MIN_CAPACITY &&
           map->count < map->capacity / GROW_FACTOR * MAP_LOAD_PERCENT / 100)
  {
    uint32_t capacity = map->capacity / GROW_FACTOR;
    if (capacity < MIN_CAPACITY) capacity = MIN_CAPACITY;

    // The map is getting empty, so shrink the entry array back down.
    // TODO: Should we do this less aggressively than we grow?
    resizeMap(vm, map, capacity);
  }

  if (IS_OBJ(value)) wrenPopRoot(vm);
  return value;
}

ObjModule* wrenNewModule(WrenVM* vm, ObjString* name)
{
  ObjModule* module = ALLOCATE(vm, ObjModule);

  // Modules are never used as first-class objects, so don't need a class.
  initObj(vm, (Obj*)module, OBJ_MODULE, NULL);

  wrenPushRoot(vm, (Obj*)module);

  wrenSymbolTableInit(&module->variableNames);
  wrenValueBufferInit(&module->variables);

  module->name = name;

  wrenPopRoot(vm);
  return module;
}

Value wrenNewRange(WrenVM* vm, double from, double to, bool isInclusive)
{
  ObjRange* range = ALLOCATE(vm, ObjRange);
  initObj(vm, &range->obj, OBJ_RANGE, vm->rangeClass);
  range->from = from;
  range->to = to;
  range->isInclusive = isInclusive;

  return OBJ_VAL(range);
}

// Creates a new string object with a null-terminated buffer large enough to
// hold a string of [length] but does not fill in the bytes.
//
// The caller is expected to fill in the buffer and then calculate the string's
// hash.
static ObjString* allocateString(WrenVM* vm, size_t length)
{
  ObjString* string = ALLOCATE_FLEX(vm, ObjString, char, length + 1);
  initObj(vm, &string->obj, OBJ_STRING, vm->stringClass);
  string->length = (int)length;
  string->value[length] = '\0';

  return string;
}

// Calculates and stores the hash code for [string].
static void hashString(ObjString* string)
{
  // FNV-1a hash. See: http://www.isthe.com/chongo/tech/comp/fnv/
  uint32_t hash = 2166136261u;

  // This is O(n) on the length of the string, but we only call this when a new
  // string is created. Since the creation is also O(n) (to copy/initialize all
  // the bytes), we allow this here.
  for (uint32_t i = 0; i < string->length; i++)
  {
    hash ^= string->value[i];
    hash *= 16777619;
  }

  string->hash = hash;
}

Value wrenNewString(WrenVM* vm, const char* text)
{
  return wrenNewStringLength(vm, text, strlen(text));
}

Value wrenNewStringLength(WrenVM* vm, const char* text, size_t length)
{
  // Allow NULL if the string is empty since byte buffers don't allocate any
  // characters for a zero-length string.
  ASSERT(length == 0 || text != NULL, "Unexpected NULL string.");
  
  ObjString* string = allocateString(vm, length);
  
  // Copy the string (if given one).
  if (length > 0 && text != NULL) memcpy(string->value, text, length);
  
  hashString(string);
  return OBJ_VAL(string);
}


Value wrenNewStringFromRange(WrenVM* vm, ObjString* source, int start,
                             uint32_t count, int step)
{
  uint8_t* from = (uint8_t*)source->value;
  int length = 0;
  for (uint32_t i = 0; i < count; i++)
  {
    length += wrenUtf8DecodeNumBytes(from[start + i * step]);
  }

  ObjString* result = allocateString(vm, length);
  result->value[length] = '\0';

  uint8_t* to = (uint8_t*)result->value;
  for (uint32_t i = 0; i < count; i++)
  {
    int index = start + i * step;
    int codePoint = wrenUtf8Decode(from + index, source->length - index);

    if (codePoint != -1)
    {
      to += wrenUtf8Encode(codePoint, to);
    }
  }

  hashString(result);
  return OBJ_VAL(result);
}

Value wrenNumToString(WrenVM* vm, double value)
{
  // Edge case: If the value is NaN or infinity, different versions of libc
  // produce different outputs (some will format it signed and some won't). To
  // get reliable output, handle it ourselves.
  if (isnan(value)) return CONST_STRING(vm, "nan");
  if (isinf(value))
  {
    if (value > 0.0)
    {
      return CONST_STRING(vm, "infinity");
    }
    else
    {
      return CONST_STRING(vm, "-infinity");
    }
  }

  // This is large enough to hold any double converted to a string using
  // "%.14g". Example:
  //
  //     -1.12345678901234e-1022
  //
  // So we have:
  //
  // + 1 char for sign
  // + 1 char for digit
  // + 1 char for "."
  // + 14 chars for decimal digits
  // + 1 char for "e"
  // + 1 char for "-" or "+"
  // + 4 chars for exponent
  // + 1 char for "\0"
  // = 24
  char buffer[24];
  int length = sprintf(buffer, "%.14g", value);
  return wrenNewStringLength(vm, buffer, length);
}

Value wrenStringFromCodePoint(WrenVM* vm, int value)
{
  int length = wrenUtf8EncodeNumBytes(value);
  ASSERT(length != 0, "Value out of range.");

  ObjString* string = allocateString(vm, length);

  wrenUtf8Encode(value, (uint8_t*)string->value);
  hashString(string);

  return OBJ_VAL(string);
}

Value wrenStringFromByte(WrenVM *vm, uint8_t value)
{
  int length = 1;
  ObjString* string = allocateString(vm, length);
  string->value[0] = value;
  hashString(string);
  return OBJ_VAL(string);
}

Value wrenStringFormat(WrenVM* vm, const char* format, ...)
{
  va_list argList;

  // Calculate the length of the result string. Do this up front so we can
  // create the final string with a single allocation.
  va_start(argList, format);
  size_t totalLength = 0;
  for (const char* c = format; *c != '\0'; c++)
  {
    switch (*c)
    {
      case '$':
        totalLength += strlen(va_arg(argList, const char*));
        break;

      case '@':
        totalLength += AS_STRING(va_arg(argList, Value))->length;
        break;

      default:
        // Any other character is interpreted literally.
        totalLength++;
    }
  }
  va_end(argList);

  // Concatenate the string.
  ObjString* result = allocateString(vm, totalLength);

  va_start(argList, format);
  char* start = result->value;
  for (const char* c = format; *c != '\0'; c++)
  {
    switch (*c)
    {
      case '$':
      {
        const char* string = va_arg(argList, const char*);
        size_t length = strlen(string);
        memcpy(start, string, length);
        start += length;
        break;
      }

      case '@':
      {
        ObjString* string = AS_STRING(va_arg(argList, Value));
        memcpy(start, string->value, string->length);
        start += string->length;
        break;
      }

      default:
        // Any other character is interpreted literally.
        *start++ = *c;
    }
  }
  va_end(argList);

  hashString(result);

  return OBJ_VAL(result);
}

Value wrenStringCodePointAt(WrenVM* vm, ObjString* string, uint32_t index)
{
  ASSERT(index < string->length, "Index out of bounds.");

  int codePoint = wrenUtf8Decode((uint8_t*)string->value + index,
                                 string->length - index);
  if (codePoint == -1)
  {
    // If it isn't a valid UTF-8 sequence, treat it as a single raw byte.
    char bytes[2];
    bytes[0] = string->value[index];
    bytes[1] = '\0';
    return wrenNewStringLength(vm, bytes, 1);
  }

  return wrenStringFromCodePoint(vm, codePoint);
}

// Uses the Boyer-Moore-Horspool string matching algorithm.
uint32_t wrenStringFind(ObjString* haystack, ObjString* needle, uint32_t start)
{
  // Edge case: An empty needle is always found.
  if (needle->length == 0) return start;

  // If the needle goes past the haystack it won't be found.
  if (start + needle->length > haystack->length) return UINT32_MAX;

  // If the startIndex is too far it also won't be found.
  if (start >= haystack->length) return UINT32_MAX;

  // Pre-calculate the shift table. For each character (8-bit value), we
  // determine how far the search window can be advanced if that character is
  // the last character in the haystack where we are searching for the needle
  // and the needle doesn't match there.
  uint32_t shift[UINT8_MAX];
  uint32_t needleEnd = needle->length - 1;

  // By default, we assume the character is not the needle at all. In that case
  // case, if a match fails on that character, we can advance one whole needle
  // width since.
  for (uint32_t index = 0; index < UINT8_MAX; index++)
  {
    shift[index] = needle->length;
  }

  // Then, for every character in the needle, determine how far it is from the
  // end. If a match fails on that character, we can advance the window such
  // that it the last character in it lines up with the last place we could
  // find it in the needle.
  for (uint32_t index = 0; index < needleEnd; index++)
  {
    char c = needle->value[index];
    shift[(uint8_t)c] = needleEnd - index;
  }

  // Slide the needle across the haystack, looking for the first match or
  // stopping if the needle goes off the end.
  char lastChar = needle->value[needleEnd];
  uint32_t range = haystack->length - needle->length;

  for (uint32_t index = start; index <= range; )
  {
    // Compare the last character in the haystack's window to the last character
    // in the needle. If it matches, see if the whole needle matches.
    char c = haystack->value[index + needleEnd];
    if (lastChar == c &&
        memcmp(haystack->value + index, needle->value, needleEnd) == 0)
    {
      // Found a match.
      return index;
    }

    // Otherwise, slide the needle forward.
    index += shift[(uint8_t)c];
  }

  // Not found.
  return UINT32_MAX;
}

ObjUpvalue* wrenNewUpvalue(WrenVM* vm, Value* value)
{
  ObjUpvalue* upvalue = ALLOCATE(vm, ObjUpvalue);

  // Upvalues are never used as first-class objects, so don't need a class.
  initObj(vm, &upvalue->obj, OBJ_UPVALUE, NULL);

  upvalue->value = value;
  upvalue->closed = NULL_VAL;
  upvalue->next = NULL;
  return upvalue;
}

void wrenGrayObj(WrenVM* vm, Obj* obj)
{
  if (obj == NULL) return;

  // Stop if the object is already darkened so we don't get stuck in a cycle.
  if (obj->isDark) return;

  // It's been reached.
  obj->isDark = true;

  // Add it to the gray list so it can be recursively explored for
  // more marks later.
  if (vm->grayCount >= vm->grayCapacity)
  {
    vm->grayCapacity = vm->grayCount * 2;
    vm->gray = (Obj**)vm->config.reallocateFn(vm->gray,
                                              vm->grayCapacity * sizeof(Obj*),
                                              vm->config.userData);
  }

  vm->gray[vm->grayCount++] = obj;
}

void wrenGrayValue(WrenVM* vm, Value value)
{
  if (!IS_OBJ(value)) return;
  wrenGrayObj(vm, AS_OBJ(value));
}

void wrenGrayBuffer(WrenVM* vm, ValueBuffer* buffer)
{
  for (int i = 0; i < buffer->count; i++)
  {
    wrenGrayValue(vm, buffer->data[i]);
  }
}

static void blackenClass(WrenVM* vm, ObjClass* classObj)
{
  // The metaclass.
  wrenGrayObj(vm, (Obj*)classObj->obj.classObj);

  // The superclass.
  wrenGrayObj(vm, (Obj*)classObj->superclass);

  // Method function objects.
  for (int i = 0; i < classObj->methods.count; i++)
  {
    if (classObj->methods.data[i].type == METHOD_BLOCK)
    {
      wrenGrayObj(vm, (Obj*)classObj->methods.data[i].as.closure);
    }
  }

  wrenGrayObj(vm, (Obj*)classObj->name);

  if(!IS_NULL(classObj->attributes)) wrenGrayObj(vm, AS_OBJ(classObj->attributes));

  // Keep track of how much memory is still in use.
  vm->bytesAllocated += sizeof(ObjClass);
  vm->bytesAllocated += classObj->methods.capacity * sizeof(Method);
}

static void blackenClosure(WrenVM* vm, ObjClosure* closure)
{
  // Mark the function.
  wrenGrayObj(vm, (Obj*)closure->fn);

  // Mark the upvalues.
  for (int i = 0; i < closure->fn->numUpvalues; i++)
  {
    wrenGrayObj(vm, (Obj*)closure->upvalues[i]);
  }

  // Keep track of how much memory is still in use.
  vm->bytesAllocated += sizeof(ObjClosure);
  vm->bytesAllocated += sizeof(ObjUpvalue*) * closure->fn->numUpvalues;
}

static void blackenFiber(WrenVM* vm, ObjFiber* fiber)
{
  // Stack functions.
  for (int i = 0; i < fiber->numFrames; i++)
  {
    wrenGrayObj(vm, (Obj*)fiber->frames[i].closure);
  }

  // Stack variables.
  for (Value* slot = fiber->stack; slot < fiber->stackTop; slot++)
  {
    wrenGrayValue(vm, *slot);
  }

  // Open upvalues.
  ObjUpvalue* upvalue = fiber->openUpvalues;
  while (upvalue != NULL)
  {
    wrenGrayObj(vm, (Obj*)upvalue);
    upvalue = upvalue->next;
  }

  // The caller.
  wrenGrayObj(vm, (Obj*)fiber->caller);
  wrenGrayValue(vm, fiber->error);

  // Keep track of how much memory is still in use.
  vm->bytesAllocated += sizeof(ObjFiber);
  vm->bytesAllocated += fiber->frameCapacity * sizeof(CallFrame);
  vm->bytesAllocated += fiber->stackCapacity * sizeof(Value);
}

static void blackenFn(WrenVM* vm, ObjFn* fn)
{
  // Mark the constants.
  wrenGrayBuffer(vm, &fn->constants);

  // Keep track of how much memory is still in use.
  vm->bytesAllocated += sizeof(ObjFn);
  vm->bytesAllocated += sizeof(uint8_t) * fn->code.capacity;
  vm->bytesAllocated += sizeof(Value) * fn->constants.capacity;
  
  // The debug line number buffer.
  vm->bytesAllocated += sizeof(int) * fn->code.capacity;
  // TODO: What about the function name?
}

static void blackenForeign(WrenVM* vm, ObjForeign* foreign)
{
  // TODO: Keep track of how much memory the foreign object uses. We can store
  // this in each foreign object, but it will balloon the size. We may not want
  // that much overhead. One option would be to let the foreign class register
  // a C function that returns a size for the object. That way the VM doesn't
  // always have to explicitly store it.
}

static void blackenInstance(WrenVM* vm, ObjInstance* instance)
{
  wrenGrayObj(vm, (Obj*)instance->obj.classObj);

  // Mark the fields.
  for (int i = 0; i < instance->obj.classObj->numFields; i++)
  {
    wrenGrayValue(vm, instance->fields[i]);
  }

  // Keep track of how much memory is still in use.
  vm->bytesAllocated += sizeof(ObjInstance);
  vm->bytesAllocated += sizeof(Value) * instance->obj.classObj->numFields;
}

static void blackenList(WrenVM* vm, ObjList* list)
{
  // Mark the elements.
  wrenGrayBuffer(vm, &list->elements);

  // Keep track of how much memory is still in use.
  vm->bytesAllocated += sizeof(ObjList);
  vm->bytesAllocated += sizeof(Value) * list->elements.capacity;
}

static void blackenMap(WrenVM* vm, ObjMap* map)
{
  // Mark the entries.
  for (uint32_t i = 0; i < map->capacity; i++)
  {
    MapEntry* entry = &map->entries[i];
    if (IS_UNDEFINED(entry->key)) continue;

    wrenGrayValue(vm, entry->key);
    wrenGrayValue(vm, entry->value);
  }

  // Keep track of how much memory is still in use.
  vm->bytesAllocated += sizeof(ObjMap);
  vm->bytesAllocated += sizeof(MapEntry) * map->capacity;
}

static void blackenModule(WrenVM* vm, ObjModule* module)
{
  // Top-level variables.
  for (int i = 0; i < module->variables.count; i++)
  {
    wrenGrayValue(vm, module->variables.data[i]);
  }

  wrenBlackenSymbolTable(vm, &module->variableNames);

  wrenGrayObj(vm, (Obj*)module->name);

  // Keep track of how much memory is still in use.
  vm->bytesAllocated += sizeof(ObjModule);
}

static void blackenRange(WrenVM* vm, ObjRange* range)
{
  // Keep track of how much memory is still in use.
  vm->bytesAllocated += sizeof(ObjRange);
}

static void blackenString(WrenVM* vm, ObjString* string)
{
  // Keep track of how much memory is still in use.
  vm->bytesAllocated += sizeof(ObjString) + string->length + 1;
}

static void blackenUpvalue(WrenVM* vm, ObjUpvalue* upvalue)
{
  // Mark the closed-over object (in case it is closed).
  wrenGrayValue(vm, upvalue->closed);

  // Keep track of how much memory is still in use.
  vm->bytesAllocated += sizeof(ObjUpvalue);
}

static void blackenObject(WrenVM* vm, Obj* obj)
{
#if WREN_DEBUG_TRACE_MEMORY
  printf("mark ");
  wrenDumpValue(OBJ_VAL(obj));
  printf(" @ %p\n", obj);
#endif

  // Traverse the object's fields.
  switch (obj->type)
  {
    case OBJ_CLASS:    blackenClass(   vm, (ObjClass*)   obj); break;
    case OBJ_CLOSURE:  blackenClosure( vm, (ObjClosure*) obj); break;
    case OBJ_FIBER:    blackenFiber(   vm, (ObjFiber*)   obj); break;
    case OBJ_FN:       blackenFn(      vm, (ObjFn*)      obj); break;
    case OBJ_FOREIGN:  blackenForeign( vm, (ObjForeign*) obj); break;
    case OBJ_INSTANCE: blackenInstance(vm, (ObjInstance*)obj); break;
    case OBJ_LIST:     blackenList(    vm, (ObjList*)    obj); break;
    case OBJ_MAP:      blackenMap(     vm, (ObjMap*)     obj); break;
    case OBJ_MODULE:   blackenModule(  vm, (ObjModule*)  obj); break;
    case OBJ_RANGE:    blackenRange(   vm, (ObjRange*)   obj); break;
    case OBJ_STRING:   blackenString(  vm, (ObjString*)  obj); break;
    case OBJ_UPVALUE:  blackenUpvalue( vm, (ObjUpvalue*) obj); break;
  }
}

void wrenBlackenObjects(WrenVM* vm)
{
  while (vm->grayCount > 0)
  {
    // Pop an item from the gray stack.
    Obj* obj = vm->gray[--vm->grayCount];
    blackenObject(vm, obj);
  }
}

void wrenFreeObj(WrenVM* vm, Obj* obj)
{
#if WREN_DEBUG_TRACE_MEMORY
  printf("free ");
  wrenDumpValue(OBJ_VAL(obj));
  printf(" @ %p\n", obj);
#endif

  switch (obj->type)
  {
    case OBJ_CLASS:
      wrenMethodBufferClear(vm, &((ObjClass*)obj)->methods);
      break;

    case OBJ_FIBER:
    {
      ObjFiber* fiber = (ObjFiber*)obj;
      DEALLOCATE(vm, fiber->frames);
      DEALLOCATE(vm, fiber->stack);
      break;
    }
      
    case OBJ_FN:
    {
      ObjFn* fn = (ObjFn*)obj;
      wrenValueBufferClear(vm, &fn->constants);
      wrenByteBufferClear(vm, &fn->code);
      wrenIntBufferClear(vm, &fn->debug->sourceLines);
      DEALLOCATE(vm, fn->debug->name);
      DEALLOCATE(vm, fn->debug);
      break;
    }

    case OBJ_FOREIGN:
      wrenFinalizeForeign(vm, (ObjForeign*)obj);
      break;

    case OBJ_LIST:
      wrenValueBufferClear(vm, &((ObjList*)obj)->elements);
      break;

    case OBJ_MAP:
      DEALLOCATE(vm, ((ObjMap*)obj)->entries);
      break;

    case OBJ_MODULE:
      wrenSymbolTableClear(vm, &((ObjModule*)obj)->variableNames);
      wrenValueBufferClear(vm, &((ObjModule*)obj)->variables);
      break;

    case OBJ_CLOSURE:
    case OBJ_INSTANCE:
    case OBJ_RANGE:
    case OBJ_STRING:
    case OBJ_UPVALUE:
      break;
  }

  DEALLOCATE(vm, obj);
}

ObjClass* wrenGetClass(WrenVM* vm, Value value)
{
  return wrenGetClassInline(vm, value);
}

bool wrenValuesEqual(Value a, Value b)
{
  if (wrenValuesSame(a, b)) return true;

  // If we get here, it's only possible for two heap-allocated immutable objects
  // to be equal.
  if (!IS_OBJ(a) || !IS_OBJ(b)) return false;

  Obj* aObj = AS_OBJ(a);
  Obj* bObj = AS_OBJ(b);

  // Must be the same type.
  if (aObj->type != bObj->type) return false;

  switch (aObj->type)
  {
    case OBJ_RANGE:
    {
      ObjRange* aRange = (ObjRange*)aObj;
      ObjRange* bRange = (ObjRange*)bObj;
      return aRange->from == bRange->from &&
             aRange->to == bRange->to &&
             aRange->isInclusive == bRange->isInclusive;
    }

    case OBJ_STRING:
    {
      ObjString* aString = (ObjString*)aObj;
      ObjString* bString = (ObjString*)bObj;
      return aString->hash == bString->hash &&
      wrenStringEqualsCString(aString, bString->value, bString->length);
    }

    default:
      // All other types are only equal if they are same, which they aren't if
      // we get here.
      return false;
  }
}
// End file "wren_value.c"
// Begin file "wren_compiler.c"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>


#if WREN_DEBUG_DUMP_COMPILED_CODE
#endif

// This is written in bottom-up order, so the tokenization comes first, then
// parsing/code generation. This minimizes the number of explicit forward
// declarations needed.

// The maximum number of local (i.e. not module level) variables that can be
// declared in a single function, method, or chunk of top level code. This is
// the maximum number of variables in scope at one time, and spans block scopes.
//
// Note that this limitation is also explicit in the bytecode. Since
// `CODE_LOAD_LOCAL` and `CODE_STORE_LOCAL` use a single argument byte to
// identify the local, only 256 can be in scope at one time.
#define MAX_LOCALS 256

// The maximum number of upvalues (i.e. variables from enclosing functions)
// that a function can close over.
#define MAX_UPVALUES 256

// The maximum number of distinct constants that a function can contain. This
// value is explicit in the bytecode since `CODE_CONSTANT` only takes a single
// two-byte argument.
#define MAX_CONSTANTS (1 << 16)

// The maximum distance a CODE_JUMP or CODE_JUMP_IF instruction can move the
// instruction pointer.
#define MAX_JUMP (1 << 16)

// The maximum depth that interpolation can nest. For example, this string has
// three levels:
//
//      "outside %(one + "%(two + "%(three)")")"
#define MAX_INTERPOLATION_NESTING 8

// The buffer size used to format a compile error message, excluding the header
// with the module name and error location. Using a hardcoded buffer for this
// is kind of hairy, but fortunately we can control what the longest possible
// message is and handle that. Ideally, we'd use `snprintf()`, but that's not
// available in standard C++98.
#define ERROR_MESSAGE_SIZE (80 + MAX_VARIABLE_NAME + 15)

typedef enum
{
  TOKEN_LEFT_PAREN,
  TOKEN_RIGHT_PAREN,
  TOKEN_LEFT_BRACKET,
  TOKEN_RIGHT_BRACKET,
  TOKEN_LEFT_BRACE,
  TOKEN_RIGHT_BRACE,
  TOKEN_COLON,
  TOKEN_DOT,
  TOKEN_DOTDOT,
  TOKEN_DOTDOTDOT,
  TOKEN_COMMA,
  TOKEN_STAR,
  TOKEN_SLASH,
  TOKEN_PERCENT,
  TOKEN_HASH,
  TOKEN_PLUS,
  TOKEN_MINUS,
  TOKEN_LTLT,
  TOKEN_GTGT,
  TOKEN_PIPE,
  TOKEN_PIPEPIPE,
  TOKEN_CARET,
  TOKEN_AMP,
  TOKEN_AMPAMP,
  TOKEN_BANG,
  TOKEN_TILDE,
  TOKEN_QUESTION,
  TOKEN_EQ,
  TOKEN_LT,
  TOKEN_GT,
  TOKEN_LTEQ,
  TOKEN_GTEQ,
  TOKEN_EQEQ,
  TOKEN_BANGEQ,

  TOKEN_BREAK,
  TOKEN_CONTINUE,
  TOKEN_CLASS,
  TOKEN_CONSTRUCT,
  TOKEN_ELSE,
  TOKEN_FALSE,
  TOKEN_FOR,
  TOKEN_FOREIGN,
  TOKEN_IF,
  TOKEN_IMPORT,
  TOKEN_AS,
  TOKEN_IN,
  TOKEN_IS,
  TOKEN_NULL,
  TOKEN_RETURN,
  TOKEN_STATIC,
  TOKEN_SUPER,
  TOKEN_THIS,
  TOKEN_TRUE,
  TOKEN_VAR,
  TOKEN_WHILE,

  TOKEN_FIELD,
  TOKEN_STATIC_FIELD,
  TOKEN_NAME,
  TOKEN_NUMBER,
  
  // A string literal without any interpolation, or the last section of a
  // string following the last interpolated expression.
  TOKEN_STRING,
  
  // A portion of a string literal preceding an interpolated expression. This
  // string:
  //
  //     "a %(b) c %(d) e"
  //
  // is tokenized to:
  //
  //     TOKEN_INTERPOLATION "a "
  //     TOKEN_NAME          b
  //     TOKEN_INTERPOLATION " c "
  //     TOKEN_NAME          d
  //     TOKEN_STRING        " e"
  TOKEN_INTERPOLATION,

  TOKEN_LINE,

  TOKEN_ERROR,
  TOKEN_EOF
} TokenType;

typedef struct
{
  TokenType type;

  // The beginning of the token, pointing directly into the source.
  const char* start;

  // The length of the token in characters.
  int length;

  // The 1-based line where the token appears.
  int line;
  
  // The parsed value if the token is a literal.
  Value value;
} Token;

typedef struct
{
  WrenVM* vm;

  // The module being parsed.
  ObjModule* module;

  // The source code being parsed.
  const char* source;

  // The beginning of the currently-being-lexed token in [source].
  const char* tokenStart;

  // The current character being lexed in [source].
  const char* currentChar;

  // The 1-based line number of [currentChar].
  int currentLine;

  // The upcoming token.
  Token next;

  // The most recently lexed token.
  Token current;

  // The most recently consumed/advanced token.
  Token previous;
  
  // Tracks the lexing state when tokenizing interpolated strings.
  //
  // Interpolated strings make the lexer not strictly regular: we don't know
  // whether a ")" should be treated as a RIGHT_PAREN token or as ending an
  // interpolated expression unless we know whether we are inside a string
  // interpolation and how many unmatched "(" there are. This is particularly
  // complex because interpolation can nest:
  //
  //     " %( " %( inner ) " ) "
  //
  // This tracks that state. The parser maintains a stack of ints, one for each
  // level of current interpolation nesting. Each value is the number of
  // unmatched "(" that are waiting to be closed.
  int parens[MAX_INTERPOLATION_NESTING];
  int numParens;

  // Whether compile errors should be printed to stderr or discarded.
  bool printErrors;

  // If a syntax or compile error has occurred.
  bool hasError;
} Parser;

typedef struct
{
  // The name of the local variable. This points directly into the original
  // source code string.
  const char* name;

  // The length of the local variable's name.
  int length;

  // The depth in the scope chain that this variable was declared at. Zero is
  // the outermost scope--parameters for a method, or the first local block in
  // top level code. One is the scope within that, etc.
  int depth;

  // If this local variable is being used as an upvalue.
  bool isUpvalue;
} Local;

typedef struct
{
  // True if this upvalue is capturing a local variable from the enclosing
  // function. False if it's capturing an upvalue.
  bool isLocal;

  // The index of the local or upvalue being captured in the enclosing function.
  int index;
} CompilerUpvalue;

// Bookkeeping information for the current loop being compiled.
typedef struct sLoop
{
  // Index of the instruction that the loop should jump back to.
  int start;

  // Index of the argument for the CODE_JUMP_IF instruction used to exit the
  // loop. Stored so we can patch it once we know where the loop ends.
  int exitJump;

  // Index of the first instruction of the body of the loop.
  int body;

  // Depth of the scope(s) that need to be exited if a break is hit inside the
  // loop.
  int scopeDepth;

  // The loop enclosing this one, or NULL if this is the outermost loop.
  struct sLoop* enclosing;
} Loop;

// The different signature syntaxes for different kinds of methods.
typedef enum
{
  // A name followed by a (possibly empty) parenthesized parameter list. Also
  // used for binary operators.
  SIG_METHOD,
  
  // Just a name. Also used for unary operators.
  SIG_GETTER,
  
  // A name followed by "=".
  SIG_SETTER,
  
  // A square bracketed parameter list.
  SIG_SUBSCRIPT,
  
  // A square bracketed parameter list followed by "=".
  SIG_SUBSCRIPT_SETTER,
  
  // A constructor initializer function. This has a distinct signature to
  // prevent it from being invoked directly outside of the constructor on the
  // metaclass.
  SIG_INITIALIZER
} SignatureType;

typedef struct
{
  const char* name;
  int length;
  SignatureType type;
  int arity;
} Signature;

// Bookkeeping information for compiling a class definition.
typedef struct
{
  // The name of the class.
  ObjString* name;
  
  // Attributes for the class itself
  ObjMap* classAttributes;
  // Attributes for methods in this class
  ObjMap* methodAttributes;

  // Symbol table for the fields of the class.
  SymbolTable fields;

  // Symbols for the methods defined by the class. Used to detect duplicate
  // method definitions.
  IntBuffer methods;
  IntBuffer staticMethods;

  // True if the class being compiled is a foreign class.
  bool isForeign;
  
  // True if the current method being compiled is static.
  bool inStatic;

  // The signature of the method being compiled.
  Signature* signature;
} ClassInfo;

struct sCompiler
{
  Parser* parser;

  // The compiler for the function enclosing this one, or NULL if it's the
  // top level.
  struct sCompiler* parent;

  // The currently in scope local variables.
  Local locals[MAX_LOCALS];

  // The number of local variables currently in scope.
  int numLocals;

  // The upvalues that this function has captured from outer scopes. The count
  // of them is stored in [numUpvalues].
  CompilerUpvalue upvalues[MAX_UPVALUES];

  // The current level of block scope nesting, where zero is no nesting. A -1
  // here means top-level code is being compiled and there is no block scope
  // in effect at all. Any variables declared will be module-level.
  int scopeDepth;
  
  // The current number of slots (locals and temporaries) in use.
  //
  // We use this and maxSlots to track the maximum number of additional slots
  // a function may need while executing. When the function is called, the
  // fiber will check to ensure its stack has enough room to cover that worst
  // case and grow the stack if needed.
  //
  // This value here doesn't include parameters to the function. Since those
  // are already pushed onto the stack by the caller and tracked there, we
  // don't need to double count them here.
  int numSlots;

  // The current innermost loop being compiled, or NULL if not in a loop.
  Loop* loop;

  // If this is a compiler for a method, keeps track of the class enclosing it.
  ClassInfo* enclosingClass;

  // The function being compiled.
  ObjFn* fn;
  
  // The constants for the function being compiled.
  ObjMap* constants;

  // Whether or not the compiler is for a constructor initializer
  bool isInitializer;

  // The number of attributes seen while parsing.
  // We track this separately as compile time attributes
  // are not stored, so we can't rely on attributes->count
  // to enforce an error message when attributes are used
  // anywhere other than methods or classes.
  int numAttributes;
  // Attributes for the next class or method.
  ObjMap* attributes;
};

// Describes where a variable is declared.
typedef enum
{
  // A local variable in the current function.
  SCOPE_LOCAL,
  
  // A local variable declared in an enclosing function.
  SCOPE_UPVALUE,
  
  // A top-level module variable.
  SCOPE_MODULE
} Scope;

// A reference to a variable and the scope where it is defined. This contains
// enough information to emit correct code to load or store the variable.
typedef struct
{
  // The stack slot, upvalue slot, or module symbol defining the variable.
  int index;
  
  // Where the variable is declared.
  Scope scope;
} Variable;

// Forward declarations
static void disallowAttributes(Compiler* compiler);
static void addToAttributeGroup(Compiler* compiler, Value group, Value key, Value value);
static void emitClassAttributes(Compiler* compiler, ClassInfo* classInfo);
static void copyAttributes(Compiler* compiler, ObjMap* into);
static void copyMethodAttributes(Compiler* compiler, bool isForeign, 
            bool isStatic, const char* fullSignature, int32_t length);

// The stack effect of each opcode. The index in the array is the opcode, and
// the value is the stack effect of that instruction.
static const int stackEffects[] = {
  #define OPCODE(_, effect) effect,
// Begin file "wren_opcodes.h"
// This defines the bytecode instructions used by the VM. It does so by invoking
// an OPCODE() macro which is expected to be defined at the point that this is
// included. (See: http://en.wikipedia.org/wiki/X_Macro for more.)
//
// The first argument is the name of the opcode. The second is its "stack
// effect" -- the amount that the op code changes the size of the stack. A
// stack effect of 1 means it pushes a value and the stack grows one larger.
// -2 means it pops two values, etc.
//
// Note that the order of instructions here affects the order of the dispatch
// table in the VM's interpreter loop. That in turn affects caching which
// affects overall performance. Take care to run benchmarks if you change the
// order here.

// Load the constant at index [arg].
OPCODE(CONSTANT, 1)

// Push null onto the stack.
OPCODE(NULL, 1)

// Push false onto the stack.
OPCODE(FALSE, 1)

// Push true onto the stack.
OPCODE(TRUE, 1)

// Pushes the value in the given local slot.
OPCODE(LOAD_LOCAL_0, 1)
OPCODE(LOAD_LOCAL_1, 1)
OPCODE(LOAD_LOCAL_2, 1)
OPCODE(LOAD_LOCAL_3, 1)
OPCODE(LOAD_LOCAL_4, 1)
OPCODE(LOAD_LOCAL_5, 1)
OPCODE(LOAD_LOCAL_6, 1)
OPCODE(LOAD_LOCAL_7, 1)
OPCODE(LOAD_LOCAL_8, 1)

// Note: The compiler assumes the following _STORE instructions always
// immediately follow their corresponding _LOAD ones.

// Pushes the value in local slot [arg].
OPCODE(LOAD_LOCAL, 1)

// Stores the top of stack in local slot [arg]. Does not pop it.
OPCODE(STORE_LOCAL, 0)

// Pushes the value in upvalue [arg].
OPCODE(LOAD_UPVALUE, 1)

// Stores the top of stack in upvalue [arg]. Does not pop it.
OPCODE(STORE_UPVALUE, 0)

// Pushes the value of the top-level variable in slot [arg].
OPCODE(LOAD_MODULE_VAR, 1)

// Stores the top of stack in top-level variable slot [arg]. Does not pop it.
OPCODE(STORE_MODULE_VAR, 0)

// Pushes the value of the field in slot [arg] of the receiver of the current
// function. This is used for regular field accesses on "this" directly in
// methods. This instruction is faster than the more general CODE_LOAD_FIELD
// instruction.
OPCODE(LOAD_FIELD_THIS, 1)

// Stores the top of the stack in field slot [arg] in the receiver of the
// current value. Does not pop the value. This instruction is faster than the
// more general CODE_LOAD_FIELD instruction.
OPCODE(STORE_FIELD_THIS, 0)

// Pops an instance and pushes the value of the field in slot [arg] of it.
OPCODE(LOAD_FIELD, 0)

// Pops an instance and stores the subsequent top of stack in field slot
// [arg] in it. Does not pop the value.
OPCODE(STORE_FIELD, -1)

// Pop and discard the top of stack.
OPCODE(POP, -1)

// Invoke the method with symbol [arg]. The number indicates the number of
// arguments (not including the receiver).
OPCODE(CALL_0, 0)
OPCODE(CALL_1, -1)
OPCODE(CALL_2, -2)
OPCODE(CALL_3, -3)
OPCODE(CALL_4, -4)
OPCODE(CALL_5, -5)
OPCODE(CALL_6, -6)
OPCODE(CALL_7, -7)
OPCODE(CALL_8, -8)
OPCODE(CALL_9, -9)
OPCODE(CALL_10, -10)
OPCODE(CALL_11, -11)
OPCODE(CALL_12, -12)
OPCODE(CALL_13, -13)
OPCODE(CALL_14, -14)
OPCODE(CALL_15, -15)
OPCODE(CALL_16, -16)

// Invoke a superclass method with symbol [arg]. The number indicates the
// number of arguments (not including the receiver).
OPCODE(SUPER_0, 0)
OPCODE(SUPER_1, -1)
OPCODE(SUPER_2, -2)
OPCODE(SUPER_3, -3)
OPCODE(SUPER_4, -4)
OPCODE(SUPER_5, -5)
OPCODE(SUPER_6, -6)
OPCODE(SUPER_7, -7)
OPCODE(SUPER_8, -8)
OPCODE(SUPER_9, -9)
OPCODE(SUPER_10, -10)
OPCODE(SUPER_11, -11)
OPCODE(SUPER_12, -12)
OPCODE(SUPER_13, -13)
OPCODE(SUPER_14, -14)
OPCODE(SUPER_15, -15)
OPCODE(SUPER_16, -16)

// Jump the instruction pointer [arg] forward.
OPCODE(JUMP, 0)

// Jump the instruction pointer [arg] backward.
OPCODE(LOOP, 0)

// Pop and if not truthy then jump the instruction pointer [arg] forward.
OPCODE(JUMP_IF, -1)

// If the top of the stack is false, jump [arg] forward. Otherwise, pop and
// continue.
OPCODE(AND, -1)

// If the top of the stack is non-false, jump [arg] forward. Otherwise, pop
// and continue.
OPCODE(OR, -1)

// Close the upvalue for the local on the top of the stack, then pop it.
OPCODE(CLOSE_UPVALUE, -1)

// Exit from the current function and return the value on the top of the
// stack.
OPCODE(RETURN, 0)

// Creates a closure for the function stored at [arg] in the constant table.
//
// Following the function argument is a number of arguments, two for each
// upvalue. The first is true if the variable being captured is a local (as
// opposed to an upvalue), and the second is the index of the local or
// upvalue being captured.
//
// Pushes the created closure.
OPCODE(CLOSURE, 1)

// Creates a new instance of a class.
//
// Assumes the class object is in slot zero, and replaces it with the new
// uninitialized instance of that class. This opcode is only emitted by the
// compiler-generated constructor metaclass methods.
OPCODE(CONSTRUCT, 0)

// Creates a new instance of a foreign class.
//
// Assumes the class object is in slot zero, and replaces it with the new
// uninitialized instance of that class. This opcode is only emitted by the
// compiler-generated constructor metaclass methods.
OPCODE(FOREIGN_CONSTRUCT, 0)

// Creates a class. Top of stack is the superclass. Below that is a string for
// the name of the class. Byte [arg] is the number of fields in the class.
OPCODE(CLASS, -1)

// Ends a class. 
// Atm the stack contains the class and the ClassAttributes (or null).
OPCODE(END_CLASS, -2)

// Creates a foreign class. Top of stack is the superclass. Below that is a
// string for the name of the class.
OPCODE(FOREIGN_CLASS, -1)

// Define a method for symbol [arg]. The class receiving the method is popped
// off the stack, then the function defining the body is popped.
//
// If a foreign method is being defined, the "function" will be a string
// identifying the foreign method. Otherwise, it will be a function or
// closure.
OPCODE(METHOD_INSTANCE, -2)

// Define a method for symbol [arg]. The class whose metaclass will receive
// the method is popped off the stack, then the function defining the body is
// popped.
//
// If a foreign method is being defined, the "function" will be a string
// identifying the foreign method. Otherwise, it will be a function or
// closure.
OPCODE(METHOD_STATIC, -2)

// This is executed at the end of the module's body. Pushes NULL onto the stack
// as the "return value" of the import statement and stores the module as the
// most recently imported one.
OPCODE(END_MODULE, 1)

// Import a module whose name is the string stored at [arg] in the constant
// table.
//
// Pushes null onto the stack so that the fiber for the imported module can
// replace that with a dummy value when it returns. (Fibers always return a
// value when resuming a caller.)
OPCODE(IMPORT_MODULE, 1)

// Import a variable from the most recently imported module. The name of the
// variable to import is at [arg] in the constant table. Pushes the loaded
// variable's value.
OPCODE(IMPORT_VARIABLE, 1)

// This pseudo-instruction indicates the end of the bytecode. It should
// always be preceded by a `CODE_RETURN`, so is never actually executed.
OPCODE(END, 0)
// End file "wren_opcodes.h"
  #undef OPCODE
};

static void printError(Parser* parser, int line, const char* label,
                       const char* format, va_list args)
{
  parser->hasError = true;
  if (!parser->printErrors) return;

  // Only report errors if there is a WrenErrorFn to handle them.
  if (parser->vm->config.errorFn == NULL) return;

  // Format the label and message.
  char message[ERROR_MESSAGE_SIZE];
  int length = sprintf(message, "%s: ", label);
  length += vsprintf(message + length, format, args);
  ASSERT(length < ERROR_MESSAGE_SIZE, "Error should not exceed buffer.");

  ObjString* module = parser->module->name;
  const char* module_name = module ? module->value : "<unknown>";

  parser->vm->config.errorFn(parser->vm, WREN_ERROR_COMPILE,
                             module_name, line, message);
}

// Outputs a lexical error.
static void lexError(Parser* parser, const char* format, ...)
{
  va_list args;
  va_start(args, format);
  printError(parser, parser->currentLine, "Error", format, args);
  va_end(args);
}

// Outputs a compile or syntax error. This also marks the compilation as having
// an error, which ensures that the resulting code will be discarded and never
// run. This means that after calling error(), it's fine to generate whatever
// invalid bytecode you want since it won't be used.
//
// You'll note that most places that call error() continue to parse and compile
// after that. That's so that we can try to find as many compilation errors in
// one pass as possible instead of just bailing at the first one.
static void error(Compiler* compiler, const char* format, ...)
{
  Token* token = &compiler->parser->previous;

  // If the parse error was caused by an error token, the lexer has already
  // reported it.
  if (token->type == TOKEN_ERROR) return;
  
  va_list args;
  va_start(args, format);
  if (token->type == TOKEN_LINE)
  {
    printError(compiler->parser, token->line, "Error at newline", format, args);
  }
  else if (token->type == TOKEN_EOF)
  {
    printError(compiler->parser, token->line,
               "Error at end of file", format, args);
  }
  else
  {
    // Make sure we don't exceed the buffer with a very long token.
    char label[10 + MAX_VARIABLE_NAME + 4 + 1];
    if (token->length <= MAX_VARIABLE_NAME)
    {
      sprintf(label, "Error at '%.*s'", token->length, token->start);
    }
    else
    {
      sprintf(label, "Error at '%.*s...'", MAX_VARIABLE_NAME, token->start);
    }
    printError(compiler->parser, token->line, label, format, args);
  }
  va_end(args);
}

// Adds [constant] to the constant pool and returns its index.
static int addConstant(Compiler* compiler, Value constant)
{
  if (compiler->parser->hasError) return -1;
  
  // See if we already have a constant for the value. If so, reuse it.
  if (compiler->constants != NULL)
  {
    Value existing = wrenMapGet(compiler->constants, constant);
    if (IS_NUM(existing)) return (int)AS_NUM(existing);
  }
  
  // It's a new constant.
  if (compiler->fn->constants.count < MAX_CONSTANTS)
  {
    if (IS_OBJ(constant)) wrenPushRoot(compiler->parser->vm, AS_OBJ(constant));
    wrenValueBufferWrite(compiler->parser->vm, &compiler->fn->constants,
                         constant);
    if (IS_OBJ(constant)) wrenPopRoot(compiler->parser->vm);
    
    if (compiler->constants == NULL)
    {
      compiler->constants = wrenNewMap(compiler->parser->vm);
    }
    wrenMapSet(compiler->parser->vm, compiler->constants, constant,
               NUM_VAL(compiler->fn->constants.count - 1));
  }
  else
  {
    error(compiler, "A function may only contain %d unique constants.",
          MAX_CONSTANTS);
  }

  return compiler->fn->constants.count - 1;
}

// Initializes [compiler].
static void initCompiler(Compiler* compiler, Parser* parser, Compiler* parent,
                         bool isMethod)
{
  compiler->parser = parser;
  compiler->parent = parent;
  compiler->loop = NULL;
  compiler->enclosingClass = NULL;
  compiler->isInitializer = false;
  
  // Initialize these to NULL before allocating in case a GC gets triggered in
  // the middle of initializing the compiler.
  compiler->fn = NULL;
  compiler->constants = NULL;
  compiler->attributes = NULL;

  parser->vm->compiler = compiler;

  // Declare a local slot for either the closure or method receiver so that we
  // don't try to reuse that slot for a user-defined local variable. For
  // methods, we name it "this", so that we can resolve references to that like
  // a normal variable. For functions, they have no explicit "this", so we use
  // an empty name. That way references to "this" inside a function walks up
  // the parent chain to find a method enclosing the function whose "this" we
  // can close over.
  compiler->numLocals = 1;
  compiler->numSlots = compiler->numLocals;

  if (isMethod)
  {
    compiler->locals[0].name = "this";
    compiler->locals[0].length = 4;
  }
  else
  {
    compiler->locals[0].name = NULL;
    compiler->locals[0].length = 0;
  }
  
  compiler->locals[0].depth = -1;
  compiler->locals[0].isUpvalue = false;

  if (parent == NULL)
  {
    // Compiling top-level code, so the initial scope is module-level.
    compiler->scopeDepth = -1;
  }
  else
  {
    // The initial scope for functions and methods is local scope.
    compiler->scopeDepth = 0;
  }
  
  compiler->numAttributes = 0;
  compiler->attributes = wrenNewMap(parser->vm);
  compiler->fn = wrenNewFunction(parser->vm, parser->module,
                                 compiler->numLocals);
}

// Lexing ----------------------------------------------------------------------

typedef struct
{
  const char* identifier;
  size_t      length;
  TokenType   tokenType;
} Keyword;

// The table of reserved words and their associated token types.
static Keyword keywords[] =
{
  {"break",     5, TOKEN_BREAK},
  {"continue",  8, TOKEN_CONTINUE},
  {"class",     5, TOKEN_CLASS},
  {"construct", 9, TOKEN_CONSTRUCT},
  {"else",      4, TOKEN_ELSE},
  {"false",     5, TOKEN_FALSE},
  {"for",       3, TOKEN_FOR},
  {"foreign",   7, TOKEN_FOREIGN},
  {"if",        2, TOKEN_IF},
  {"import",    6, TOKEN_IMPORT},
  {"as",        2, TOKEN_AS},
  {"in",        2, TOKEN_IN},
  {"is",        2, TOKEN_IS},
  {"null",      4, TOKEN_NULL},
  {"return",    6, TOKEN_RETURN},
  {"static",    6, TOKEN_STATIC},
  {"super",     5, TOKEN_SUPER},
  {"this",      4, TOKEN_THIS},
  {"true",      4, TOKEN_TRUE},
  {"var",       3, TOKEN_VAR},
  {"while",     5, TOKEN_WHILE},
  {NULL,        0, TOKEN_EOF} // Sentinel to mark the end of the array.
};

// Returns true if [c] is a valid (non-initial) identifier character.
static bool isName(char c)
{
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

// Returns true if [c] is a digit.
static bool isDigit(char c)
{
  return c >= '0' && c <= '9';
}

// Returns the current character the parser is sitting on.
static char peekChar(Parser* parser)
{
  return *parser->currentChar;
}

// Returns the character after the current character.
static char peekNextChar(Parser* parser)
{
  // If we're at the end of the source, don't read past it.
  if (peekChar(parser) == '\0') return '\0';
  return *(parser->currentChar + 1);
}

// Advances the parser forward one character.
static char nextChar(Parser* parser)
{
  char c = peekChar(parser);
  parser->currentChar++;
  if (c == '\n') parser->currentLine++;
  return c;
}

// If the current character is [c], consumes it and returns `true`.
static bool matchChar(Parser* parser, char c)
{
  if (peekChar(parser) != c) return false;
  nextChar(parser);
  return true;
}

// Sets the parser's current token to the given [type] and current character
// range.
static void makeToken(Parser* parser, TokenType type)
{
  parser->next.type = type;
  parser->next.start = parser->tokenStart;
  parser->next.length = (int)(parser->currentChar - parser->tokenStart);
  parser->next.line = parser->currentLine;
  
  // Make line tokens appear on the line containing the "\n".
  if (type == TOKEN_LINE) parser->next.line--;
}

// If the current character is [c], then consumes it and makes a token of type
// [two]. Otherwise makes a token of type [one].
static void twoCharToken(Parser* parser, char c, TokenType two, TokenType one)
{
  makeToken(parser, matchChar(parser, c) ? two : one);
}

// Skips the rest of the current line.
static void skipLineComment(Parser* parser)
{
  while (peekChar(parser) != '\n' && peekChar(parser) != '\0')
  {
    nextChar(parser);
  }
}

// Skips the rest of a block comment.
static void skipBlockComment(Parser* parser)
{
  int nesting = 1;
  while (nesting > 0)
  {
    if (peekChar(parser) == '\0')
    {
      lexError(parser, "Unterminated block comment.");
      return;
    }

    if (peekChar(parser) == '/' && peekNextChar(parser) == '*')
    {
      nextChar(parser);
      nextChar(parser);
      nesting++;
      continue;
    }

    if (peekChar(parser) == '*' && peekNextChar(parser) == '/')
    {
      nextChar(parser);
      nextChar(parser);
      nesting--;
      continue;
    }

    // Regular comment character.
    nextChar(parser);
  }
}

// Reads the next character, which should be a hex digit (0-9, a-f, or A-F) and
// returns its numeric value. If the character isn't a hex digit, returns -1.
static int readHexDigit(Parser* parser)
{
  char c = nextChar(parser);
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;

  // Don't consume it if it isn't expected. Keeps us from reading past the end
  // of an unterminated string.
  parser->currentChar--;
  return -1;
}

// Parses the numeric value of the current token.
static void makeNumber(Parser* parser, bool isHex)
{
  errno = 0;

  if (isHex)
  {
    parser->next.value = NUM_VAL((double)strtoll(parser->tokenStart, NULL, 16));
  }
  else
  {
    parser->next.value = NUM_VAL(strtod(parser->tokenStart, NULL));
  }
  
  if (errno == ERANGE)
  {
    lexError(parser, "Number literal was too large (%d).", sizeof(long int));
    parser->next.value = NUM_VAL(0);
  }
  
  // We don't check that the entire token is consumed after calling strtoll()
  // or strtod() because we've already scanned it ourselves and know it's valid.

  makeToken(parser, TOKEN_NUMBER);
}

// Finishes lexing a hexadecimal number literal.
static void readHexNumber(Parser* parser)
{
  // Skip past the `x` used to denote a hexadecimal literal.
  nextChar(parser);

  // Iterate over all the valid hexadecimal digits found.
  while (readHexDigit(parser) != -1) continue;

  makeNumber(parser, true);
}

// Finishes lexing a number literal.
static void readNumber(Parser* parser)
{
  while (isDigit(peekChar(parser))) nextChar(parser);

  // See if it has a floating point. Make sure there is a digit after the "."
  // so we don't get confused by method calls on number literals.
  if (peekChar(parser) == '.' && isDigit(peekNextChar(parser)))
  {
    nextChar(parser);
    while (isDigit(peekChar(parser))) nextChar(parser);
  }

  // See if the number is in scientific notation.
  if (matchChar(parser, 'e') || matchChar(parser, 'E'))
  {
    // Allow a single positive/negative exponent symbol.
    if(!matchChar(parser, '+'))
    {
      matchChar(parser, '-');
    }

    if (!isDigit(peekChar(parser)))
    {
      lexError(parser, "Unterminated scientific notation.");
    }

    while (isDigit(peekChar(parser))) nextChar(parser);
  }

  makeNumber(parser, false);
}

// Finishes lexing an identifier. Handles reserved words.
static void readName(Parser* parser, TokenType type, char firstChar)
{
  ByteBuffer string;
  wrenByteBufferInit(&string);
  wrenByteBufferWrite(parser->vm, &string, firstChar);

  while (isName(peekChar(parser)) || isDigit(peekChar(parser)))
  {
    char c = nextChar(parser);
    wrenByteBufferWrite(parser->vm, &string, c);
  }

  // Update the type if it's a keyword.
  size_t length = parser->currentChar - parser->tokenStart;
  for (int i = 0; keywords[i].identifier != NULL; i++)
  {
    if (length == keywords[i].length &&
        memcmp(parser->tokenStart, keywords[i].identifier, length) == 0)
    {
      type = keywords[i].tokenType;
      break;
    }
  }
  
  parser->next.value = wrenNewStringLength(parser->vm,
                                            (char*)string.data, string.count);

  wrenByteBufferClear(parser->vm, &string);
  makeToken(parser, type);
}

// Reads [digits] hex digits in a string literal and returns their number value.
static int readHexEscape(Parser* parser, int digits, const char* description)
{
  int value = 0;
  for (int i = 0; i < digits; i++)
  {
    if (peekChar(parser) == '"' || peekChar(parser) == '\0')
    {
      lexError(parser, "Incomplete %s escape sequence.", description);

      // Don't consume it if it isn't expected. Keeps us from reading past the
      // end of an unterminated string.
      parser->currentChar--;
      break;
    }

    int digit = readHexDigit(parser);
    if (digit == -1)
    {
      lexError(parser, "Invalid %s escape sequence.", description);
      break;
    }

    value = (value * 16) | digit;
  }

  return value;
}

// Reads a hex digit Unicode escape sequence in a string literal.
static void readUnicodeEscape(Parser* parser, ByteBuffer* string, int length)
{
  int value = readHexEscape(parser, length, "Unicode");

  // Grow the buffer enough for the encoded result.
  int numBytes = wrenUtf8EncodeNumBytes(value);
  if (numBytes != 0)
  {
    wrenByteBufferFill(parser->vm, string, 0, numBytes);
    wrenUtf8Encode(value, string->data + string->count - numBytes);
  }
}

static void readRawString(Parser* parser)
{
  ByteBuffer string;
  wrenByteBufferInit(&string);
  TokenType type = TOKEN_STRING;

  //consume the second and third "
  nextChar(parser);
  nextChar(parser);

  int skipStart = 0;
  int firstNewline = -1;

  int skipEnd = -1;
  int lastNewline = -1;

  for (;;)
  {
    char c = nextChar(parser);
    char c1 = peekChar(parser);
    char c2 = peekNextChar(parser);

    if (c == '\r') continue;

    if (c == '\n') {
      lastNewline = string.count;
      skipEnd = lastNewline;
      firstNewline = firstNewline == -1 ? string.count : firstNewline;
    }

    if (c == '"' && c1 == '"' && c2 == '"') break;
    
    bool isWhitespace = c == ' ' || c == '\t';
    skipEnd = c == '\n' || isWhitespace ? skipEnd : -1;

    // If we haven't seen a newline or other character yet, 
    // and still seeing whitespace, count the characters 
    // as skippable till we know otherwise
    bool skippable = skipStart != -1 && isWhitespace && firstNewline == -1;
    skipStart = skippable ? string.count + 1 : skipStart;
    
    // We've counted leading whitespace till we hit something else, 
    // but it's not a newline, so we reset skipStart since we need these characters
    if (firstNewline == -1 && !isWhitespace && c != '\n') skipStart = -1;

    if (c == '\0' || c1 == '\0' || c2 == '\0')
    {
      lexError(parser, "Unterminated raw string.");

      // Don't consume it if it isn't expected. Keeps us from reading past the
      // end of an unterminated string.
      parser->currentChar--;
      break;
    }
 
    wrenByteBufferWrite(parser->vm, &string, c);
  }

  //consume the second and third "
  nextChar(parser);
  nextChar(parser);

  int offset = 0;
  int count = string.count;

  if(firstNewline != -1 && skipStart == firstNewline) offset = firstNewline + 1;
  if(lastNewline != -1 && skipEnd == lastNewline) count = lastNewline;

  count -= (offset > count) ? count : offset;

  parser->next.value = wrenNewStringLength(parser->vm, 
                         ((char*)string.data) + offset, count);
  
  wrenByteBufferClear(parser->vm, &string);
  makeToken(parser, type);
}

// Finishes lexing a string literal.
static void readString(Parser* parser)
{
  ByteBuffer string;
  TokenType type = TOKEN_STRING;
  wrenByteBufferInit(&string);
  
  for (;;)
  {
    char c = nextChar(parser);
    if (c == '"') break;
    if (c == '\r') continue;

    if (c == '\0')
    {
      lexError(parser, "Unterminated string.");

      // Don't consume it if it isn't expected. Keeps us from reading past the
      // end of an unterminated string.
      parser->currentChar--;
      break;
    }

    if (c == '%')
    {
      if (parser->numParens < MAX_INTERPOLATION_NESTING)
      {
        // TODO: Allow format string.
        if (nextChar(parser) != '(') lexError(parser, "Expect '(' after '%%'.");
        
        parser->parens[parser->numParens++] = 1;
        type = TOKEN_INTERPOLATION;
        break;
      }

      lexError(parser, "Interpolation may only nest %d levels deep.",
               MAX_INTERPOLATION_NESTING);
    }
    
    if (c == '\\')
    {
      switch (nextChar(parser))
      {
        case '"':  wrenByteBufferWrite(parser->vm, &string, '"'); break;
        case '\\': wrenByteBufferWrite(parser->vm, &string, '\\'); break;
        case '%':  wrenByteBufferWrite(parser->vm, &string, '%'); break;
        case '0':  wrenByteBufferWrite(parser->vm, &string, '\0'); break;
        case 'a':  wrenByteBufferWrite(parser->vm, &string, '\a'); break;
        case 'b':  wrenByteBufferWrite(parser->vm, &string, '\b'); break;
        case 'e':  wrenByteBufferWrite(parser->vm, &string, '\33'); break;
        case 'f':  wrenByteBufferWrite(parser->vm, &string, '\f'); break;
        case 'n':  wrenByteBufferWrite(parser->vm, &string, '\n'); break;
        case 'r':  wrenByteBufferWrite(parser->vm, &string, '\r'); break;
        case 't':  wrenByteBufferWrite(parser->vm, &string, '\t'); break;
        case 'u':  readUnicodeEscape(parser, &string, 4); break;
        case 'U':  readUnicodeEscape(parser, &string, 8); break;
        case 'v':  wrenByteBufferWrite(parser->vm, &string, '\v'); break;
        case 'x':
          wrenByteBufferWrite(parser->vm, &string,
                              (uint8_t)readHexEscape(parser, 2, "byte"));
          break;

        default:
          lexError(parser, "Invalid escape character '%c'.",
                   *(parser->currentChar - 1));
          break;
      }
    }
    else
    {
      wrenByteBufferWrite(parser->vm, &string, c);
    }
  }

  parser->next.value = wrenNewStringLength(parser->vm,
                                              (char*)string.data, string.count);
  
  wrenByteBufferClear(parser->vm, &string);
  makeToken(parser, type);
}

// Lex the next token and store it in [parser.next].
static void nextToken(Parser* parser)
{
  parser->previous = parser->current;
  parser->current = parser->next;

  // If we are out of tokens, don't try to tokenize any more. We *do* still
  // copy the TOKEN_EOF to previous so that code that expects it to be consumed
  // will still work.
  if (parser->next.type == TOKEN_EOF) return;
  if (parser->current.type == TOKEN_EOF) return;
  
  while (peekChar(parser) != '\0')
  {
    parser->tokenStart = parser->currentChar;

    char c = nextChar(parser);
    switch (c)
    {
      case '(':
        // If we are inside an interpolated expression, count the unmatched "(".
        if (parser->numParens > 0) parser->parens[parser->numParens - 1]++;
        makeToken(parser, TOKEN_LEFT_PAREN);
        return;
        
      case ')':
        // If we are inside an interpolated expression, count the ")".
        if (parser->numParens > 0 &&
            --parser->parens[parser->numParens - 1] == 0)
        {
          // This is the final ")", so the interpolation expression has ended.
          // This ")" now begins the next section of the template string.
          parser->numParens--;
          readString(parser);
          return;
        }
        
        makeToken(parser, TOKEN_RIGHT_PAREN);
        return;
        
      case '[': makeToken(parser, TOKEN_LEFT_BRACKET); return;
      case ']': makeToken(parser, TOKEN_RIGHT_BRACKET); return;
      case '{': makeToken(parser, TOKEN_LEFT_BRACE); return;
      case '}': makeToken(parser, TOKEN_RIGHT_BRACE); return;
      case ':': makeToken(parser, TOKEN_COLON); return;
      case ',': makeToken(parser, TOKEN_COMMA); return;
      case '*': makeToken(parser, TOKEN_STAR); return;
      case '%': makeToken(parser, TOKEN_PERCENT); return;
      case '#': {
        // Ignore shebang on the first line.
        if (parser->currentLine == 1 && peekChar(parser) == '!' && peekNextChar(parser) == '/')
        {
          skipLineComment(parser);
          break;
        }
        // Otherwise we treat it as a token
        makeToken(parser, TOKEN_HASH); 
        return;
      }
      case '^': makeToken(parser, TOKEN_CARET); return;
      case '+': makeToken(parser, TOKEN_PLUS); return;
      case '-': makeToken(parser, TOKEN_MINUS); return;
      case '~': makeToken(parser, TOKEN_TILDE); return;
      case '?': makeToken(parser, TOKEN_QUESTION); return;
        
      case '|': twoCharToken(parser, '|', TOKEN_PIPEPIPE, TOKEN_PIPE); return;
      case '&': twoCharToken(parser, '&', TOKEN_AMPAMP, TOKEN_AMP); return;
      case '=': twoCharToken(parser, '=', TOKEN_EQEQ, TOKEN_EQ); return;
      case '!': twoCharToken(parser, '=', TOKEN_BANGEQ, TOKEN_BANG); return;
        
      case '.':
        if (matchChar(parser, '.'))
        {
          twoCharToken(parser, '.', TOKEN_DOTDOTDOT, TOKEN_DOTDOT);
          return;
        }
        
        makeToken(parser, TOKEN_DOT);
        return;
        
      case '/':
        if (matchChar(parser, '/'))
        {
          skipLineComment(parser);
          break;
        }

        if (matchChar(parser, '*'))
        {
          skipBlockComment(parser);
          break;
        }

        makeToken(parser, TOKEN_SLASH);
        return;

      case '<':
        if (matchChar(parser, '<'))
        {
          makeToken(parser, TOKEN_LTLT);
        }
        else
        {
          twoCharToken(parser, '=', TOKEN_LTEQ, TOKEN_LT);
        }
        return;

      case '>':
        if (matchChar(parser, '>'))
        {
          makeToken(parser, TOKEN_GTGT);
        }
        else
        {
          twoCharToken(parser, '=', TOKEN_GTEQ, TOKEN_GT);
        }
        return;

      case '\n':
        makeToken(parser, TOKEN_LINE);
        return;

      case ' ':
      case '\r':
      case '\t':
        // Skip forward until we run out of whitespace.
        while (peekChar(parser) == ' ' ||
               peekChar(parser) == '\r' ||
               peekChar(parser) == '\t')
        {
          nextChar(parser);
        }
        break;

      case '"': {
        if(peekChar(parser) == '"' && peekNextChar(parser)  == '"') {
          readRawString(parser);
          return;
        }
        readString(parser); return;
      }
      case '_':
        readName(parser,
                 peekChar(parser) == '_' ? TOKEN_STATIC_FIELD : TOKEN_FIELD, c);
        return;

      case '0':
        if (peekChar(parser) == 'x')
        {
          readHexNumber(parser);
          return;
        }

        readNumber(parser);
        return;

      default:
        if (isName(c))
        {
          readName(parser, TOKEN_NAME, c);
        }
        else if (isDigit(c))
        {
          readNumber(parser);
        }
        else
        {
          if (c >= 32 && c <= 126)
          {
            lexError(parser, "Invalid character '%c'.", c);
          }
          else
          {
            // Don't show non-ASCII values since we didn't UTF-8 decode the
            // bytes. Since there are no non-ASCII byte values that are
            // meaningful code units in Wren, the lexer works on raw bytes,
            // even though the source code and console output are UTF-8.
            lexError(parser, "Invalid byte 0x%x.", (uint8_t)c);
          }
          parser->next.type = TOKEN_ERROR;
          parser->next.length = 0;
        }
        return;
    }
  }

  // If we get here, we're out of source, so just make EOF tokens.
  parser->tokenStart = parser->currentChar;
  makeToken(parser, TOKEN_EOF);
}

// Parsing ---------------------------------------------------------------------

// Returns the type of the current token.
static TokenType peek(Compiler* compiler)
{
  return compiler->parser->current.type;
}

// Returns the type of the current token.
static TokenType peekNext(Compiler* compiler)
{
  return compiler->parser->next.type;
}

// Consumes the current token if its type is [expected]. Returns true if a
// token was consumed.
static bool match(Compiler* compiler, TokenType expected)
{
  if (peek(compiler) != expected) return false;

  nextToken(compiler->parser);
  return true;
}

// Consumes the current token. Emits an error if its type is not [expected].
static void consume(Compiler* compiler, TokenType expected,
                    const char* errorMessage)
{
  nextToken(compiler->parser);
  if (compiler->parser->previous.type != expected)
  {
    error(compiler, errorMessage);

    // If the next token is the one we want, assume the current one is just a
    // spurious error and discard it to minimize the number of cascaded errors.
    if (compiler->parser->current.type == expected) nextToken(compiler->parser);
  }
}

// Matches one or more newlines. Returns true if at least one was found.
static bool matchLine(Compiler* compiler)
{
  if (!match(compiler, TOKEN_LINE)) return false;

  while (match(compiler, TOKEN_LINE));
  return true;
}

// Discards any newlines starting at the current token.
static void ignoreNewlines(Compiler* compiler)
{
  matchLine(compiler);
}

// Consumes the current token. Emits an error if it is not a newline. Then
// discards any duplicate newlines following it.
static void consumeLine(Compiler* compiler, const char* errorMessage)
{
  consume(compiler, TOKEN_LINE, errorMessage);
  ignoreNewlines(compiler);
}

static void allowLineBeforeDot(Compiler* compiler) {
  if (peek(compiler) == TOKEN_LINE && peekNext(compiler) == TOKEN_DOT) {
    nextToken(compiler->parser);
  }
}

// Variables and scopes --------------------------------------------------------

// Emits one single-byte argument. Returns its index.
static int emitByte(Compiler* compiler, int byte)
{
  wrenByteBufferWrite(compiler->parser->vm, &compiler->fn->code, (uint8_t)byte);
  
  // Assume the instruction is associated with the most recently consumed token.
  wrenIntBufferWrite(compiler->parser->vm, &compiler->fn->debug->sourceLines,
                     compiler->parser->previous.line);
  
  return compiler->fn->code.count - 1;
}

// Emits one bytecode instruction.
static void emitOp(Compiler* compiler, Code instruction)
{
  emitByte(compiler, instruction);
  
  // Keep track of the stack's high water mark.
  compiler->numSlots += stackEffects[instruction];
  if (compiler->numSlots > compiler->fn->maxSlots)
  {
    compiler->fn->maxSlots = compiler->numSlots;
  }
}

// Emits one 16-bit argument, which will be written big endian.
static void emitShort(Compiler* compiler, int arg)
{
  emitByte(compiler, (arg >> 8) & 0xff);
  emitByte(compiler, arg & 0xff);
}

// Emits one bytecode instruction followed by a 8-bit argument. Returns the
// index of the argument in the bytecode.
static int emitByteArg(Compiler* compiler, Code instruction, int arg)
{
  emitOp(compiler, instruction);
  return emitByte(compiler, arg);
}

// Emits one bytecode instruction followed by a 16-bit argument, which will be
// written big endian.
static void emitShortArg(Compiler* compiler, Code instruction, int arg)
{
  emitOp(compiler, instruction);
  emitShort(compiler, arg);
}

// Emits [instruction] followed by a placeholder for a jump offset. The
// placeholder can be patched by calling [jumpPatch]. Returns the index of the
// placeholder.
static int emitJump(Compiler* compiler, Code instruction)
{
  emitOp(compiler, instruction);
  emitByte(compiler, 0xff);
  return emitByte(compiler, 0xff) - 1;
}

// Creates a new constant for the current value and emits the bytecode to load
// it from the constant table.
static void emitConstant(Compiler* compiler, Value value)
{
  int constant = addConstant(compiler, value);
  
  // Compile the code to load the constant.
  emitShortArg(compiler, CODE_CONSTANT, constant);
}

// Create a new local variable with [name]. Assumes the current scope is local
// and the name is unique.
static int addLocal(Compiler* compiler, const char* name, int length)
{
  Local* local = &compiler->locals[compiler->numLocals];
  local->name = name;
  local->length = length;
  local->depth = compiler->scopeDepth;
  local->isUpvalue = false;
  return compiler->numLocals++;
}

// Declares a variable in the current scope whose name is the given token.
//
// If [token] is `NULL`, uses the previously consumed token. Returns its symbol.
static int declareVariable(Compiler* compiler, Token* token)
{
  if (token == NULL) token = &compiler->parser->previous;

  if (token->length > MAX_VARIABLE_NAME)
  {
    error(compiler, "Variable name cannot be longer than %d characters.",
          MAX_VARIABLE_NAME);
  }

  // Top-level module scope.
  if (compiler->scopeDepth == -1)
  {
    int line = -1;
    int symbol = wrenDefineVariable(compiler->parser->vm,
                                    compiler->parser->module,
                                    token->start, token->length,
                                    NULL_VAL, &line);

    if (symbol == -1)
    {
      error(compiler, "Module variable is already defined.");
    }
    else if (symbol == -2)
    {
      error(compiler, "Too many module variables defined.");
    }
    else if (symbol == -3)
    {
      error(compiler,
        "Variable '%.*s' referenced before this definition (first use at line %d).",
        token->length, token->start, line);
    }

    return symbol;
  }

  // See if there is already a variable with this name declared in the current
  // scope. (Outer scopes are OK: those get shadowed.)
  for (int i = compiler->numLocals - 1; i >= 0; i--)
  {
    Local* local = &compiler->locals[i];

    // Once we escape this scope and hit an outer one, we can stop.
    if (local->depth < compiler->scopeDepth) break;

    if (local->length == token->length &&
        memcmp(local->name, token->start, token->length) == 0)
    {
      error(compiler, "Variable is already declared in this scope.");
      return i;
    }
  }

  if (compiler->numLocals == MAX_LOCALS)
  {
    error(compiler, "Cannot declare more than %d variables in one scope.",
          MAX_LOCALS);
    return -1;
  }

  return addLocal(compiler, token->start, token->length);
}

// Parses a name token and declares a variable in the current scope with that
// name. Returns its slot.
static int declareNamedVariable(Compiler* compiler)
{
  consume(compiler, TOKEN_NAME, "Expect variable name.");
  return declareVariable(compiler, NULL);
}

// Stores a variable with the previously defined symbol in the current scope.
static void defineVariable(Compiler* compiler, int symbol)
{
  // Store the variable. If it's a local, the result of the initializer is
  // in the correct slot on the stack already so we're done.
  if (compiler->scopeDepth >= 0) return;

  // It's a module-level variable, so store the value in the module slot and
  // then discard the temporary for the initializer.
  emitShortArg(compiler, CODE_STORE_MODULE_VAR, symbol);
  emitOp(compiler, CODE_POP);
}

// Starts a new local block scope.
static void pushScope(Compiler* compiler)
{
  compiler->scopeDepth++;
}

// Generates code to discard local variables at [depth] or greater. Does *not*
// actually undeclare variables or pop any scopes, though. This is called
// directly when compiling "break" statements to ditch the local variables
// before jumping out of the loop even though they are still in scope *past*
// the break instruction.
//
// Returns the number of local variables that were eliminated.
static int discardLocals(Compiler* compiler, int depth)
{
  ASSERT(compiler->scopeDepth > -1, "Cannot exit top-level scope.");

  int local = compiler->numLocals - 1;
  while (local >= 0 && compiler->locals[local].depth >= depth)
  {
    // If the local was closed over, make sure the upvalue gets closed when it
    // goes out of scope on the stack. We use emitByte() and not emitOp() here
    // because we don't want to track that stack effect of these pops since the
    // variables are still in scope after the break.
    if (compiler->locals[local].isUpvalue)
    {
      emitByte(compiler, CODE_CLOSE_UPVALUE);
    }
    else
    {
      emitByte(compiler, CODE_POP);
    }
    

    local--;
  }

  return compiler->numLocals - local - 1;
}

// Closes the last pushed block scope and discards any local variables declared
// in that scope. This should only be called in a statement context where no
// temporaries are still on the stack.
static void popScope(Compiler* compiler)
{
  int popped = discardLocals(compiler, compiler->scopeDepth);
  compiler->numLocals -= popped;
  compiler->numSlots -= popped;
  compiler->scopeDepth--;
}

// Attempts to look up the name in the local variables of [compiler]. If found,
// returns its index, otherwise returns -1.
static int resolveLocal(Compiler* compiler, const char* name, int length)
{
  // Look it up in the local scopes. Look in reverse order so that the most
  // nested variable is found first and shadows outer ones.
  for (int i = compiler->numLocals - 1; i >= 0; i--)
  {
    if (compiler->locals[i].length == length &&
        memcmp(name, compiler->locals[i].name, length) == 0)
    {
      return i;
    }
  }

  return -1;
}

// Adds an upvalue to [compiler]'s function with the given properties. Does not
// add one if an upvalue for that variable is already in the list. Returns the
// index of the upvalue.
static int addUpvalue(Compiler* compiler, bool isLocal, int index)
{
  // Look for an existing one.
  for (int i = 0; i < compiler->fn->numUpvalues; i++)
  {
    CompilerUpvalue* upvalue = &compiler->upvalues[i];
    if (upvalue->index == index && upvalue->isLocal == isLocal) return i;
  }

  // If we got here, it's a new upvalue.
  compiler->upvalues[compiler->fn->numUpvalues].isLocal = isLocal;
  compiler->upvalues[compiler->fn->numUpvalues].index = index;
  return compiler->fn->numUpvalues++;
}

// Attempts to look up [name] in the functions enclosing the one being compiled
// by [compiler]. If found, it adds an upvalue for it to this compiler's list
// of upvalues (unless it's already in there) and returns its index. If not
// found, returns -1.
//
// If the name is found outside of the immediately enclosing function, this
// will flatten the closure and add upvalues to all of the intermediate
// functions so that it gets walked down to this one.
//
// If it reaches a method boundary, this stops and returns -1 since methods do
// not close over local variables.
static int findUpvalue(Compiler* compiler, const char* name, int length)
{
  // If we are at the top level, we didn't find it.
  if (compiler->parent == NULL) return -1;
  
  // If we hit the method boundary (and the name isn't a static field), then
  // stop looking for it. We'll instead treat it as a self send.
  if (name[0] != '_' && compiler->parent->enclosingClass != NULL) return -1;
  
  // See if it's a local variable in the immediately enclosing function.
  int local = resolveLocal(compiler->parent, name, length);
  if (local != -1)
  {
    // Mark the local as an upvalue so we know to close it when it goes out of
    // scope.
    compiler->parent->locals[local].isUpvalue = true;

    return addUpvalue(compiler, true, local);
  }

  // See if it's an upvalue in the immediately enclosing function. In other
  // words, if it's a local variable in a non-immediately enclosing function.
  // This "flattens" closures automatically: it adds upvalues to all of the
  // intermediate functions to get from the function where a local is declared
  // all the way into the possibly deeply nested function that is closing over
  // it.
  int upvalue = findUpvalue(compiler->parent, name, length);
  if (upvalue != -1)
  {
    return addUpvalue(compiler, false, upvalue);
  }

  // If we got here, we walked all the way up the parent chain and couldn't
  // find it.
  return -1;
}

// Look up [name] in the current scope to see what variable it refers to.
// Returns the variable either in local scope, or the enclosing function's
// upvalue list. Does not search the module scope. Returns a variable with
// index -1 if not found.
static Variable resolveNonmodule(Compiler* compiler,
                                 const char* name, int length)
{
  // Look it up in the local scopes.
  Variable variable;
  variable.scope = SCOPE_LOCAL;
  variable.index = resolveLocal(compiler, name, length);
  if (variable.index != -1) return variable;

  // Tt's not a local, so guess that it's an upvalue.
  variable.scope = SCOPE_UPVALUE;
  variable.index = findUpvalue(compiler, name, length);
  return variable;
}

// Look up [name] in the current scope to see what variable it refers to.
// Returns the variable either in module scope, local scope, or the enclosing
// function's upvalue list. Returns a variable with index -1 if not found.
static Variable resolveName(Compiler* compiler, const char* name, int length)
{
  Variable variable = resolveNonmodule(compiler, name, length);
  if (variable.index != -1) return variable;

  variable.scope = SCOPE_MODULE;
  variable.index = wrenSymbolTableFind(&compiler->parser->module->variableNames,
                                       name, length);
  return variable;
}

static void loadLocal(Compiler* compiler, int slot)
{
  if (slot <= 8)
  {
    emitOp(compiler, (Code)(CODE_LOAD_LOCAL_0 + slot));
    return;
  }

  emitByteArg(compiler, CODE_LOAD_LOCAL, slot);
}

// Finishes [compiler], which is compiling a function, method, or chunk of top
// level code. If there is a parent compiler, then this emits code in the
// parent compiler to load the resulting function.
static ObjFn* endCompiler(Compiler* compiler,
                          const char* debugName, int debugNameLength)
{
  // If we hit an error, don't finish the function since it's borked anyway.
  if (compiler->parser->hasError)
  {
    compiler->parser->vm->compiler = compiler->parent;
    return NULL;
  }

  // Mark the end of the bytecode. Since it may contain multiple early returns,
  // we can't rely on CODE_RETURN to tell us we're at the end.
  emitOp(compiler, CODE_END);

  wrenFunctionBindName(compiler->parser->vm, compiler->fn,
                       debugName, debugNameLength);
  
  // In the function that contains this one, load the resulting function object.
  if (compiler->parent != NULL)
  {
    int constant = addConstant(compiler->parent, OBJ_VAL(compiler->fn));

    // Wrap the function in a closure. We do this even if it has no upvalues so
    // that the VM can uniformly assume all called objects are closures. This
    // makes creating a function a little slower, but makes invoking them
    // faster. Given that functions are invoked more often than they are
    // created, this is a win.
    emitShortArg(compiler->parent, CODE_CLOSURE, constant);

    // Emit arguments for each upvalue to know whether to capture a local or
    // an upvalue.
    for (int i = 0; i < compiler->fn->numUpvalues; i++)
    {
      emitByte(compiler->parent, compiler->upvalues[i].isLocal ? 1 : 0);
      emitByte(compiler->parent, compiler->upvalues[i].index);
    }
  }

  // Pop this compiler off the stack.
  compiler->parser->vm->compiler = compiler->parent;
  
  #if WREN_DEBUG_DUMP_COMPILED_CODE
    wrenDumpCode(compiler->parser->vm, compiler->fn);
  #endif

  return compiler->fn;
}

// Grammar ---------------------------------------------------------------------

typedef enum
{
  PREC_NONE,
  PREC_LOWEST,
  PREC_ASSIGNMENT,    // =
  PREC_CONDITIONAL,   // ?:
  PREC_LOGICAL_OR,    // ||
  PREC_LOGICAL_AND,   // &&
  PREC_EQUALITY,      // == !=
  PREC_IS,            // is
  PREC_COMPARISON,    // < > <= >=
  PREC_BITWISE_OR,    // |
  PREC_BITWISE_XOR,   // ^
  PREC_BITWISE_AND,   // &
  PREC_BITWISE_SHIFT, // << >>
  PREC_RANGE,         // .. ...
  PREC_TERM,          // + -
  PREC_FACTOR,        // * / %
  PREC_UNARY,         // unary - ! ~
  PREC_CALL,          // . () []
  PREC_PRIMARY
} Precedence;

typedef void (*GrammarFn)(Compiler*, bool canAssign);

typedef void (*SignatureFn)(Compiler* compiler, Signature* signature);

typedef struct
{
  GrammarFn prefix;
  GrammarFn infix;
  SignatureFn method;
  Precedence precedence;
  const char* name;
} GrammarRule;

// Forward declarations since the grammar is recursive.
static GrammarRule* getRule(TokenType type);
static void expression(Compiler* compiler);
static void statement(Compiler* compiler);
static void definition(Compiler* compiler);
static void parsePrecedence(Compiler* compiler, Precedence precedence);

// Replaces the placeholder argument for a previous CODE_JUMP or CODE_JUMP_IF
// instruction with an offset that jumps to the current end of bytecode.
static void patchJump(Compiler* compiler, int offset)
{
  // -2 to adjust for the bytecode for the jump offset itself.
  int jump = compiler->fn->code.count - offset - 2;
  if (jump > MAX_JUMP) error(compiler, "Too much code to jump over.");

  compiler->fn->code.data[offset] = (jump >> 8) & 0xff;
  compiler->fn->code.data[offset + 1] = jump & 0xff;
}

// Parses a block body, after the initial "{" has been consumed.
//
// Returns true if it was a expression body, false if it was a statement body.
// (More precisely, returns true if a value was left on the stack. An empty
// block returns false.)
static bool finishBlock(Compiler* compiler)
{
  // Empty blocks do nothing.
  if (match(compiler, TOKEN_RIGHT_BRACE)) return false;

  // If there's no line after the "{", it's a single-expression body.
  if (!matchLine(compiler))
  {
    expression(compiler);
    consume(compiler, TOKEN_RIGHT_BRACE, "Expect '}' at end of block.");
    return true;
  }

  // Empty blocks (with just a newline inside) do nothing.
  if (match(compiler, TOKEN_RIGHT_BRACE)) return false;

  // Compile the definition list.
  do
  {
    definition(compiler);
    consumeLine(compiler, "Expect newline after statement.");
  }
  while (peek(compiler) != TOKEN_RIGHT_BRACE && peek(compiler) != TOKEN_EOF);
  
  consume(compiler, TOKEN_RIGHT_BRACE, "Expect '}' at end of block.");
  return false;
}

// Parses a method or function body, after the initial "{" has been consumed.
//
// If [Compiler->isInitializer] is `true`, this is the body of a constructor
// initializer. In that case, this adds the code to ensure it returns `this`.
static void finishBody(Compiler* compiler)
{
  bool isExpressionBody = finishBlock(compiler);

  if (compiler->isInitializer)
  {
    // If the initializer body evaluates to a value, discard it.
    if (isExpressionBody) emitOp(compiler, CODE_POP);

    // The receiver is always stored in the first local slot.
    emitOp(compiler, CODE_LOAD_LOCAL_0);
  }
  else if (!isExpressionBody)
  {
    // Implicitly return null in statement bodies.
    emitOp(compiler, CODE_NULL);
  }

  emitOp(compiler, CODE_RETURN);
}

// The VM can only handle a certain number of parameters, so check that we
// haven't exceeded that and give a usable error.
static void validateNumParameters(Compiler* compiler, int numArgs)
{
  if (numArgs == MAX_PARAMETERS + 1)
  {
    // Only show an error at exactly max + 1 so that we can keep parsing the
    // parameters and minimize cascaded errors.
    error(compiler, "Methods cannot have more than %d parameters.",
          MAX_PARAMETERS);
  }
}

// Parses the rest of a comma-separated parameter list after the opening
// delimeter. Updates `arity` in [signature] with the number of parameters.
static void finishParameterList(Compiler* compiler, Signature* signature)
{
  do
  {
    ignoreNewlines(compiler);
    validateNumParameters(compiler, ++signature->arity);

    // Define a local variable in the method for the parameter.
    declareNamedVariable(compiler);
  }
  while (match(compiler, TOKEN_COMMA));
}

// Gets the symbol for a method [name] with [length].
static int methodSymbol(Compiler* compiler, const char* name, int length)
{
  return wrenSymbolTableEnsure(compiler->parser->vm,
      &compiler->parser->vm->methodNames, name, length);
}

// Appends characters to [name] (and updates [length]) for [numParams] "_"
// surrounded by [leftBracket] and [rightBracket].
static void signatureParameterList(char name[MAX_METHOD_SIGNATURE], int* length,
                                   int numParams, char leftBracket, char rightBracket)
{
  name[(*length)++] = leftBracket;

  // This function may be called with too many parameters. When that happens,
  // a compile error has already been reported, but we need to make sure we
  // don't overflow the string too, hence the MAX_PARAMETERS check.
  for (int i = 0; i < numParams && i < MAX_PARAMETERS; i++)
  {
    if (i > 0) name[(*length)++] = ',';
    name[(*length)++] = '_';
  }
  name[(*length)++] = rightBracket;
}

// Fills [name] with the stringified version of [signature] and updates
// [length] to the resulting length.
static void signatureToString(Signature* signature,
                              char name[MAX_METHOD_SIGNATURE], int* length)
{
  *length = 0;

  // Build the full name from the signature.
  memcpy(name + *length, signature->name, signature->length);
  *length += signature->length;

  switch (signature->type)
  {
    case SIG_METHOD:
      signatureParameterList(name, length, signature->arity, '(', ')');
      break;

    case SIG_GETTER:
      // The signature is just the name.
      break;

    case SIG_SETTER:
      name[(*length)++] = '=';
      signatureParameterList(name, length, 1, '(', ')');
      break;

    case SIG_SUBSCRIPT:
      signatureParameterList(name, length, signature->arity, '[', ']');
      break;

    case SIG_SUBSCRIPT_SETTER:
      signatureParameterList(name, length, signature->arity - 1, '[', ']');
      name[(*length)++] = '=';
      signatureParameterList(name, length, 1, '(', ')');
      break;
      
    case SIG_INITIALIZER:
      memcpy(name, "init ", 5);
      memcpy(name + 5, signature->name, signature->length);
      *length = 5 + signature->length;
      signatureParameterList(name, length, signature->arity, '(', ')');
      break;
  }

  name[*length] = '\0';
}

// Gets the symbol for a method with [signature].
static int signatureSymbol(Compiler* compiler, Signature* signature)
{
  // Build the full name from the signature.
  char name[MAX_METHOD_SIGNATURE];
  int length;
  signatureToString(signature, name, &length);

  return methodSymbol(compiler, name, length);
}

// Returns a signature with [type] whose name is from the last consumed token.
static Signature signatureFromToken(Compiler* compiler, SignatureType type)
{
  Signature signature;
  
  // Get the token for the method name.
  Token* token = &compiler->parser->previous;
  signature.name = token->start;
  signature.length = token->length;
  signature.type = type;
  signature.arity = 0;

  if (signature.length > MAX_METHOD_NAME)
  {
    error(compiler, "Method names cannot be longer than %d characters.",
          MAX_METHOD_NAME);
    signature.length = MAX_METHOD_NAME;
  }
  
  return signature;
}

// Parses a comma-separated list of arguments. Modifies [signature] to include
// the arity of the argument list.
static void finishArgumentList(Compiler* compiler, Signature* signature)
{
  do
  {
    ignoreNewlines(compiler);
    validateNumParameters(compiler, ++signature->arity);
    expression(compiler);
  }
  while (match(compiler, TOKEN_COMMA));

  // Allow a newline before the closing delimiter.
  ignoreNewlines(compiler);
}

// Compiles a method call with [signature] using [instruction].
static void callSignature(Compiler* compiler, Code instruction,
                          Signature* signature)
{
  int symbol = signatureSymbol(compiler, signature);
  emitShortArg(compiler, (Code)(instruction + signature->arity), symbol);

  if (instruction == CODE_SUPER_0)
  {
    // Super calls need to be statically bound to the class's superclass. This
    // ensures we call the right method even when a method containing a super
    // call is inherited by another subclass.
    //
    // We bind it at class definition time by storing a reference to the
    // superclass in a constant. So, here, we create a slot in the constant
    // table and store NULL in it. When the method is bound, we'll look up the
    // superclass then and store it in the constant slot.
    emitShort(compiler, addConstant(compiler, NULL_VAL));
  }
}

// Compiles a method call with [numArgs] for a method with [name] with [length].
static void callMethod(Compiler* compiler, int numArgs, const char* name,
                       int length)
{
  int symbol = methodSymbol(compiler, name, length);
  emitShortArg(compiler, (Code)(CODE_CALL_0 + numArgs), symbol);
}

// Compiles an (optional) argument list for a method call with [methodSignature]
// and then calls it.
static void methodCall(Compiler* compiler, Code instruction,
                       Signature* signature)
{
  // Make a new signature that contains the updated arity and type based on
  // the arguments we find.
  Signature called = { signature->name, signature->length, SIG_GETTER, 0 };

  // Parse the argument list, if any.
  if (match(compiler, TOKEN_LEFT_PAREN))
  {
    called.type = SIG_METHOD;

    // Allow new line before an empty argument list
    ignoreNewlines(compiler);

    // Allow empty an argument list.
    if (peek(compiler) != TOKEN_RIGHT_PAREN)
    {
      finishArgumentList(compiler, &called);
    }
    consume(compiler, TOKEN_RIGHT_PAREN, "Expect ')' after arguments.");
  }

  // Parse the block argument, if any.
  if (match(compiler, TOKEN_LEFT_BRACE))
  {
    // Include the block argument in the arity.
    called.type = SIG_METHOD;
    called.arity++;

    Compiler fnCompiler;
    initCompiler(&fnCompiler, compiler->parser, compiler, false);

    // Make a dummy signature to track the arity.
    Signature fnSignature = { "", 0, SIG_METHOD, 0 };

    // Parse the parameter list, if any.
    if (match(compiler, TOKEN_PIPE))
    {
      finishParameterList(&fnCompiler, &fnSignature);
      consume(compiler, TOKEN_PIPE, "Expect '|' after function parameters.");
    }

    fnCompiler.fn->arity = fnSignature.arity;

    finishBody(&fnCompiler);

    // Name the function based on the method its passed to.
    char blockName[MAX_METHOD_SIGNATURE + 15];
    int blockLength;
    signatureToString(&called, blockName, &blockLength);
    memmove(blockName + blockLength, " block argument", 16);

    endCompiler(&fnCompiler, blockName, blockLength + 15);
  }

  // TODO: Allow Grace-style mixfix methods?

  // If this is a super() call for an initializer, make sure we got an actual
  // argument list.
  if (signature->type == SIG_INITIALIZER)
  {
    if (called.type != SIG_METHOD)
    {
      error(compiler, "A superclass constructor must have an argument list.");
    }
    
    called.type = SIG_INITIALIZER;
  }
  
  callSignature(compiler, instruction, &called);
}

// Compiles a call whose name is the previously consumed token. This includes
// getters, method calls with arguments, and setter calls.
static void namedCall(Compiler* compiler, bool canAssign, Code instruction)
{
  // Get the token for the method name.
  Signature signature = signatureFromToken(compiler, SIG_GETTER);

  if (canAssign && match(compiler, TOKEN_EQ))
  {
    ignoreNewlines(compiler);

    // Build the setter signature.
    signature.type = SIG_SETTER;
    signature.arity = 1;

    // Compile the assigned value.
    expression(compiler);
    callSignature(compiler, instruction, &signature);
  }
  else
  {
    methodCall(compiler, instruction, &signature);
    allowLineBeforeDot(compiler);
  }
}

// Emits the code to load [variable] onto the stack.
static void loadVariable(Compiler* compiler, Variable variable)
{
  switch (variable.scope)
  {
    case SCOPE_LOCAL:
      loadLocal(compiler, variable.index);
      break;
    case SCOPE_UPVALUE:
      emitByteArg(compiler, CODE_LOAD_UPVALUE, variable.index);
      break;
    case SCOPE_MODULE:
      emitShortArg(compiler, CODE_LOAD_MODULE_VAR, variable.index);
      break;
    default:
      UNREACHABLE();
  }
}

// Loads the receiver of the currently enclosing method. Correctly handles
// functions defined inside methods.
static void loadThis(Compiler* compiler)
{
  loadVariable(compiler, resolveNonmodule(compiler, "this", 4));
}

// Pushes the value for a module-level variable implicitly imported from core.
static void loadCoreVariable(Compiler* compiler, const char* name)
{
  int symbol = wrenSymbolTableFind(&compiler->parser->module->variableNames,
                                   name, strlen(name));
  ASSERT(symbol != -1, "Should have already defined core name.");
  emitShortArg(compiler, CODE_LOAD_MODULE_VAR, symbol);
}

// A parenthesized expression.
static void grouping(Compiler* compiler, bool canAssign)
{
  expression(compiler);
  consume(compiler, TOKEN_RIGHT_PAREN, "Expect ')' after expression.");
}

// A list literal.
static void list(Compiler* compiler, bool canAssign)
{
  // Instantiate a new list.
  loadCoreVariable(compiler, "List");
  callMethod(compiler, 0, "new()", 5);
  
  // Compile the list elements. Each one compiles to a ".add()" call.
  do
  {
    ignoreNewlines(compiler);

    // Stop if we hit the end of the list.
    if (peek(compiler) == TOKEN_RIGHT_BRACKET) break;

    // The element.
    expression(compiler);
    callMethod(compiler, 1, "addCore_(_)", 11);
  } while (match(compiler, TOKEN_COMMA));

  // Allow newlines before the closing ']'.
  ignoreNewlines(compiler);
  consume(compiler, TOKEN_RIGHT_BRACKET, "Expect ']' after list elements.");
}

// A map literal.
static void map(Compiler* compiler, bool canAssign)
{
  // Instantiate a new map.
  loadCoreVariable(compiler, "Map");
  callMethod(compiler, 0, "new()", 5);

  // Compile the map elements. Each one is compiled to just invoke the
  // subscript setter on the map.
  do
  {
    ignoreNewlines(compiler);

    // Stop if we hit the end of the map.
    if (peek(compiler) == TOKEN_RIGHT_BRACE) break;

    // The key.
    parsePrecedence(compiler, PREC_UNARY);
    consume(compiler, TOKEN_COLON, "Expect ':' after map key.");
    ignoreNewlines(compiler);

    // The value.
    expression(compiler);
    callMethod(compiler, 2, "addCore_(_,_)", 13);
  } while (match(compiler, TOKEN_COMMA));

  // Allow newlines before the closing '}'.
  ignoreNewlines(compiler);
  consume(compiler, TOKEN_RIGHT_BRACE, "Expect '}' after map entries.");
}

// Unary operators like `-foo`.
static void unaryOp(Compiler* compiler, bool canAssign)
{
  GrammarRule* rule = getRule(compiler->parser->previous.type);

  ignoreNewlines(compiler);

  // Compile the argument.
  parsePrecedence(compiler, (Precedence)(PREC_UNARY + 1));

  // Call the operator method on the left-hand side.
  callMethod(compiler, 0, rule->name, 1);
}

static void boolean(Compiler* compiler, bool canAssign)
{
  emitOp(compiler,
      compiler->parser->previous.type == TOKEN_FALSE ? CODE_FALSE : CODE_TRUE);
}

// Walks the compiler chain to find the compiler for the nearest class
// enclosing this one. Returns NULL if not currently inside a class definition.
static Compiler* getEnclosingClassCompiler(Compiler* compiler)
{
  while (compiler != NULL)
  {
    if (compiler->enclosingClass != NULL) return compiler;
    compiler = compiler->parent;
  }

  return NULL;
}

// Walks the compiler chain to find the nearest class enclosing this one.
// Returns NULL if not currently inside a class definition.
static ClassInfo* getEnclosingClass(Compiler* compiler)
{
  compiler = getEnclosingClassCompiler(compiler);
  return compiler == NULL ? NULL : compiler->enclosingClass;
}

static void field(Compiler* compiler, bool canAssign)
{
  // Initialize it with a fake value so we can keep parsing and minimize the
  // number of cascaded errors.
  int field = MAX_FIELDS;

  ClassInfo* enclosingClass = getEnclosingClass(compiler);

  if (enclosingClass == NULL)
  {
    error(compiler, "Cannot reference a field outside of a class definition.");
  }
  else if (enclosingClass->isForeign)
  {
    error(compiler, "Cannot define fields in a foreign class.");
  }
  else if (enclosingClass->inStatic)
  {
    error(compiler, "Cannot use an instance field in a static method.");
  }
  else
  {
    // Look up the field, or implicitly define it.
    field = wrenSymbolTableEnsure(compiler->parser->vm, &enclosingClass->fields,
        compiler->parser->previous.start,
        compiler->parser->previous.length);

    if (field >= MAX_FIELDS)
    {
      error(compiler, "A class can only have %d fields.", MAX_FIELDS);
    }
  }

  // If there's an "=" after a field name, it's an assignment.
  bool isLoad = true;
  if (canAssign && match(compiler, TOKEN_EQ))
  {
    // Compile the right-hand side.
    expression(compiler);
    isLoad = false;
  }

  // If we're directly inside a method, use a more optimal instruction.
  if (compiler->parent != NULL &&
      compiler->parent->enclosingClass == enclosingClass)
  {
    emitByteArg(compiler, isLoad ? CODE_LOAD_FIELD_THIS : CODE_STORE_FIELD_THIS,
                field);
  }
  else
  {
    loadThis(compiler);
    emitByteArg(compiler, isLoad ? CODE_LOAD_FIELD : CODE_STORE_FIELD, field);
  }

  allowLineBeforeDot(compiler);
}

// Compiles a read or assignment to [variable].
static void bareName(Compiler* compiler, bool canAssign, Variable variable)
{
  // If there's an "=" after a bare name, it's a variable assignment.
  if (canAssign && match(compiler, TOKEN_EQ))
  {
    // Compile the right-hand side.
    expression(compiler);

    // Emit the store instruction.
    switch (variable.scope)
    {
      case SCOPE_LOCAL:
        emitByteArg(compiler, CODE_STORE_LOCAL, variable.index);
        break;
      case SCOPE_UPVALUE:
        emitByteArg(compiler, CODE_STORE_UPVALUE, variable.index);
        break;
      case SCOPE_MODULE:
        emitShortArg(compiler, CODE_STORE_MODULE_VAR, variable.index);
        break;
      default:
        UNREACHABLE();
    }
    return;
  }

  // Emit the load instruction.
  loadVariable(compiler, variable);

  allowLineBeforeDot(compiler);
}

static void staticField(Compiler* compiler, bool canAssign)
{
  Compiler* classCompiler = getEnclosingClassCompiler(compiler);
  if (classCompiler == NULL)
  {
    error(compiler, "Cannot use a static field outside of a class definition.");
    return;
  }

  // Look up the name in the scope chain.
  Token* token = &compiler->parser->previous;

  // If this is the first time we've seen this static field, implicitly
  // define it as a variable in the scope surrounding the class definition.
  if (resolveLocal(classCompiler, token->start, token->length) == -1)
  {
    int symbol = declareVariable(classCompiler, NULL);

    // Implicitly initialize it to null.
    emitOp(classCompiler, CODE_NULL);
    defineVariable(classCompiler, symbol);
  }

  // It definitely exists now, so resolve it properly. This is different from
  // the above resolveLocal() call because we may have already closed over it
  // as an upvalue.
  Variable variable = resolveName(compiler, token->start, token->length);
  bareName(compiler, canAssign, variable);
}

// Compiles a variable name or method call with an implicit receiver.
static void name(Compiler* compiler, bool canAssign)
{
  // Look for the name in the scope chain up to the nearest enclosing method.
  Token* token = &compiler->parser->previous;

  Variable variable = resolveNonmodule(compiler, token->start, token->length);
  if (variable.index != -1)
  {
    bareName(compiler, canAssign, variable);
    return;
  }

  // TODO: The fact that we return above here if the variable is known and parse
  // an optional argument list below if not means that the grammar is not
  // context-free. A line of code in a method like "someName(foo)" is a parse
  // error if "someName" is a defined variable in the surrounding scope and not
  // if it isn't. Fix this. One option is to have "someName(foo)" always
  // resolve to a self-call if there is an argument list, but that makes
  // getters a little confusing.

  // If we're inside a method and the name is lowercase, treat it as a method
  // on this.
  if (wrenIsLocalName(token->start) && getEnclosingClass(compiler) != NULL)
  {
    loadThis(compiler);
    namedCall(compiler, canAssign, CODE_CALL_0);
    return;
  }

  // Otherwise, look for a module-level variable with the name.
  variable.scope = SCOPE_MODULE;
  variable.index = wrenSymbolTableFind(&compiler->parser->module->variableNames,
                                       token->start, token->length);
  if (variable.index == -1)
  {
    // Implicitly define a module-level variable in
    // the hopes that we get a real definition later.
    variable.index = wrenDeclareVariable(compiler->parser->vm,
                                         compiler->parser->module,
                                         token->start, token->length,
                                         token->line);

    if (variable.index == -2)
    {
      error(compiler, "Too many module variables defined.");
    }
  }
  
  bareName(compiler, canAssign, variable);
}

static void null(Compiler* compiler, bool canAssign)
{
  emitOp(compiler, CODE_NULL);
}

// A number or string literal.
static void literal(Compiler* compiler, bool canAssign)
{
  emitConstant(compiler, compiler->parser->previous.value);
}

// A string literal that contains interpolated expressions.
//
// Interpolation is syntactic sugar for calling ".join()" on a list. So the
// string:
//
//     "a %(b + c) d"
//
// is compiled roughly like:
//
//     ["a ", b + c, " d"].join()
static void stringInterpolation(Compiler* compiler, bool canAssign)
{
  // Instantiate a new list.
  loadCoreVariable(compiler, "List");
  callMethod(compiler, 0, "new()", 5);
  
  do
  {
    // The opening string part.
    literal(compiler, false);
    callMethod(compiler, 1, "addCore_(_)", 11);
    
    // The interpolated expression.
    ignoreNewlines(compiler);
    expression(compiler);
    callMethod(compiler, 1, "addCore_(_)", 11);
    
    ignoreNewlines(compiler);
  } while (match(compiler, TOKEN_INTERPOLATION));
  
  // The trailing string part.
  consume(compiler, TOKEN_STRING, "Expect end of string interpolation.");
  literal(compiler, false);
  callMethod(compiler, 1, "addCore_(_)", 11);
  
  // The list of interpolated parts.
  callMethod(compiler, 0, "join()", 6);
}

static void super_(Compiler* compiler, bool canAssign)
{
  ClassInfo* enclosingClass = getEnclosingClass(compiler);
  if (enclosingClass == NULL)
  {
    error(compiler, "Cannot use 'super' outside of a method.");
  }

  loadThis(compiler);

  // TODO: Super operator calls.
  // TODO: There's no syntax for invoking a superclass constructor with a
  // different name from the enclosing one. Figure that out.

  // See if it's a named super call, or an unnamed one.
  if (match(compiler, TOKEN_DOT))
  {
    // Compile the superclass call.
    consume(compiler, TOKEN_NAME, "Expect method name after 'super.'.");
    namedCall(compiler, canAssign, CODE_SUPER_0);
  }
  else if (enclosingClass != NULL)
  {
    // No explicit name, so use the name of the enclosing method. Make sure we
    // check that enclosingClass isn't NULL first. We've already reported the
    // error, but we don't want to crash here.
    methodCall(compiler, CODE_SUPER_0, enclosingClass->signature);
  }
}

static void this_(Compiler* compiler, bool canAssign)
{
  if (getEnclosingClass(compiler) == NULL)
  {
    error(compiler, "Cannot use 'this' outside of a method.");
    return;
  }

  loadThis(compiler);
}

// Subscript or "array indexing" operator like `foo[bar]`.
static void subscript(Compiler* compiler, bool canAssign)
{
  Signature signature = { "", 0, SIG_SUBSCRIPT, 0 };

  // Parse the argument list.
  finishArgumentList(compiler, &signature);
  consume(compiler, TOKEN_RIGHT_BRACKET, "Expect ']' after arguments.");

  allowLineBeforeDot(compiler);

  if (canAssign && match(compiler, TOKEN_EQ))
  {
    signature.type = SIG_SUBSCRIPT_SETTER;

    // Compile the assigned value.
    validateNumParameters(compiler, ++signature.arity);
    expression(compiler);
  }

  callSignature(compiler, CODE_CALL_0, &signature);
}

static void call(Compiler* compiler, bool canAssign)
{
  ignoreNewlines(compiler);
  consume(compiler, TOKEN_NAME, "Expect method name after '.'.");
  namedCall(compiler, canAssign, CODE_CALL_0);
}

static void and_(Compiler* compiler, bool canAssign)
{
  ignoreNewlines(compiler);

  // Skip the right argument if the left is false.
  int jump = emitJump(compiler, CODE_AND);
  parsePrecedence(compiler, PREC_LOGICAL_AND);
  patchJump(compiler, jump);
}

static void or_(Compiler* compiler, bool canAssign)
{
  ignoreNewlines(compiler);

  // Skip the right argument if the left is true.
  int jump = emitJump(compiler, CODE_OR);
  parsePrecedence(compiler, PREC_LOGICAL_OR);
  patchJump(compiler, jump);
}

static void conditional(Compiler* compiler, bool canAssign)
{
  // Ignore newline after '?'.
  ignoreNewlines(compiler);

  // Jump to the else branch if the condition is false.
  int ifJump = emitJump(compiler, CODE_JUMP_IF);

  // Compile the then branch.
  parsePrecedence(compiler, PREC_CONDITIONAL);

  consume(compiler, TOKEN_COLON,
          "Expect ':' after then branch of conditional operator.");
  ignoreNewlines(compiler);

  // Jump over the else branch when the if branch is taken.
  int elseJump = emitJump(compiler, CODE_JUMP);

  // Compile the else branch.
  patchJump(compiler, ifJump);

  parsePrecedence(compiler, PREC_ASSIGNMENT);

  // Patch the jump over the else.
  patchJump(compiler, elseJump);
}

void infixOp(Compiler* compiler, bool canAssign)
{
  GrammarRule* rule = getRule(compiler->parser->previous.type);

  // An infix operator cannot end an expression.
  ignoreNewlines(compiler);

  // Compile the right-hand side.
  parsePrecedence(compiler, (Precedence)(rule->precedence + 1));

  // Call the operator method on the left-hand side.
  Signature signature = { rule->name, (int)strlen(rule->name), SIG_METHOD, 1 };
  callSignature(compiler, CODE_CALL_0, &signature);
}

// Compiles a method signature for an infix operator.
void infixSignature(Compiler* compiler, Signature* signature)
{
  // Add the RHS parameter.
  signature->type = SIG_METHOD;
  signature->arity = 1;

  // Parse the parameter name.
  consume(compiler, TOKEN_LEFT_PAREN, "Expect '(' after operator name.");
  declareNamedVariable(compiler);
  consume(compiler, TOKEN_RIGHT_PAREN, "Expect ')' after parameter name.");
}

// Compiles a method signature for an unary operator (i.e. "!").
void unarySignature(Compiler* compiler, Signature* signature)
{
  // Do nothing. The name is already complete.
  signature->type = SIG_GETTER;
}

// Compiles a method signature for an operator that can either be unary or
// infix (i.e. "-").
void mixedSignature(Compiler* compiler, Signature* signature)
{
  signature->type = SIG_GETTER;

  // If there is a parameter, it's an infix operator, otherwise it's unary.
  if (match(compiler, TOKEN_LEFT_PAREN))
  {
    // Add the RHS parameter.
    signature->type = SIG_METHOD;
    signature->arity = 1;

    // Parse the parameter name.
    declareNamedVariable(compiler);
    consume(compiler, TOKEN_RIGHT_PAREN, "Expect ')' after parameter name.");
  }
}

// Compiles an optional setter parameter in a method [signature].
//
// Returns `true` if it was a setter.
static bool maybeSetter(Compiler* compiler, Signature* signature)
{
  // See if it's a setter.
  if (!match(compiler, TOKEN_EQ)) return false;

  // It's a setter.
  if (signature->type == SIG_SUBSCRIPT)
  {
    signature->type = SIG_SUBSCRIPT_SETTER;
  }
  else
  {
    signature->type = SIG_SETTER;
  }

  // Parse the value parameter.
  consume(compiler, TOKEN_LEFT_PAREN, "Expect '(' after '='.");
  declareNamedVariable(compiler);
  consume(compiler, TOKEN_RIGHT_PAREN, "Expect ')' after parameter name.");

  signature->arity++;

  return true;
}

// Compiles a method signature for a subscript operator.
void subscriptSignature(Compiler* compiler, Signature* signature)
{
  signature->type = SIG_SUBSCRIPT;

  // The signature currently has "[" as its name since that was the token that
  // matched it. Clear that out.
  signature->length = 0;

  // Parse the parameters inside the subscript.
  finishParameterList(compiler, signature);
  consume(compiler, TOKEN_RIGHT_BRACKET, "Expect ']' after parameters.");

  maybeSetter(compiler, signature);
}

// Parses an optional parenthesized parameter list. Updates `type` and `arity`
// in [signature] to match what was parsed.
static void parameterList(Compiler* compiler, Signature* signature)
{
  // The parameter list is optional.
  if (!match(compiler, TOKEN_LEFT_PAREN)) return;
  
  signature->type = SIG_METHOD;
  
  // Allow new line before an empty argument list
  ignoreNewlines(compiler);

  // Allow an empty parameter list.
  if (match(compiler, TOKEN_RIGHT_PAREN)) return;

  finishParameterList(compiler, signature);
  consume(compiler, TOKEN_RIGHT_PAREN, "Expect ')' after parameters.");
}

// Compiles a method signature for a named method or setter.
void namedSignature(Compiler* compiler, Signature* signature)
{
  signature->type = SIG_GETTER;
  
  // If it's a setter, it can't also have a parameter list.
  if (maybeSetter(compiler, signature)) return;

  // Regular named method with an optional parameter list.
  parameterList(compiler, signature);
}

// Compiles a method signature for a constructor.
void constructorSignature(Compiler* compiler, Signature* signature)
{
  consume(compiler, TOKEN_NAME, "Expect constructor name after 'construct'.");
  
  // Capture the name.
  *signature = signatureFromToken(compiler, SIG_INITIALIZER);
  
  if (match(compiler, TOKEN_EQ))
  {
    error(compiler, "A constructor cannot be a setter.");
  }

  if (!match(compiler, TOKEN_LEFT_PAREN))
  {
    error(compiler, "A constructor cannot be a getter.");
    return;
  }
  
  // Allow an empty parameter list.
  if (match(compiler, TOKEN_RIGHT_PAREN)) return;
  
  finishParameterList(compiler, signature);
  consume(compiler, TOKEN_RIGHT_PAREN, "Expect ')' after parameters.");
}

// This table defines all of the parsing rules for the prefix and infix
// expressions in the grammar. Expressions are parsed using a Pratt parser.
//
// See: http://journal.stuffwithstuff.com/2011/03/19/pratt-parsers-expression-parsing-made-easy/
#define UNUSED                     { NULL, NULL, NULL, PREC_NONE, NULL }
#define PREFIX(fn)                 { fn, NULL, NULL, PREC_NONE, NULL }
#define INFIX(prec, fn)            { NULL, fn, NULL, prec, NULL }
#define INFIX_OPERATOR(prec, name) { NULL, infixOp, infixSignature, prec, name }
#define PREFIX_OPERATOR(name)      { unaryOp, NULL, unarySignature, PREC_NONE, name }
#define OPERATOR(name)             { unaryOp, infixOp, mixedSignature, PREC_TERM, name }

GrammarRule rules[] =
{
  /* TOKEN_LEFT_PAREN    */ PREFIX(grouping),
  /* TOKEN_RIGHT_PAREN   */ UNUSED,
  /* TOKEN_LEFT_BRACKET  */ { list, subscript, subscriptSignature, PREC_CALL, NULL },
  /* TOKEN_RIGHT_BRACKET */ UNUSED,
  /* TOKEN_LEFT_BRACE    */ PREFIX(map),
  /* TOKEN_RIGHT_BRACE   */ UNUSED,
  /* TOKEN_COLON         */ UNUSED,
  /* TOKEN_DOT           */ INFIX(PREC_CALL, call),
  /* TOKEN_DOTDOT        */ INFIX_OPERATOR(PREC_RANGE, ".."),
  /* TOKEN_DOTDOTDOT     */ INFIX_OPERATOR(PREC_RANGE, "..."),
  /* TOKEN_COMMA         */ UNUSED,
  /* TOKEN_STAR          */ INFIX_OPERATOR(PREC_FACTOR, "*"),
  /* TOKEN_SLASH         */ INFIX_OPERATOR(PREC_FACTOR, "/"),
  /* TOKEN_PERCENT       */ INFIX_OPERATOR(PREC_FACTOR, "%"),
  /* TOKEN_HASH          */ UNUSED,
  /* TOKEN_PLUS          */ INFIX_OPERATOR(PREC_TERM, "+"),
  /* TOKEN_MINUS         */ OPERATOR("-"),
  /* TOKEN_LTLT          */ INFIX_OPERATOR(PREC_BITWISE_SHIFT, "<<"),
  /* TOKEN_GTGT          */ INFIX_OPERATOR(PREC_BITWISE_SHIFT, ">>"),
  /* TOKEN_PIPE          */ INFIX_OPERATOR(PREC_BITWISE_OR, "|"),
  /* TOKEN_PIPEPIPE      */ INFIX(PREC_LOGICAL_OR, or_),
  /* TOKEN_CARET         */ INFIX_OPERATOR(PREC_BITWISE_XOR, "^"),
  /* TOKEN_AMP           */ INFIX_OPERATOR(PREC_BITWISE_AND, "&"),
  /* TOKEN_AMPAMP        */ INFIX(PREC_LOGICAL_AND, and_),
  /* TOKEN_BANG          */ PREFIX_OPERATOR("!"),
  /* TOKEN_TILDE         */ PREFIX_OPERATOR("~"),
  /* TOKEN_QUESTION      */ INFIX(PREC_ASSIGNMENT, conditional),
  /* TOKEN_EQ            */ UNUSED,
  /* TOKEN_LT            */ INFIX_OPERATOR(PREC_COMPARISON, "<"),
  /* TOKEN_GT            */ INFIX_OPERATOR(PREC_COMPARISON, ">"),
  /* TOKEN_LTEQ          */ INFIX_OPERATOR(PREC_COMPARISON, "<="),
  /* TOKEN_GTEQ          */ INFIX_OPERATOR(PREC_COMPARISON, ">="),
  /* TOKEN_EQEQ          */ INFIX_OPERATOR(PREC_EQUALITY, "=="),
  /* TOKEN_BANGEQ        */ INFIX_OPERATOR(PREC_EQUALITY, "!="),
  /* TOKEN_BREAK         */ UNUSED,
  /* TOKEN_CONTINUE      */ UNUSED,
  /* TOKEN_CLASS         */ UNUSED,
  /* TOKEN_CONSTRUCT     */ { NULL, NULL, constructorSignature, PREC_NONE, NULL },
  /* TOKEN_ELSE          */ UNUSED,
  /* TOKEN_FALSE         */ PREFIX(boolean),
  /* TOKEN_FOR           */ UNUSED,
  /* TOKEN_FOREIGN       */ UNUSED,
  /* TOKEN_IF            */ UNUSED,
  /* TOKEN_IMPORT        */ UNUSED,
  /* TOKEN_AS            */ UNUSED,
  /* TOKEN_IN            */ UNUSED,
  /* TOKEN_IS            */ INFIX_OPERATOR(PREC_IS, "is"),
  /* TOKEN_NULL          */ PREFIX(null),
  /* TOKEN_RETURN        */ UNUSED,
  /* TOKEN_STATIC        */ UNUSED,
  /* TOKEN_SUPER         */ PREFIX(super_),
  /* TOKEN_THIS          */ PREFIX(this_),
  /* TOKEN_TRUE          */ PREFIX(boolean),
  /* TOKEN_VAR           */ UNUSED,
  /* TOKEN_WHILE         */ UNUSED,
  /* TOKEN_FIELD         */ PREFIX(field),
  /* TOKEN_STATIC_FIELD  */ PREFIX(staticField),
  /* TOKEN_NAME          */ { name, NULL, namedSignature, PREC_NONE, NULL },
  /* TOKEN_NUMBER        */ PREFIX(literal),
  /* TOKEN_STRING        */ PREFIX(literal),
  /* TOKEN_INTERPOLATION */ PREFIX(stringInterpolation),
  /* TOKEN_LINE          */ UNUSED,
  /* TOKEN_ERROR         */ UNUSED,
  /* TOKEN_EOF           */ UNUSED
};

// Gets the [GrammarRule] associated with tokens of [type].
static GrammarRule* getRule(TokenType type)
{
  return &rules[type];
}

// The main entrypoint for the top-down operator precedence parser.
void parsePrecedence(Compiler* compiler, Precedence precedence)
{
  nextToken(compiler->parser);
  GrammarFn prefix = rules[compiler->parser->previous.type].prefix;

  if (prefix == NULL)
  {
    error(compiler, "Expected expression.");
    return;
  }

  // Track if the precendence of the surrounding expression is low enough to
  // allow an assignment inside this one. We can't compile an assignment like
  // a normal expression because it requires us to handle the LHS specially --
  // it needs to be an lvalue, not an rvalue. So, for each of the kinds of
  // expressions that are valid lvalues -- names, subscripts, fields, etc. --
  // we pass in whether or not it appears in a context loose enough to allow
  // "=". If so, it will parse the "=" itself and handle it appropriately.
  bool canAssign = precedence <= PREC_CONDITIONAL;
  prefix(compiler, canAssign);

  while (precedence <= rules[compiler->parser->current.type].precedence)
  {
    nextToken(compiler->parser);
    GrammarFn infix = rules[compiler->parser->previous.type].infix;
    infix(compiler, canAssign);
  }
}

// Parses an expression. Unlike statements, expressions leave a resulting value
// on the stack.
void expression(Compiler* compiler)
{
  parsePrecedence(compiler, PREC_LOWEST);
}

// Returns the number of bytes for the arguments to the instruction 
// at [ip] in [fn]'s bytecode.
static int getByteCountForArguments(const uint8_t* bytecode,
                            const Value* constants, int ip)
{
  Code instruction = (Code)bytecode[ip];
  switch (instruction)
  {
    case CODE_NULL:
    case CODE_FALSE:
    case CODE_TRUE:
    case CODE_POP:
    case CODE_CLOSE_UPVALUE:
    case CODE_RETURN:
    case CODE_END:
    case CODE_LOAD_LOCAL_0:
    case CODE_LOAD_LOCAL_1:
    case CODE_LOAD_LOCAL_2:
    case CODE_LOAD_LOCAL_3:
    case CODE_LOAD_LOCAL_4:
    case CODE_LOAD_LOCAL_5:
    case CODE_LOAD_LOCAL_6:
    case CODE_LOAD_LOCAL_7:
    case CODE_LOAD_LOCAL_8:
    case CODE_CONSTRUCT:
    case CODE_FOREIGN_CONSTRUCT:
    case CODE_FOREIGN_CLASS:
    case CODE_END_MODULE:
    case CODE_END_CLASS:
      return 0;

    case CODE_LOAD_LOCAL:
    case CODE_STORE_LOCAL:
    case CODE_LOAD_UPVALUE:
    case CODE_STORE_UPVALUE:
    case CODE_LOAD_FIELD_THIS:
    case CODE_STORE_FIELD_THIS:
    case CODE_LOAD_FIELD:
    case CODE_STORE_FIELD:
    case CODE_CLASS:
      return 1;

    case CODE_CONSTANT:
    case CODE_LOAD_MODULE_VAR:
    case CODE_STORE_MODULE_VAR:
    case CODE_CALL_0:
    case CODE_CALL_1:
    case CODE_CALL_2:
    case CODE_CALL_3:
    case CODE_CALL_4:
    case CODE_CALL_5:
    case CODE_CALL_6:
    case CODE_CALL_7:
    case CODE_CALL_8:
    case CODE_CALL_9:
    case CODE_CALL_10:
    case CODE_CALL_11:
    case CODE_CALL_12:
    case CODE_CALL_13:
    case CODE_CALL_14:
    case CODE_CALL_15:
    case CODE_CALL_16:
    case CODE_JUMP:
    case CODE_LOOP:
    case CODE_JUMP_IF:
    case CODE_AND:
    case CODE_OR:
    case CODE_METHOD_INSTANCE:
    case CODE_METHOD_STATIC:
    case CODE_IMPORT_MODULE:
    case CODE_IMPORT_VARIABLE:
      return 2;

    case CODE_SUPER_0:
    case CODE_SUPER_1:
    case CODE_SUPER_2:
    case CODE_SUPER_3:
    case CODE_SUPER_4:
    case CODE_SUPER_5:
    case CODE_SUPER_6:
    case CODE_SUPER_7:
    case CODE_SUPER_8:
    case CODE_SUPER_9:
    case CODE_SUPER_10:
    case CODE_SUPER_11:
    case CODE_SUPER_12:
    case CODE_SUPER_13:
    case CODE_SUPER_14:
    case CODE_SUPER_15:
    case CODE_SUPER_16:
      return 4;

    case CODE_CLOSURE:
    {
      int constant = (bytecode[ip + 1] << 8) | bytecode[ip + 2];
      ObjFn* loadedFn = AS_FN(constants[constant]);

      // There are two bytes for the constant, then two for each upvalue.
      return 2 + (loadedFn->numUpvalues * 2);
    }
  }

  UNREACHABLE();
  return 0;
}

// Marks the beginning of a loop. Keeps track of the current instruction so we
// know what to loop back to at the end of the body.
static void startLoop(Compiler* compiler, Loop* loop)
{
  loop->enclosing = compiler->loop;
  loop->start = compiler->fn->code.count - 1;
  loop->scopeDepth = compiler->scopeDepth;
  compiler->loop = loop;
}

// Emits the [CODE_JUMP_IF] instruction used to test the loop condition and
// potentially exit the loop. Keeps track of the instruction so we can patch it
// later once we know where the end of the body is.
static void testExitLoop(Compiler* compiler)
{
  compiler->loop->exitJump = emitJump(compiler, CODE_JUMP_IF);
}

// Compiles the body of the loop and tracks its extent so that contained "break"
// statements can be handled correctly.
static void loopBody(Compiler* compiler)
{
  compiler->loop->body = compiler->fn->code.count;
  statement(compiler);
}

// Ends the current innermost loop. Patches up all jumps and breaks now that
// we know where the end of the loop is.
static void endLoop(Compiler* compiler)
{
  // We don't check for overflow here since the forward jump over the loop body
  // will report an error for the same problem.
  int loopOffset = compiler->fn->code.count - compiler->loop->start + 2;
  emitShortArg(compiler, CODE_LOOP, loopOffset);

  patchJump(compiler, compiler->loop->exitJump);

  // Find any break placeholder instructions (which will be CODE_END in the
  // bytecode) and replace them with real jumps.
  int i = compiler->loop->body;
  while (i < compiler->fn->code.count)
  {
    if (compiler->fn->code.data[i] == CODE_END)
    {
      compiler->fn->code.data[i] = CODE_JUMP;
      patchJump(compiler, i + 1);
      i += 3;
    }
    else
    {
      // Skip this instruction and its arguments.
      i += 1 + getByteCountForArguments(compiler->fn->code.data,
                               compiler->fn->constants.data, i);
    }
  }

  compiler->loop = compiler->loop->enclosing;
}

static void forStatement(Compiler* compiler)
{
  // A for statement like:
  //
  //     for (i in sequence.expression) {
  //       System.print(i)
  //     }
  //
  // Is compiled to bytecode almost as if the source looked like this:
  //
  //     {
  //       var seq_ = sequence.expression
  //       var iter_
  //       while (iter_ = seq_.iterate(iter_)) {
  //         var i = seq_.iteratorValue(iter_)
  //         System.print(i)
  //       }
  //     }
  //
  // It's not exactly this, because the synthetic variables `seq_` and `iter_`
  // actually get names that aren't valid Wren identfiers, but that's the basic
  // idea.
  //
  // The important parts are:
  // - The sequence expression is only evaluated once.
  // - The .iterate() method is used to advance the iterator and determine if
  //   it should exit the loop.
  // - The .iteratorValue() method is used to get the value at the current
  //   iterator position.

  // Create a scope for the hidden local variables used for the iterator.
  pushScope(compiler);

  consume(compiler, TOKEN_LEFT_PAREN, "Expect '(' after 'for'.");
  consume(compiler, TOKEN_NAME, "Expect for loop variable name.");

  // Remember the name of the loop variable.
  const char* name = compiler->parser->previous.start;
  int length = compiler->parser->previous.length;

  consume(compiler, TOKEN_IN, "Expect 'in' after loop variable.");
  ignoreNewlines(compiler);

  // Evaluate the sequence expression and store it in a hidden local variable.
  // The space in the variable name ensures it won't collide with a user-defined
  // variable.
  expression(compiler);

  // Verify that there is space to hidden local variables.
  // Note that we expect only two addLocal calls next to each other in the
  // following code.
  if (compiler->numLocals + 2 > MAX_LOCALS)
  {
    error(compiler, "Cannot declare more than %d variables in one scope. (Not enough space for for-loops internal variables)",
          MAX_LOCALS);
    return;
  }
  int seqSlot = addLocal(compiler, "seq ", 4);

  // Create another hidden local for the iterator object.
  null(compiler, false);
  int iterSlot = addLocal(compiler, "iter ", 5);

  consume(compiler, TOKEN_RIGHT_PAREN, "Expect ')' after loop expression.");

  Loop loop;
  startLoop(compiler, &loop);

  // Advance the iterator by calling the ".iterate" method on the sequence.
  loadLocal(compiler, seqSlot);
  loadLocal(compiler, iterSlot);

  // Update and test the iterator.
  callMethod(compiler, 1, "iterate(_)", 10);
  emitByteArg(compiler, CODE_STORE_LOCAL, iterSlot);
  testExitLoop(compiler);

  // Get the current value in the sequence by calling ".iteratorValue".
  loadLocal(compiler, seqSlot);
  loadLocal(compiler, iterSlot);
  callMethod(compiler, 1, "iteratorValue(_)", 16);

  // Bind the loop variable in its own scope. This ensures we get a fresh
  // variable each iteration so that closures for it don't all see the same one.
  pushScope(compiler);
  addLocal(compiler, name, length);

  loopBody(compiler);

  // Loop variable.
  popScope(compiler);

  endLoop(compiler);

  // Hidden variables.
  popScope(compiler);
}

static void ifStatement(Compiler* compiler)
{
  // Compile the condition.
  consume(compiler, TOKEN_LEFT_PAREN, "Expect '(' after 'if'.");
  expression(compiler);
  consume(compiler, TOKEN_RIGHT_PAREN, "Expect ')' after if condition.");
  
  // Jump to the else branch if the condition is false.
  int ifJump = emitJump(compiler, CODE_JUMP_IF);
  
  // Compile the then branch.
  statement(compiler);
  
  // Compile the else branch if there is one.
  if (match(compiler, TOKEN_ELSE))
  {
    // Jump over the else branch when the if branch is taken.
    int elseJump = emitJump(compiler, CODE_JUMP);
    patchJump(compiler, ifJump);
    
    statement(compiler);
    
    // Patch the jump over the else.
    patchJump(compiler, elseJump);
  }
  else
  {
    patchJump(compiler, ifJump);
  }
}

static void whileStatement(Compiler* compiler)
{
  Loop loop;
  startLoop(compiler, &loop);

  // Compile the condition.
  consume(compiler, TOKEN_LEFT_PAREN, "Expect '(' after 'while'.");
  expression(compiler);
  consume(compiler, TOKEN_RIGHT_PAREN, "Expect ')' after while condition.");

  testExitLoop(compiler);
  loopBody(compiler);
  endLoop(compiler);
}

// Compiles a simple statement. These can only appear at the top-level or
// within curly blocks. Simple statements exclude variable binding statements
// like "var" and "class" which are not allowed directly in places like the
// branches of an "if" statement.
//
// Unlike expressions, statements do not leave a value on the stack.
void statement(Compiler* compiler)
{
  if (match(compiler, TOKEN_BREAK))
  {
    if (compiler->loop == NULL)
    {
      error(compiler, "Cannot use 'break' outside of a loop.");
      return;
    }

    // Since we will be jumping out of the scope, make sure any locals in it
    // are discarded first.
    discardLocals(compiler, compiler->loop->scopeDepth + 1);

    // Emit a placeholder instruction for the jump to the end of the body. When
    // we're done compiling the loop body and know where the end is, we'll
    // replace these with `CODE_JUMP` instructions with appropriate offsets.
    // We use `CODE_END` here because that can't occur in the middle of
    // bytecode.
    emitJump(compiler, CODE_END);
  }
  else if (match(compiler, TOKEN_CONTINUE))
  {
    if (compiler->loop == NULL)
    {
        error(compiler, "Cannot use 'continue' outside of a loop.");
        return;
    }

    // Since we will be jumping out of the scope, make sure any locals in it
    // are discarded first.
    discardLocals(compiler, compiler->loop->scopeDepth + 1);

    // emit a jump back to the top of the loop
    int loopOffset = compiler->fn->code.count - compiler->loop->start + 2;
    emitShortArg(compiler, CODE_LOOP, loopOffset);
  }
  else if (match(compiler, TOKEN_FOR))
  {
    forStatement(compiler);
  }
  else if (match(compiler, TOKEN_IF))
  {
    ifStatement(compiler);
  }
  else if (match(compiler, TOKEN_RETURN))
  {
    // Compile the return value.
    if (peek(compiler) == TOKEN_LINE)
    {
      // If there's no expression after return, initializers should 
      // return 'this' and regular methods should return null
      Code result = compiler->isInitializer ? CODE_LOAD_LOCAL_0 : CODE_NULL;
      emitOp(compiler, result);
    }
    else
    {
      if (compiler->isInitializer)
      {
        error(compiler, "A constructor cannot return a value.");
      }

      expression(compiler);
    }

    emitOp(compiler, CODE_RETURN);
  }
  else if (match(compiler, TOKEN_WHILE))
  {
    whileStatement(compiler);
  }
  else if (match(compiler, TOKEN_LEFT_BRACE))
  {
    // Block statement.
    pushScope(compiler);
    if (finishBlock(compiler))
    {
      // Block was an expression, so discard it.
      emitOp(compiler, CODE_POP);
    }
    popScope(compiler);
  }
  else
  {
    // Expression statement.
    expression(compiler);
    emitOp(compiler, CODE_POP);
  }
}

// Creates a matching constructor method for an initializer with [signature]
// and [initializerSymbol].
//
// Construction is a two-stage process in Wren that involves two separate
// methods. There is a static method that allocates a new instance of the class.
// It then invokes an initializer method on the new instance, forwarding all of
// the constructor arguments to it.
//
// The allocator method always has a fixed implementation:
//
//     CODE_CONSTRUCT - Replace the class in slot 0 with a new instance of it.
//     CODE_CALL      - Invoke the initializer on the new instance.
//
// This creates that method and calls the initializer with [initializerSymbol].
static void createConstructor(Compiler* compiler, Signature* signature,
                              int initializerSymbol)
{
  Compiler methodCompiler;
  initCompiler(&methodCompiler, compiler->parser, compiler, true);
  
  // Allocate the instance.
  emitOp(&methodCompiler, compiler->enclosingClass->isForeign
       ? CODE_FOREIGN_CONSTRUCT : CODE_CONSTRUCT);
  
  // Run its initializer.
  emitShortArg(&methodCompiler, (Code)(CODE_CALL_0 + signature->arity),
               initializerSymbol);
  
  // Return the instance.
  emitOp(&methodCompiler, CODE_RETURN);
  
  endCompiler(&methodCompiler, "", 0);
}

// Loads the enclosing class onto the stack and then binds the function already
// on the stack as a method on that class.
static void defineMethod(Compiler* compiler, Variable classVariable,
                         bool isStatic, int methodSymbol)
{
  // Load the class. We have to do this for each method because we can't
  // keep the class on top of the stack. If there are static fields, they
  // will be locals above the initial variable slot for the class on the
  // stack. To skip past those, we just load the class each time right before
  // defining a method.
  loadVariable(compiler, classVariable);

  // Define the method.
  Code instruction = isStatic ? CODE_METHOD_STATIC : CODE_METHOD_INSTANCE;
  emitShortArg(compiler, instruction, methodSymbol);
}

// Declares a method in the enclosing class with [signature].
//
// Reports an error if a method with that signature is already declared.
// Returns the symbol for the method.
static int declareMethod(Compiler* compiler, Signature* signature,
                         const char* name, int length)
{
  int symbol = signatureSymbol(compiler, signature);
  
  // See if the class has already declared method with this signature.
  ClassInfo* classInfo = compiler->enclosingClass;
  IntBuffer* methods = classInfo->inStatic
      ? &classInfo->staticMethods : &classInfo->methods;
  for (int i = 0; i < methods->count; i++)
  {
    if (methods->data[i] == symbol)
    {
      const char* staticPrefix = classInfo->inStatic ? "static " : "";
      error(compiler, "Class %s already defines a %smethod '%s'.",
            &compiler->enclosingClass->name->value, staticPrefix, name);
      break;
    }
  }
  
  wrenIntBufferWrite(compiler->parser->vm, methods, symbol);
  return symbol;
}

static Value consumeLiteral(Compiler* compiler, const char* message) 
{
  if(match(compiler, TOKEN_FALSE))  return FALSE_VAL;
  if(match(compiler, TOKEN_TRUE))   return TRUE_VAL;
  if(match(compiler, TOKEN_NUMBER)) return compiler->parser->previous.value;
  if(match(compiler, TOKEN_STRING)) return compiler->parser->previous.value;
  if(match(compiler, TOKEN_NAME))   return compiler->parser->previous.value;

  error(compiler, message);
  nextToken(compiler->parser);
  return NULL_VAL;
}

static bool matchAttribute(Compiler* compiler) {

  if(match(compiler, TOKEN_HASH)) 
  {
    compiler->numAttributes++;
    bool runtimeAccess = match(compiler, TOKEN_BANG);
    if(match(compiler, TOKEN_NAME)) 
    {
      Value group = compiler->parser->previous.value;
      TokenType ahead = peek(compiler);
      if(ahead == TOKEN_EQ || ahead == TOKEN_LINE)
      {
        Value key = group;
        Value value = NULL_VAL;
        if(match(compiler, TOKEN_EQ)) 
        {
          value = consumeLiteral(compiler, "Expect a Bool, Num, String or Identifier literal for an attribute value.");
        }
        if(runtimeAccess) addToAttributeGroup(compiler, NULL_VAL, key, value);
      }
      else if(match(compiler, TOKEN_LEFT_PAREN))
      {
        ignoreNewlines(compiler);
        if(match(compiler, TOKEN_RIGHT_PAREN))
        {
          error(compiler, "Expected attributes in group, group cannot be empty.");
        } 
        else 
        {
          while(peek(compiler) != TOKEN_RIGHT_PAREN)
          {
            consume(compiler, TOKEN_NAME, "Expect name for attribute key.");
            Value key = compiler->parser->previous.value;
            Value value = NULL_VAL;
            if(match(compiler, TOKEN_EQ))
            {
              value = consumeLiteral(compiler, "Expect a Bool, Num, String or Identifier literal for an attribute value.");
            }
            if(runtimeAccess) addToAttributeGroup(compiler, group, key, value);
            ignoreNewlines(compiler);
            if(!match(compiler, TOKEN_COMMA)) break;
            ignoreNewlines(compiler);
          }

          ignoreNewlines(compiler);
          consume(compiler, TOKEN_RIGHT_PAREN, 
            "Expected ')' after grouped attributes.");
        }
      }
      else
      {
        error(compiler, "Expect an equal, newline or grouping after an attribute key.");
      }
    }
    else 
    {
      error(compiler, "Expect an attribute definition after #.");
    }

    consumeLine(compiler, "Expect newline after attribute.");
    return true;
  }

  return false;
}

// Compiles a method definition inside a class body.
//
// Returns `true` if it compiled successfully, or `false` if the method couldn't
// be parsed.
static bool method(Compiler* compiler, Variable classVariable)
{
  // Parse any attributes before the method and store them
  if(matchAttribute(compiler)) {
    return method(compiler, classVariable);
  }

  // TODO: What about foreign constructors?
  bool isForeign = match(compiler, TOKEN_FOREIGN);
  bool isStatic = match(compiler, TOKEN_STATIC);
  compiler->enclosingClass->inStatic = isStatic;
    
  SignatureFn signatureFn = rules[compiler->parser->current.type].method;
  nextToken(compiler->parser);
  
  if (signatureFn == NULL)
  {
    error(compiler, "Expect method definition.");
    return false;
  }
  
  // Build the method signature.
  Signature signature = signatureFromToken(compiler, SIG_GETTER);
  compiler->enclosingClass->signature = &signature;

  Compiler methodCompiler;
  initCompiler(&methodCompiler, compiler->parser, compiler, true);

  // Compile the method signature.
  signatureFn(&methodCompiler, &signature);

  methodCompiler.isInitializer = signature.type == SIG_INITIALIZER;
  
  if (isStatic && signature.type == SIG_INITIALIZER)
  {
    error(compiler, "A constructor cannot be static.");
  }
  
  // Include the full signature in debug messages in stack traces.
  char fullSignature[MAX_METHOD_SIGNATURE];
  int length;
  signatureToString(&signature, fullSignature, &length);

  // Copy any attributes the compiler collected into the enclosing class 
  copyMethodAttributes(compiler, isForeign, isStatic, fullSignature, length);

  // Check for duplicate methods. Doesn't matter that it's already been
  // defined, error will discard bytecode anyway.
  // Check if the method table already contains this symbol
  int methodSymbol = declareMethod(compiler, &signature, fullSignature, length);
  
  if (isForeign)
  {
    // Define a constant for the signature.
    emitConstant(compiler, wrenNewStringLength(compiler->parser->vm,
                                               fullSignature, length));

    // We don't need the function we started compiling in the parameter list
    // any more.
    methodCompiler.parser->vm->compiler = methodCompiler.parent;
  }
  else
  {
    consume(compiler, TOKEN_LEFT_BRACE, "Expect '{' to begin method body.");
    finishBody(&methodCompiler);
    endCompiler(&methodCompiler, fullSignature, length);
  }
  
  // Define the method. For a constructor, this defines the instance
  // initializer method.
  defineMethod(compiler, classVariable, isStatic, methodSymbol);

  if (signature.type == SIG_INITIALIZER)
  {
    // Also define a matching constructor method on the metaclass.
    signature.type = SIG_METHOD;
    int constructorSymbol = signatureSymbol(compiler, &signature);
    
    createConstructor(compiler, &signature, methodSymbol);
    defineMethod(compiler, classVariable, true, constructorSymbol);
  }

  return true;
}

// Compiles a class definition. Assumes the "class" token has already been
// consumed (along with a possibly preceding "foreign" token).
static void classDefinition(Compiler* compiler, bool isForeign)
{
  // Create a variable to store the class in.
  Variable classVariable;
  classVariable.scope = compiler->scopeDepth == -1 ? SCOPE_MODULE : SCOPE_LOCAL;
  classVariable.index = declareNamedVariable(compiler);
  
  // Create shared class name value
  Value classNameString = wrenNewStringLength(compiler->parser->vm,
      compiler->parser->previous.start, compiler->parser->previous.length);
  
  // Create class name string to track method duplicates
  ObjString* className = AS_STRING(classNameString);
  
  // Make a string constant for the name.
  emitConstant(compiler, classNameString);

  // Load the superclass (if there is one).
  if (match(compiler, TOKEN_IS))
  {
    parsePrecedence(compiler, PREC_CALL);
  }
  else
  {
    // Implicitly inherit from Object.
    loadCoreVariable(compiler, "Object");
  }

  // Store a placeholder for the number of fields argument. We don't know the
  // count until we've compiled all the methods to see which fields are used.
  int numFieldsInstruction = -1;
  if (isForeign)
  {
    emitOp(compiler, CODE_FOREIGN_CLASS);
  }
  else
  {
    numFieldsInstruction = emitByteArg(compiler, CODE_CLASS, 255);
  }

  // Store it in its name.
  defineVariable(compiler, classVariable.index);

  // Push a local variable scope. Static fields in a class body are hoisted out
  // into local variables declared in this scope. Methods that use them will
  // have upvalues referencing them.
  pushScope(compiler);

  ClassInfo classInfo;
  classInfo.isForeign = isForeign;
  classInfo.name = className;

  // Allocate attribute maps if necessary. 
  // A method will allocate the methods one if needed
  classInfo.classAttributes = compiler->attributes->count > 0 
        ? wrenNewMap(compiler->parser->vm) 
        : NULL;
  classInfo.methodAttributes = NULL;
  // Copy any existing attributes into the class
  copyAttributes(compiler, classInfo.classAttributes);

  // Set up a symbol table for the class's fields. We'll initially compile
  // them to slots starting at zero. When the method is bound to the class, the
  // bytecode will be adjusted by [wrenBindMethod] to take inherited fields
  // into account.
  wrenSymbolTableInit(&classInfo.fields);
  
  // Set up symbol buffers to track duplicate static and instance methods.
  wrenIntBufferInit(&classInfo.methods);
  wrenIntBufferInit(&classInfo.staticMethods);
  compiler->enclosingClass = &classInfo;

  // Compile the method definitions.
  consume(compiler, TOKEN_LEFT_BRACE, "Expect '{' after class declaration.");
  matchLine(compiler);

  while (!match(compiler, TOKEN_RIGHT_BRACE))
  {
    if (!method(compiler, classVariable)) break;
    
    // Don't require a newline after the last definition.
    if (match(compiler, TOKEN_RIGHT_BRACE)) break;

    consumeLine(compiler, "Expect newline after definition in class.");
  }
  
  // If any attributes are present, 
  // instantiate a ClassAttributes instance for the class
  // and send it over to CODE_END_CLASS
  bool hasAttr = classInfo.classAttributes != NULL || 
                 classInfo.methodAttributes != NULL;
  if(hasAttr) {
    emitClassAttributes(compiler, &classInfo);
    loadVariable(compiler, classVariable);
    // At the moment, we don't have other uses for CODE_END_CLASS,
    // so we put it inside this condition. Later, we can always
    // emit it and use it as needed.
    emitOp(compiler, CODE_END_CLASS);
  }

  // Update the class with the number of fields.
  if (!isForeign)
  {
    compiler->fn->code.data[numFieldsInstruction] =
        (uint8_t)classInfo.fields.count;
  }
  
  // Clear symbol tables for tracking field and method names.
  wrenSymbolTableClear(compiler->parser->vm, &classInfo.fields);
  wrenIntBufferClear(compiler->parser->vm, &classInfo.methods);
  wrenIntBufferClear(compiler->parser->vm, &classInfo.staticMethods);
  compiler->enclosingClass = NULL;
  popScope(compiler);
}

// Compiles an "import" statement.
//
// An import compiles to a series of instructions. Given:
//
//     import "foo" for Bar, Baz
//
// We compile a single IMPORT_MODULE "foo" instruction to load the module
// itself. When that finishes executing the imported module, it leaves the
// ObjModule in vm->lastModule. Then, for Bar and Baz, we:
//
// * Declare a variable in the current scope with that name.
// * Emit an IMPORT_VARIABLE instruction to load the variable's value from the
//   other module.
// * Compile the code to store that value in the variable in this scope.
static void import(Compiler* compiler)
{
  ignoreNewlines(compiler);
  consume(compiler, TOKEN_STRING, "Expect a string after 'import'.");
  int moduleConstant = addConstant(compiler, compiler->parser->previous.value);

  // Load the module.
  emitShortArg(compiler, CODE_IMPORT_MODULE, moduleConstant);

  // Discard the unused result value from calling the module body's closure.
  emitOp(compiler, CODE_POP);
  
  // The for clause is optional.
  if (!match(compiler, TOKEN_FOR)) return;

  // Compile the comma-separated list of variables to import.
  do
  {
    ignoreNewlines(compiler);
    
    consume(compiler, TOKEN_NAME, "Expect variable name.");
    
    // We need to hold onto the source variable, 
    // in order to reference it in the import later
    Token sourceVariableToken = compiler->parser->previous;

    // Define a string constant for the original variable name.
    int sourceVariableConstant = addConstant(compiler,
          wrenNewStringLength(compiler->parser->vm,
                        sourceVariableToken.start,
                        sourceVariableToken.length));

    // Store the symbol we care about for the variable
    int slot = -1;
    if(match(compiler, TOKEN_AS))
    {
      //import "module" for Source as Dest
      //Use 'Dest' as the name by declaring a new variable for it.
      //This parses a name after the 'as' and defines it.
      slot = declareNamedVariable(compiler);
    }
    else
    {
      //import "module" for Source
      //Uses 'Source' as the name directly
      slot = declareVariable(compiler, &sourceVariableToken);
    }

    // Load the variable from the other module.
    emitShortArg(compiler, CODE_IMPORT_VARIABLE, sourceVariableConstant);

    // Store the result in the variable here.
    defineVariable(compiler, slot);
  } while (match(compiler, TOKEN_COMMA));
}

// Compiles a "var" variable definition statement.
static void variableDefinition(Compiler* compiler)
{
  // Grab its name, but don't declare it yet. A (local) variable shouldn't be
  // in scope in its own initializer.
  consume(compiler, TOKEN_NAME, "Expect variable name.");
  Token nameToken = compiler->parser->previous;

  // Compile the initializer.
  if (match(compiler, TOKEN_EQ))
  {
    ignoreNewlines(compiler);
    expression(compiler);
  }
  else
  {
    // Default initialize it to null.
    null(compiler, false);
  }

  // Now put it in scope.
  int symbol = declareVariable(compiler, &nameToken);
  defineVariable(compiler, symbol);
}

// Compiles a "definition". These are the statements that bind new variables.
// They can only appear at the top level of a block and are prohibited in places
// like the non-curly body of an if or while.
void definition(Compiler* compiler)
{
  if(matchAttribute(compiler)) {
    definition(compiler);
    return;
  }

  if (match(compiler, TOKEN_CLASS))
  {
    classDefinition(compiler, false);
    return;
  }
  else if (match(compiler, TOKEN_FOREIGN))
  {
    consume(compiler, TOKEN_CLASS, "Expect 'class' after 'foreign'.");
    classDefinition(compiler, true);
    return;
  }

  disallowAttributes(compiler);

  if (match(compiler, TOKEN_IMPORT))
  {
    import(compiler);
  }
  else if (match(compiler, TOKEN_VAR))
  {
    variableDefinition(compiler);
  }
  else
  {
    statement(compiler);
  }
}

ObjFn* wrenCompile(WrenVM* vm, ObjModule* module, const char* source,
                   bool isExpression, bool printErrors)
{
  // Skip the UTF-8 BOM if there is one.
  if (strncmp(source, "\xEF\xBB\xBF", 3) == 0) source += 3;
  
  Parser parser;
  parser.vm = vm;
  parser.module = module;
  parser.source = source;

  parser.tokenStart = source;
  parser.currentChar = source;
  parser.currentLine = 1;
  parser.numParens = 0;

  // Zero-init the current token. This will get copied to previous when
  // nextToken() is called below.
  parser.next.type = TOKEN_ERROR;
  parser.next.start = source;
  parser.next.length = 0;
  parser.next.line = 0;
  parser.next.value = UNDEFINED_VAL;

  parser.printErrors = printErrors;
  parser.hasError = false;

  // Read the first token into next
  nextToken(&parser);
  // Copy next -> current
  nextToken(&parser);

  int numExistingVariables = module->variables.count;

  Compiler compiler;
  initCompiler(&compiler, &parser, NULL, false);
  ignoreNewlines(&compiler);

  if (isExpression)
  {
    expression(&compiler);
    consume(&compiler, TOKEN_EOF, "Expect end of expression.");
  }
  else
  {
    while (!match(&compiler, TOKEN_EOF))
    {
      definition(&compiler);
      
      // If there is no newline, it must be the end of file on the same line.
      if (!matchLine(&compiler))
      {
        consume(&compiler, TOKEN_EOF, "Expect end of file.");
        break;
      }
    }
    
    emitOp(&compiler, CODE_END_MODULE);
  }
  
  emitOp(&compiler, CODE_RETURN);

  // See if there are any implicitly declared module-level variables that never
  // got an explicit definition. They will have values that are numbers
  // indicating the line where the variable was first used.
  for (int i = numExistingVariables; i < parser.module->variables.count; i++)
  {
    if (IS_NUM(parser.module->variables.data[i]))
    {
      // Synthesize a token for the original use site.
      parser.previous.type = TOKEN_NAME;
      parser.previous.start = parser.module->variableNames.data[i]->value;
      parser.previous.length = parser.module->variableNames.data[i]->length;
      parser.previous.line = (int)AS_NUM(parser.module->variables.data[i]);
      error(&compiler, "Variable is used but not defined.");
    }
  }
  
  return endCompiler(&compiler, "(script)", 8);
}

void wrenBindMethodCode(ObjClass* classObj, ObjFn* fn)
{
  int ip = 0;
  for (;;)
  {
    Code instruction = (Code)fn->code.data[ip];
    switch (instruction)
    {
      case CODE_LOAD_FIELD:
      case CODE_STORE_FIELD:
      case CODE_LOAD_FIELD_THIS:
      case CODE_STORE_FIELD_THIS:
        // Shift this class's fields down past the inherited ones. We don't
        // check for overflow here because we'll see if the number of fields
        // overflows when the subclass is created.
        fn->code.data[ip + 1] += classObj->superclass->numFields;
        break;

      case CODE_SUPER_0:
      case CODE_SUPER_1:
      case CODE_SUPER_2:
      case CODE_SUPER_3:
      case CODE_SUPER_4:
      case CODE_SUPER_5:
      case CODE_SUPER_6:
      case CODE_SUPER_7:
      case CODE_SUPER_8:
      case CODE_SUPER_9:
      case CODE_SUPER_10:
      case CODE_SUPER_11:
      case CODE_SUPER_12:
      case CODE_SUPER_13:
      case CODE_SUPER_14:
      case CODE_SUPER_15:
      case CODE_SUPER_16:
      {
        // Fill in the constant slot with a reference to the superclass.
        int constant = (fn->code.data[ip + 3] << 8) | fn->code.data[ip + 4];
        fn->constants.data[constant] = OBJ_VAL(classObj->superclass);
        break;
      }

      case CODE_CLOSURE:
      {
        // Bind the nested closure too.
        int constant = (fn->code.data[ip + 1] << 8) | fn->code.data[ip + 2];
        wrenBindMethodCode(classObj, AS_FN(fn->constants.data[constant]));
        break;
      }

      case CODE_END:
        return;

      default:
        // Other instructions are unaffected, so just skip over them.
        break;
    }
    ip += 1 + getByteCountForArguments(fn->code.data, fn->constants.data, ip);
  }
}

void wrenMarkCompiler(WrenVM* vm, Compiler* compiler)
{
  wrenGrayValue(vm, compiler->parser->current.value);
  wrenGrayValue(vm, compiler->parser->previous.value);
  wrenGrayValue(vm, compiler->parser->next.value);

  // Walk up the parent chain to mark the outer compilers too. The VM only
  // tracks the innermost one.
  do
  {
    wrenGrayObj(vm, (Obj*)compiler->fn);
    wrenGrayObj(vm, (Obj*)compiler->constants);
    wrenGrayObj(vm, (Obj*)compiler->attributes);
    
    if (compiler->enclosingClass != NULL)
    {
      wrenBlackenSymbolTable(vm, &compiler->enclosingClass->fields);

      if(compiler->enclosingClass->methodAttributes != NULL) 
      {
        wrenGrayObj(vm, (Obj*)compiler->enclosingClass->methodAttributes);
      }
      if(compiler->enclosingClass->classAttributes != NULL) 
      {
        wrenGrayObj(vm, (Obj*)compiler->enclosingClass->classAttributes);
      }
    }
    
    compiler = compiler->parent;
  }
  while (compiler != NULL);
}

// Helpers for Attributes

// Throw an error if any attributes were found preceding, 
// and clear the attributes so the error doesn't keep happening.
static void disallowAttributes(Compiler* compiler)
{
  if (compiler->numAttributes > 0)
  {
    error(compiler, "Attributes can only specified before a class or a method");
    wrenMapClear(compiler->parser->vm, compiler->attributes);
    compiler->numAttributes = 0;
  }
}

// Add an attribute to a given group in the compiler attribues map
static void addToAttributeGroup(Compiler* compiler, 
                                Value group, Value key, Value value) 
{
  WrenVM* vm = compiler->parser->vm;

  if(IS_OBJ(group)) wrenPushRoot(vm, AS_OBJ(group));
  if(IS_OBJ(key))   wrenPushRoot(vm, AS_OBJ(key));
  if(IS_OBJ(value)) wrenPushRoot(vm, AS_OBJ(value));

  Value groupMapValue = wrenMapGet(compiler->attributes, group);
  if(IS_UNDEFINED(groupMapValue)) 
  {
    groupMapValue = OBJ_VAL(wrenNewMap(vm));
    wrenMapSet(vm, compiler->attributes, group, groupMapValue);
  }

  //we store them as a map per so we can maintain duplicate keys 
  //group = { key:[value, ...], }
  ObjMap* groupMap = AS_MAP(groupMapValue);

  //var keyItems = group[key]
  //if(!keyItems) keyItems = group[key] = [] 
  Value keyItemsValue = wrenMapGet(groupMap, key);
  if(IS_UNDEFINED(keyItemsValue)) 
  {
    keyItemsValue = OBJ_VAL(wrenNewList(vm, 0));
    wrenMapSet(vm, groupMap, key, keyItemsValue);
  }

  //keyItems.add(value)
  ObjList* keyItems = AS_LIST(keyItemsValue);
  wrenValueBufferWrite(vm, &keyItems->elements, value);

  if(IS_OBJ(group)) wrenPopRoot(vm);
  if(IS_OBJ(key))   wrenPopRoot(vm);
  if(IS_OBJ(value)) wrenPopRoot(vm);
}


// Emit the attributes in the give map onto the stack
static void emitAttributes(Compiler* compiler, ObjMap* attributes) 
{
  // Instantiate a new map for the attributes
  loadCoreVariable(compiler, "Map");
  callMethod(compiler, 0, "new()", 5);

  // The attributes are stored as group = { key:[value, value, ...] }
  // so our first level is the group map
  for(uint32_t groupIdx = 0; groupIdx < attributes->capacity; groupIdx++)
  {
    const MapEntry* groupEntry = &attributes->entries[groupIdx];
    if(IS_UNDEFINED(groupEntry->key)) continue;
    //group key
    emitConstant(compiler, groupEntry->key);

    //group value is gonna be a map
    loadCoreVariable(compiler, "Map");
    callMethod(compiler, 0, "new()", 5);

    ObjMap* groupItems = AS_MAP(groupEntry->value);
    for(uint32_t itemIdx = 0; itemIdx < groupItems->capacity; itemIdx++)
    {
      const MapEntry* itemEntry = &groupItems->entries[itemIdx];
      if(IS_UNDEFINED(itemEntry->key)) continue;

      emitConstant(compiler, itemEntry->key);
      // Attribute key value, key = []
      loadCoreVariable(compiler, "List");
      callMethod(compiler, 0, "new()", 5);
      // Add the items to the key list
      ObjList* items = AS_LIST(itemEntry->value);
      for(int itemIdx = 0; itemIdx < items->elements.count; ++itemIdx)
      {
        emitConstant(compiler, items->elements.data[itemIdx]);
        callMethod(compiler, 1, "addCore_(_)", 11);
      }
      // Add the list to the map
      callMethod(compiler, 2, "addCore_(_,_)", 13);
    }

    // Add the key/value to the map
    callMethod(compiler, 2, "addCore_(_,_)", 13);
  }

}

// Methods are stored as method <-> attributes, so we have to have 
// an indirection to resolve for methods
static void emitAttributeMethods(Compiler* compiler, ObjMap* attributes)
{
    // Instantiate a new map for the attributes
  loadCoreVariable(compiler, "Map");
  callMethod(compiler, 0, "new()", 5);

  for(uint32_t methodIdx = 0; methodIdx < attributes->capacity; methodIdx++)
  {
    const MapEntry* methodEntry = &attributes->entries[methodIdx];
    if(IS_UNDEFINED(methodEntry->key)) continue;
    emitConstant(compiler, methodEntry->key);
    ObjMap* attributeMap = AS_MAP(methodEntry->value);
    emitAttributes(compiler, attributeMap);
    callMethod(compiler, 2, "addCore_(_,_)", 13);
  }
}


// Emit the final ClassAttributes that exists at runtime
static void emitClassAttributes(Compiler* compiler, ClassInfo* classInfo)
{
  loadCoreVariable(compiler, "ClassAttributes");

  classInfo->classAttributes 
    ? emitAttributes(compiler, classInfo->classAttributes) 
    : null(compiler, false);

  classInfo->methodAttributes 
    ? emitAttributeMethods(compiler, classInfo->methodAttributes) 
    : null(compiler, false);

  callMethod(compiler, 2, "new(_,_)", 8);
}

// Copy the current attributes stored in the compiler into a destination map
// This also resets the counter, since the intent is to consume the attributes
static void copyAttributes(Compiler* compiler, ObjMap* into)
{
  compiler->numAttributes = 0;

  if(compiler->attributes->count == 0) return;
  if(into == NULL) return;

  WrenVM* vm = compiler->parser->vm;
  
  // Note we copy the actual values as is since we'll take ownership 
  // and clear the original map
  for(uint32_t attrIdx = 0; attrIdx < compiler->attributes->capacity; attrIdx++)
  {
    const MapEntry* attrEntry = &compiler->attributes->entries[attrIdx];
    if(IS_UNDEFINED(attrEntry->key)) continue;
    wrenMapSet(vm, into, attrEntry->key, attrEntry->value);
  }
  
  wrenMapClear(vm, compiler->attributes);
}

// Copy the current attributes stored in the compiler into the method specific
// attributes for the current enclosingClass.
// This also resets the counter, since the intent is to consume the attributes
static void copyMethodAttributes(Compiler* compiler, bool isForeign,
            bool isStatic, const char* fullSignature, int32_t length) 
{
  compiler->numAttributes = 0;

  if(compiler->attributes->count == 0) return;

  WrenVM* vm = compiler->parser->vm;
  
  // Make a map for this method to copy into
  ObjMap* methodAttr = wrenNewMap(vm);
  wrenPushRoot(vm, (Obj*)methodAttr);
  copyAttributes(compiler, methodAttr);

  // Include 'foreign static ' in front as needed
  int32_t fullLength = length;
  if(isForeign) fullLength += 8;
  if(isStatic) fullLength += 7;
  char fullSignatureWithPrefix[MAX_METHOD_SIGNATURE + 8 + 7];
  const char* foreignPrefix = isForeign ? "foreign " : "";
  const char* staticPrefix = isStatic ? "static " : "";
  sprintf(fullSignatureWithPrefix, "%s%s%.*s", foreignPrefix, staticPrefix, 
                                               length, fullSignature);
  fullSignatureWithPrefix[fullLength] = '\0';

  if(compiler->enclosingClass->methodAttributes == NULL) {
    compiler->enclosingClass->methodAttributes = wrenNewMap(vm);
  }
  
  // Store the method attributes in the class map
  Value key = wrenNewStringLength(vm, fullSignatureWithPrefix, fullLength);
  wrenMapSet(vm, compiler->enclosingClass->methodAttributes, key, OBJ_VAL(methodAttr));

  wrenPopRoot(vm);
}
// End file "wren_compiler.c"
// Begin file "wren_primitive.c"

#include <math.h>

// Validates that [value] is an integer within `[0, count)`. Also allows
// negative indices which map backwards from the end. Returns the valid positive
// index value. If invalid, reports an error and returns `UINT32_MAX`.
static uint32_t validateIndexValue(WrenVM* vm, uint32_t count, double value,
                                   const char* argName)
{
  if (!validateIntValue(vm, value, argName)) return UINT32_MAX;
  
  // Negative indices count from the end.
  if (value < 0) value = count + value;
  
  // Check bounds.
  if (value >= 0 && value < count) return (uint32_t)value;
  
  vm->fiber->error = wrenStringFormat(vm, "$ out of bounds.", argName);
  return UINT32_MAX;
}

bool validateFn(WrenVM* vm, Value arg, const char* argName)
{
  if (IS_CLOSURE(arg)) return true;
  RETURN_ERROR_FMT("$ must be a function.", argName);
}

bool validateNum(WrenVM* vm, Value arg, const char* argName)
{
  if (IS_NUM(arg)) return true;
  RETURN_ERROR_FMT("$ must be a number.", argName);
}

bool validateIntValue(WrenVM* vm, double value, const char* argName)
{
  if (trunc(value) == value) return true;
  RETURN_ERROR_FMT("$ must be an integer.", argName);
}

bool validateInt(WrenVM* vm, Value arg, const char* argName)
{
  // Make sure it's a number first.
  if (!validateNum(vm, arg, argName)) return false;
  return validateIntValue(vm, AS_NUM(arg), argName);
}

bool validateKey(WrenVM* vm, Value arg)
{
  if (wrenMapIsValidKey(arg)) return true;

  RETURN_ERROR("Key must be a value type.");
}

uint32_t validateIndex(WrenVM* vm, Value arg, uint32_t count,
                       const char* argName)
{
  if (!validateNum(vm, arg, argName)) return UINT32_MAX;
  return validateIndexValue(vm, count, AS_NUM(arg), argName);
}

bool validateString(WrenVM* vm, Value arg, const char* argName)
{
  if (IS_STRING(arg)) return true;
  RETURN_ERROR_FMT("$ must be a string.", argName);
}

uint32_t calculateRange(WrenVM* vm, ObjRange* range, uint32_t* length,
                        int* step)
{
  *step = 0;

  // Edge case: an empty range is allowed at the end of a sequence. This way,
  // list[0..-1] and list[0...list.count] can be used to copy a list even when
  // empty.
  if (range->from == *length &&
      range->to == (range->isInclusive ? -1.0 : (double)*length))
  {
    *length = 0;
    return 0;
  }

  uint32_t from = validateIndexValue(vm, *length, range->from, "Range start");
  if (from == UINT32_MAX) return UINT32_MAX;

  // Bounds check the end manually to handle exclusive ranges.
  double value = range->to;
  if (!validateIntValue(vm, value, "Range end")) return UINT32_MAX;

  // Negative indices count from the end.
  if (value < 0) value = *length + value;

  // Convert the exclusive range to an inclusive one.
  if (!range->isInclusive)
  {
    // An exclusive range with the same start and end points is empty.
    if (value == from)
    {
      *length = 0;
      return from;
    }

    // Shift the endpoint to make it inclusive, handling both increasing and
    // decreasing ranges.
    value += value >= from ? -1 : 1;
  }

  // Check bounds.
  if (value < 0 || value >= *length)
  {
    vm->fiber->error = CONST_STRING(vm, "Range end out of bounds.");
    return UINT32_MAX;
  }

  uint32_t to = (uint32_t)value;
  *length = abs((int)(from - to)) + 1;
  *step = from < to ? 1 : -1;
  return from;
}
// End file "wren_primitive.c"
// Begin file "wren_utils.c"
#include <string.h>


DEFINE_BUFFER(Byte, uint8_t);
DEFINE_BUFFER(Int, int);
DEFINE_BUFFER(String, ObjString*);

void wrenSymbolTableInit(SymbolTable* symbols)
{
  wrenStringBufferInit(symbols);
}

void wrenSymbolTableClear(WrenVM* vm, SymbolTable* symbols)
{
  wrenStringBufferClear(vm, symbols);
}

int wrenSymbolTableAdd(WrenVM* vm, SymbolTable* symbols,
                       const char* name, size_t length)
{
  ObjString* symbol = AS_STRING(wrenNewStringLength(vm, name, length));
  
  wrenPushRoot(vm, &symbol->obj);
  wrenStringBufferWrite(vm, symbols, symbol);
  wrenPopRoot(vm);
  
  return symbols->count - 1;
}

int wrenSymbolTableEnsure(WrenVM* vm, SymbolTable* symbols,
                          const char* name, size_t length)
{
  // See if the symbol is already defined.
  int existing = wrenSymbolTableFind(symbols, name, length);
  if (existing != -1) return existing;

  // New symbol, so add it.
  return wrenSymbolTableAdd(vm, symbols, name, length);
}

int wrenSymbolTableFind(const SymbolTable* symbols,
                        const char* name, size_t length)
{
  // See if the symbol is already defined.
  // TODO: O(n). Do something better.
  for (int i = 0; i < symbols->count; i++)
  {
    if (wrenStringEqualsCString(symbols->data[i], name, length)) return i;
  }

  return -1;
}

void wrenBlackenSymbolTable(WrenVM* vm, SymbolTable* symbolTable)
{
  for (int i = 0; i < symbolTable->count; i++)
  {
    wrenGrayObj(vm, &symbolTable->data[i]->obj);
  }
  
  // Keep track of how much memory is still in use.
  vm->bytesAllocated += symbolTable->capacity * sizeof(*symbolTable->data);
}

int wrenUtf8EncodeNumBytes(int value)
{
  ASSERT(value >= 0, "Cannot encode a negative value.");
  
  if (value <= 0x7f) return 1;
  if (value <= 0x7ff) return 2;
  if (value <= 0xffff) return 3;
  if (value <= 0x10ffff) return 4;
  return 0;
}

int wrenUtf8Encode(int value, uint8_t* bytes)
{
  if (value <= 0x7f)
  {
    // Single byte (i.e. fits in ASCII).
    *bytes = value & 0x7f;
    return 1;
  }
  else if (value <= 0x7ff)
  {
    // Two byte sequence: 110xxxxx 10xxxxxx.
    *bytes = 0xc0 | ((value & 0x7c0) >> 6);
    bytes++;
    *bytes = 0x80 | (value & 0x3f);
    return 2;
  }
  else if (value <= 0xffff)
  {
    // Three byte sequence: 1110xxxx 10xxxxxx 10xxxxxx.
    *bytes = 0xe0 | ((value & 0xf000) >> 12);
    bytes++;
    *bytes = 0x80 | ((value & 0xfc0) >> 6);
    bytes++;
    *bytes = 0x80 | (value & 0x3f);
    return 3;
  }
  else if (value <= 0x10ffff)
  {
    // Four byte sequence: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx.
    *bytes = 0xf0 | ((value & 0x1c0000) >> 18);
    bytes++;
    *bytes = 0x80 | ((value & 0x3f000) >> 12);
    bytes++;
    *bytes = 0x80 | ((value & 0xfc0) >> 6);
    bytes++;
    *bytes = 0x80 | (value & 0x3f);
    return 4;
  }

  // Invalid Unicode value. See: http://tools.ietf.org/html/rfc3629
  UNREACHABLE();
  return 0;
}

int wrenUtf8Decode(const uint8_t* bytes, uint32_t length)
{
  // Single byte (i.e. fits in ASCII).
  if (*bytes <= 0x7f) return *bytes;

  int value;
  uint32_t remainingBytes;
  if ((*bytes & 0xe0) == 0xc0)
  {
    // Two byte sequence: 110xxxxx 10xxxxxx.
    value = *bytes & 0x1f;
    remainingBytes = 1;
  }
  else if ((*bytes & 0xf0) == 0xe0)
  {
    // Three byte sequence: 1110xxxx	 10xxxxxx 10xxxxxx.
    value = *bytes & 0x0f;
    remainingBytes = 2;
  }
  else if ((*bytes & 0xf8) == 0xf0)
  {
    // Four byte sequence: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx.
    value = *bytes & 0x07;
    remainingBytes = 3;
  }
  else
  {
    // Invalid UTF-8 sequence.
    return -1;
  }

  // Don't read past the end of the buffer on truncated UTF-8.
  if (remainingBytes > length - 1) return -1;

  while (remainingBytes > 0)
  {
    bytes++;
    remainingBytes--;

    // Remaining bytes must be of form 10xxxxxx.
    if ((*bytes & 0xc0) != 0x80) return -1;

    value = value << 6 | (*bytes & 0x3f);
  }

  return value;
}

int wrenUtf8DecodeNumBytes(uint8_t byte)
{
  // If the byte starts with 10xxxxx, it's the middle of a UTF-8 sequence, so
  // don't count it at all.
  if ((byte & 0xc0) == 0x80) return 0;
  
  // The first byte's high bits tell us how many bytes are in the UTF-8
  // sequence.
  if ((byte & 0xf8) == 0xf0) return 4;
  if ((byte & 0xf0) == 0xe0) return 3;
  if ((byte & 0xe0) == 0xc0) return 2;
  return 1;
}

// From: http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2Float
int wrenPowerOf2Ceil(int n)
{
  n--;
  n |= n >> 1;
  n |= n >> 2;
  n |= n >> 4;
  n |= n >> 8;
  n |= n >> 16;
  n++;
  
  return n;
}

uint32_t wrenValidateIndex(uint32_t count, int64_t value)
{
  // Negative indices count from the end.
  if (value < 0) value = count + value;

  // Check bounds.
  if (value >= 0 && value < count) return (uint32_t)value;

  return UINT32_MAX;
}
// End file "wren_utils.c"
// Begin file "wren_core.c"
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <math.h>
#include <string.h>
#include <time.h>


// Begin file "wren_core.wren.inc"
// Generated automatically from src/vm/wren_core.wren. Do not edit.
static const char* coreModuleSource =
"class Bool {}\n"
"class Fiber {}\n"
"class Fn {}\n"
"class Null {}\n"
"class Num {}\n"
"\n"
"class Sequence {\n"
"  all(f) {\n"
"    var result = true\n"
"    for (element in this) {\n"
"      result = f.call(element)\n"
"      if (!result) return result\n"
"    }\n"
"    return result\n"
"  }\n"
"\n"
"  any(f) {\n"
"    var result = false\n"
"    for (element in this) {\n"
"      result = f.call(element)\n"
"      if (result) return result\n"
"    }\n"
"    return result\n"
"  }\n"
"\n"
"  contains(element) {\n"
"    for (item in this) {\n"
"      if (element == item) return true\n"
"    }\n"
"    return false\n"
"  }\n"
"\n"
"  count {\n"
"    var result = 0\n"
"    for (element in this) {\n"
"      result = result + 1\n"
"    }\n"
"    return result\n"
"  }\n"
"\n"
"  count(f) {\n"
"    var result = 0\n"
"    for (element in this) {\n"
"      if (f.call(element)) result = result + 1\n"
"    }\n"
"    return result\n"
"  }\n"
"\n"
"  each(f) {\n"
"    for (element in this) {\n"
"      f.call(element)\n"
"    }\n"
"  }\n"
"\n"
"  isEmpty { iterate(null) ? false : true }\n"
"\n"
"  map(transformation) { MapSequence.new(this, transformation) }\n"
"\n"
"  skip(count) {\n"
"    if (!(count is Num) || !count.isInteger || count < 0) {\n"
"      Fiber.abort(\"Count must be a non-negative integer.\")\n"
"    }\n"
"\n"
"    return SkipSequence.new(this, count)\n"
"  }\n"
"\n"
"  take(count) {\n"
"    if (!(count is Num) || !count.isInteger || count < 0) {\n"
"      Fiber.abort(\"Count must be a non-negative integer.\")\n"
"    }\n"
"\n"
"    return TakeSequence.new(this, count)\n"
"  }\n"
"\n"
"  where(predicate) { WhereSequence.new(this, predicate) }\n"
"\n"
"  reduce(acc, f) {\n"
"    for (element in this) {\n"
"      acc = f.call(acc, element)\n"
"    }\n"
"    return acc\n"
"  }\n"
"\n"
"  reduce(f) {\n"
"    var iter = iterate(null)\n"
"    if (!iter) Fiber.abort(\"Can't reduce an empty sequence.\")\n"
"\n"
"    // Seed with the first element.\n"
"    var result = iteratorValue(iter)\n"
"    while (iter = iterate(iter)) {\n"
"      result = f.call(result, iteratorValue(iter))\n"
"    }\n"
"\n"
"    return result\n"
"  }\n"
"\n"
"  join() { join(\"\") }\n"
"\n"
"  join(sep) {\n"
"    var first = true\n"
"    var result = \"\"\n"
"\n"
"    for (element in this) {\n"
"      if (!first) result = result + sep\n"
"      first = false\n"
"      result = result + element.toString\n"
"    }\n"
"\n"
"    return result\n"
"  }\n"
"\n"
"  toList {\n"
"    var result = List.new()\n"
"    for (element in this) {\n"
"      result.add(element)\n"
"    }\n"
"    return result\n"
"  }\n"
"}\n"
"\n"
"class MapSequence is Sequence {\n"
"  construct new(sequence, fn) {\n"
"    _sequence = sequence\n"
"    _fn = fn\n"
"  }\n"
"\n"
"  iterate(iterator) { _sequence.iterate(iterator) }\n"
"  iteratorValue(iterator) { _fn.call(_sequence.iteratorValue(iterator)) }\n"
"}\n"
"\n"
"class SkipSequence is Sequence {\n"
"  construct new(sequence, count) {\n"
"    _sequence = sequence\n"
"    _count = count\n"
"  }\n"
"\n"
"  iterate(iterator) {\n"
"    if (iterator) {\n"
"      return _sequence.iterate(iterator)\n"
"    } else {\n"
"      iterator = _sequence.iterate(iterator)\n"
"      var count = _count\n"
"      while (count > 0 && iterator) {\n"
"        iterator = _sequence.iterate(iterator)\n"
"        count = count - 1\n"
"      }\n"
"      return iterator\n"
"    }\n"
"  }\n"
"\n"
"  iteratorValue(iterator) { _sequence.iteratorValue(iterator) }\n"
"}\n"
"\n"
"class TakeSequence is Sequence {\n"
"  construct new(sequence, count) {\n"
"    _sequence = sequence\n"
"    _count = count\n"
"  }\n"
"\n"
"  iterate(iterator) {\n"
"    if (!iterator) _taken = 1 else _taken = _taken + 1\n"
"    return _taken > _count ? null : _sequence.iterate(iterator)\n"
"  }\n"
"\n"
"  iteratorValue(iterator) { _sequence.iteratorValue(iterator) }\n"
"}\n"
"\n"
"class WhereSequence is Sequence {\n"
"  construct new(sequence, fn) {\n"
"    _sequence = sequence\n"
"    _fn = fn\n"
"  }\n"
"\n"
"  iterate(iterator) {\n"
"    while (iterator = _sequence.iterate(iterator)) {\n"
"      if (_fn.call(_sequence.iteratorValue(iterator))) break\n"
"    }\n"
"    return iterator\n"
"  }\n"
"\n"
"  iteratorValue(iterator) { _sequence.iteratorValue(iterator) }\n"
"}\n"
"\n"
"class String is Sequence {\n"
"  bytes { StringByteSequence.new(this) }\n"
"  codePoints { StringCodePointSequence.new(this) }\n"
"\n"
"  split(delimiter) {\n"
"    if (!(delimiter is String) || delimiter.isEmpty) {\n"
"      Fiber.abort(\"Delimiter must be a non-empty string.\")\n"
"    }\n"
"\n"
"    var result = []\n"
"\n"
"    var last = 0\n"
"    var index = 0\n"
"\n"
"    var delimSize = delimiter.byteCount_\n"
"    var size = byteCount_\n"
"\n"
"    while (last < size && (index = indexOf(delimiter, last)) != -1) {\n"
"      result.add(this[last...index])\n"
"      last = index + delimSize\n"
"    }\n"
"\n"
"    if (last < size) {\n"
"      result.add(this[last..-1])\n"
"    } else {\n"
"      result.add(\"\")\n"
"    }\n"
"    return result\n"
"  }\n"
"\n"
"  replace(from, to) {\n"
"    if (!(from is String) || from.isEmpty) {\n"
"      Fiber.abort(\"From must be a non-empty string.\")\n"
"    } else if (!(to is String)) {\n"
"      Fiber.abort(\"To must be a string.\")\n"
"    }\n"
"\n"
"    var result = \"\"\n"
"\n"
"    var last = 0\n"
"    var index = 0\n"
"\n"
"    var fromSize = from.byteCount_\n"
"    var size = byteCount_\n"
"\n"
"    while (last < size && (index = indexOf(from, last)) != -1) {\n"
"      result = result + this[last...index] + to\n"
"      last = index + fromSize\n"
"    }\n"
"\n"
"    if (last < size) result = result + this[last..-1]\n"
"\n"
"    return result\n"
"  }\n"
"\n"
"  trim() { trim_(\"\\t\\r\\n \", true, true) }\n"
"  trim(chars) { trim_(chars, true, true) }\n"
"  trimEnd() { trim_(\"\\t\\r\\n \", false, true) }\n"
"  trimEnd(chars) { trim_(chars, false, true) }\n"
"  trimStart() { trim_(\"\\t\\r\\n \", true, false) }\n"
"  trimStart(chars) { trim_(chars, true, false) }\n"
"\n"
"  trim_(chars, trimStart, trimEnd) {\n"
"    if (!(chars is String)) {\n"
"      Fiber.abort(\"Characters must be a string.\")\n"
"    }\n"
"\n"
"    var codePoints = chars.codePoints.toList\n"
"\n"
"    var start\n"
"    if (trimStart) {\n"
"      while (start = iterate(start)) {\n"
"        if (!codePoints.contains(codePointAt_(start))) break\n"
"      }\n"
"\n"
"      if (start == false) return \"\"\n"
"    } else {\n"
"      start = 0\n"
"    }\n"
"\n"
"    var end\n"
"    if (trimEnd) {\n"
"      end = byteCount_ - 1\n"
"      while (end >= start) {\n"
"        var codePoint = codePointAt_(end)\n"
"        if (codePoint != -1 && !codePoints.contains(codePoint)) break\n"
"        end = end - 1\n"
"      }\n"
"\n"
"      if (end < start) return \"\"\n"
"    } else {\n"
"      end = -1\n"
"    }\n"
"\n"
"    return this[start..end]\n"
"  }\n"
"\n"
"  *(count) {\n"
"    if (!(count is Num) || !count.isInteger || count < 0) {\n"
"      Fiber.abort(\"Count must be a non-negative integer.\")\n"
"    }\n"
"\n"
"    var result = \"\"\n"
"    for (i in 0...count) {\n"
"      result = result + this\n"
"    }\n"
"    return result\n"
"  }\n"
"}\n"
"\n"
"class StringByteSequence is Sequence {\n"
"  construct new(string) {\n"
"    _string = string\n"
"  }\n"
"\n"
"  [index] { _string.byteAt_(index) }\n"
"  iterate(iterator) { _string.iterateByte_(iterator) }\n"
"  iteratorValue(iterator) { _string.byteAt_(iterator) }\n"
"\n"
"  count { _string.byteCount_ }\n"
"}\n"
"\n"
"class StringCodePointSequence is Sequence {\n"
"  construct new(string) {\n"
"    _string = string\n"
"  }\n"
"\n"
"  [index] { _string.codePointAt_(index) }\n"
"  iterate(iterator) { _string.iterate(iterator) }\n"
"  iteratorValue(iterator) { _string.codePointAt_(iterator) }\n"
"\n"
"  count { _string.count }\n"
"}\n"
"\n"
"class List is Sequence {\n"
"  addAll(other) {\n"
"    for (element in other) {\n"
"      add(element)\n"
"    }\n"
"    return other\n"
"  }\n"
"\n"
"  sort() { sort {|low, high| low < high } }\n"
"\n"
"  sort(comparer) {\n"
"    if (!(comparer is Fn)) {\n"
"      Fiber.abort(\"Comparer must be a function.\")\n"
"    }\n"
"    quicksort_(0, count - 1, comparer)\n"
"    return this\n"
"  }\n"
"\n"
"  quicksort_(low, high, comparer) {\n"
"    if (low < high) {\n"
"      var p = partition_(low, high, comparer)\n"
"      quicksort_(low, p - 1, comparer)\n"
"      quicksort_(p + 1, high, comparer)\n"
"    }\n"
"  }\n"
"\n"
"  partition_(low, high, comparer) {\n"
"    var p = this[high]\n"
"    var i = low - 1\n"
"    for (j in low..(high-1)) {\n"
"      if (comparer.call(this[j], p)) {  \n"
"        i = i + 1\n"
"        var t = this[i]\n"
"        this[i] = this[j]\n"
"        this[j] = t\n"
"      }\n"
"    }\n"
"    var t = this[i+1]\n"
"    this[i+1] = this[high]\n"
"    this[high] = t\n"
"    return i+1\n"
"  }\n"
"\n"
"  toString { \"[%(join(\", \"))]\" }\n"
"\n"
"  +(other) {\n"
"    var result = this[0..-1]\n"
"    for (element in other) {\n"
"      result.add(element)\n"
"    }\n"
"    return result\n"
"  }\n"
"\n"
"  *(count) {\n"
"    if (!(count is Num) || !count.isInteger || count < 0) {\n"
"      Fiber.abort(\"Count must be a non-negative integer.\")\n"
"    }\n"
"\n"
"    var result = []\n"
"    for (i in 0...count) {\n"
"      result.addAll(this)\n"
"    }\n"
"    return result\n"
"  }\n"
"}\n"
"\n"
"class Map is Sequence {\n"
"  keys { MapKeySequence.new(this) }\n"
"  values { MapValueSequence.new(this) }\n"
"\n"
"  toString {\n"
"    var first = true\n"
"    var result = \"{\"\n"
"\n"
"    for (key in keys) {\n"
"      if (!first) result = result + \", \"\n"
"      first = false\n"
"      result = result + \"%(key): %(this[key])\"\n"
"    }\n"
"\n"
"    return result + \"}\"\n"
"  }\n"
"\n"
"  iteratorValue(iterator) {\n"
"    return MapEntry.new(\n"
"        keyIteratorValue_(iterator),\n"
"        valueIteratorValue_(iterator))\n"
"  }\n"
"}\n"
"\n"
"class MapEntry {\n"
"  construct new(key, value) {\n"
"    _key = key\n"
"    _value = value\n"
"  }\n"
"\n"
"  key { _key }\n"
"  value { _value }\n"
"\n"
"  toString { \"%(_key):%(_value)\" }\n"
"}\n"
"\n"
"class MapKeySequence is Sequence {\n"
"  construct new(map) {\n"
"    _map = map\n"
"  }\n"
"\n"
"  iterate(n) { _map.iterate(n) }\n"
"  iteratorValue(iterator) { _map.keyIteratorValue_(iterator) }\n"
"}\n"
"\n"
"class MapValueSequence is Sequence {\n"
"  construct new(map) {\n"
"    _map = map\n"
"  }\n"
"\n"
"  iterate(n) { _map.iterate(n) }\n"
"  iteratorValue(iterator) { _map.valueIteratorValue_(iterator) }\n"
"}\n"
"\n"
"class Range is Sequence {}\n"
"\n"
"class System {\n"
"  static print() {\n"
"    writeString_(\"\\n\")\n"
"  }\n"
"\n"
"  static print(obj) {\n"
"    writeObject_(obj)\n"
"    writeString_(\"\\n\")\n"
"    return obj\n"
"  }\n"
"\n"
"  static printAll(sequence) {\n"
"    for (object in sequence) writeObject_(object)\n"
"    writeString_(\"\\n\")\n"
"  }\n"
"\n"
"  static write(obj) {\n"
"    writeObject_(obj)\n"
"    return obj\n"
"  }\n"
"\n"
"  static writeAll(sequence) {\n"
"    for (object in sequence) writeObject_(object)\n"
"  }\n"
"\n"
"  static writeObject_(obj) {\n"
"    var string = obj.toString\n"
"    if (string is String) {\n"
"      writeString_(string)\n"
"    } else {\n"
"      writeString_(\"[invalid toString]\")\n"
"    }\n"
"  }\n"
"}\n"
"\n"
"class ClassAttributes {\n"
"  self { _attributes }\n"
"  methods { _methods }\n"
"  construct new(attributes, methods) {\n"
"    _attributes = attributes\n"
"    _methods = methods\n"
"  }\n"
"  toString { \"attributes:%(_attributes) methods:%(_methods)\" }\n"
"}\n";
// End file "wren_core.wren.inc"

DEF_PRIMITIVE(bool_not)
{
  RETURN_BOOL(!AS_BOOL(args[0]));
}

DEF_PRIMITIVE(bool_toString)
{
  if (AS_BOOL(args[0]))
  {
    RETURN_VAL(CONST_STRING(vm, "true"));
  }
  else
  {
    RETURN_VAL(CONST_STRING(vm, "false"));
  }
}

DEF_PRIMITIVE(class_name)
{
  RETURN_OBJ(AS_CLASS(args[0])->name);
}

DEF_PRIMITIVE(class_supertype)
{
  ObjClass* classObj = AS_CLASS(args[0]);

  // Object has no superclass.
  if (classObj->superclass == NULL) RETURN_NULL;

  RETURN_OBJ(classObj->superclass);
}

DEF_PRIMITIVE(class_toString)
{
  RETURN_OBJ(AS_CLASS(args[0])->name);
}

DEF_PRIMITIVE(class_attributes)
{
  RETURN_VAL(AS_CLASS(args[0])->attributes);
}

DEF_PRIMITIVE(fiber_new)
{
  if (!validateFn(vm, args[1], "Argument")) return false;

  ObjClosure* closure = AS_CLOSURE(args[1]);
  if (closure->fn->arity > 1)
  {
    RETURN_ERROR("Function cannot take more than one parameter.");
  }
  
  RETURN_OBJ(wrenNewFiber(vm, closure));
}

DEF_PRIMITIVE(fiber_abort)
{
  vm->fiber->error = args[1];

  // If the error is explicitly null, it's not really an abort.
  return IS_NULL(args[1]);
}

// Transfer execution to [fiber] coming from the current fiber whose stack has
// [args].
//
// [isCall] is true if [fiber] is being called and not transferred.
//
// [hasValue] is true if a value in [args] is being passed to the new fiber.
// Otherwise, `null` is implicitly being passed.
static bool runFiber(WrenVM* vm, ObjFiber* fiber, Value* args, bool isCall,
                     bool hasValue, const char* verb)
{

  if (wrenHasError(fiber))
  {
    RETURN_ERROR_FMT("Cannot $ an aborted fiber.", verb);
  }

  if (isCall)
  {
    // You can't call a called fiber, but you can transfer directly to it,
    // which is why this check is gated on `isCall`. This way, after resuming a
    // suspended fiber, it will run and then return to the fiber that called it
    // and so on.
    if (fiber->caller != NULL) RETURN_ERROR("Fiber has already been called.");

    if (fiber->state == FIBER_ROOT) RETURN_ERROR("Cannot call root fiber.");
    
    // Remember who ran it.
    fiber->caller = vm->fiber;
  }

  if (fiber->numFrames == 0)
  {
    RETURN_ERROR_FMT("Cannot $ a finished fiber.", verb);
  }

  // When the calling fiber resumes, we'll store the result of the call in its
  // stack. If the call has two arguments (the fiber and the value), we only
  // need one slot for the result, so discard the other slot now.
  if (hasValue) vm->fiber->stackTop--;

  if (fiber->numFrames == 1 &&
      fiber->frames[0].ip == fiber->frames[0].closure->fn->code.data)
  {
    // The fiber is being started for the first time. If its function takes a
    // parameter, bind an argument to it.
    if (fiber->frames[0].closure->fn->arity == 1)
    {
      fiber->stackTop[0] = hasValue ? args[1] : NULL_VAL;
      fiber->stackTop++;
    }
  }
  else
  {
    // The fiber is being resumed, make yield() or transfer() return the result.
    fiber->stackTop[-1] = hasValue ? args[1] : NULL_VAL;
  }

  vm->fiber = fiber;
  return false;
}

DEF_PRIMITIVE(fiber_call)
{
  return runFiber(vm, AS_FIBER(args[0]), args, true, false, "call");
}

DEF_PRIMITIVE(fiber_call1)
{
  return runFiber(vm, AS_FIBER(args[0]), args, true, true, "call");
}

DEF_PRIMITIVE(fiber_current)
{
  RETURN_OBJ(vm->fiber);
}

DEF_PRIMITIVE(fiber_error)
{
  RETURN_VAL(AS_FIBER(args[0])->error);
}

DEF_PRIMITIVE(fiber_isDone)
{
  ObjFiber* runFiber = AS_FIBER(args[0]);
  RETURN_BOOL(runFiber->numFrames == 0 || wrenHasError(runFiber));
}

DEF_PRIMITIVE(fiber_suspend)
{
  // Switching to a null fiber tells the interpreter to stop and exit.
  vm->fiber = NULL;
  vm->apiStack = NULL;
  return false;
}

DEF_PRIMITIVE(fiber_transfer)
{
  return runFiber(vm, AS_FIBER(args[0]), args, false, false, "transfer to");
}

DEF_PRIMITIVE(fiber_transfer1)
{
  return runFiber(vm, AS_FIBER(args[0]), args, false, true, "transfer to");
}

DEF_PRIMITIVE(fiber_transferError)
{
  runFiber(vm, AS_FIBER(args[0]), args, false, true, "transfer to");
  vm->fiber->error = args[1];
  return false;
}

DEF_PRIMITIVE(fiber_try)
{
  runFiber(vm, AS_FIBER(args[0]), args, true, false, "try");
  
  // If we're switching to a valid fiber to try, remember that we're trying it.
  if (!wrenHasError(vm->fiber)) vm->fiber->state = FIBER_TRY;
  return false;
}

DEF_PRIMITIVE(fiber_try1)
{
  runFiber(vm, AS_FIBER(args[0]), args, true, true, "try");
  
  // If we're switching to a valid fiber to try, remember that we're trying it.
  if (!wrenHasError(vm->fiber)) vm->fiber->state = FIBER_TRY;
  return false;
}

DEF_PRIMITIVE(fiber_yield)
{
  ObjFiber* current = vm->fiber;
  vm->fiber = current->caller;

  // Unhook this fiber from the one that called it.
  current->caller = NULL;
  current->state = FIBER_OTHER;

  if (vm->fiber != NULL)
  {
    // Make the caller's run method return null.
    vm->fiber->stackTop[-1] = NULL_VAL;
  }

  return false;
}

DEF_PRIMITIVE(fiber_yield1)
{
  ObjFiber* current = vm->fiber;
  vm->fiber = current->caller;

  // Unhook this fiber from the one that called it.
  current->caller = NULL;
  current->state = FIBER_OTHER;

  if (vm->fiber != NULL)
  {
    // Make the caller's run method return the argument passed to yield.
    vm->fiber->stackTop[-1] = args[1];

    // When the yielding fiber resumes, we'll store the result of the yield
    // call in its stack. Since Fiber.yield(value) has two arguments (the Fiber
    // class and the value) and we only need one slot for the result, discard
    // the other slot now.
    current->stackTop--;
  }

  return false;
}

DEF_PRIMITIVE(fn_new)
{
  if (!validateFn(vm, args[1], "Argument")) return false;

  // The block argument is already a function, so just return it.
  RETURN_VAL(args[1]);
}

DEF_PRIMITIVE(fn_arity)
{
  RETURN_NUM(AS_CLOSURE(args[0])->fn->arity);
}

static void call_fn(WrenVM* vm, Value* args, int numArgs)
{
  // +1 to include the function itself.
  wrenCallFunction(vm, vm->fiber, AS_CLOSURE(args[0]), numArgs + 1);
}

#define DEF_FN_CALL(numArgs)                                                   \
    DEF_PRIMITIVE(fn_call##numArgs)                                            \
    {                                                                          \
      call_fn(vm, args, numArgs);                                              \
      return false;                                                            \
    }

DEF_FN_CALL(0)
DEF_FN_CALL(1)
DEF_FN_CALL(2)
DEF_FN_CALL(3)
DEF_FN_CALL(4)
DEF_FN_CALL(5)
DEF_FN_CALL(6)
DEF_FN_CALL(7)
DEF_FN_CALL(8)
DEF_FN_CALL(9)
DEF_FN_CALL(10)
DEF_FN_CALL(11)
DEF_FN_CALL(12)
DEF_FN_CALL(13)
DEF_FN_CALL(14)
DEF_FN_CALL(15)
DEF_FN_CALL(16)

DEF_PRIMITIVE(fn_toString)
{
  RETURN_VAL(CONST_STRING(vm, "<fn>"));
}

// Creates a new list of size args[1], with all elements initialized to args[2].
DEF_PRIMITIVE(list_filled)
{
  if (!validateInt(vm, args[1], "Size")) return false;  
  if (AS_NUM(args[1]) < 0) RETURN_ERROR("Size cannot be negative.");
  
  uint32_t size = (uint32_t)AS_NUM(args[1]);
  ObjList* list = wrenNewList(vm, size);
  
  for (uint32_t i = 0; i < size; i++)
  {
    list->elements.data[i] = args[2];
  }
  
  RETURN_OBJ(list);
}

DEF_PRIMITIVE(list_new)
{
  RETURN_OBJ(wrenNewList(vm, 0));
}

DEF_PRIMITIVE(list_add)
{
  wrenValueBufferWrite(vm, &AS_LIST(args[0])->elements, args[1]);
  RETURN_VAL(args[1]);
}

// Adds an element to the list and then returns the list itself. This is called
// by the compiler when compiling list literals instead of using add() to
// minimize stack churn.
DEF_PRIMITIVE(list_addCore)
{
  wrenValueBufferWrite(vm, &AS_LIST(args[0])->elements, args[1]);
  
  // Return the list.
  RETURN_VAL(args[0]);
}

DEF_PRIMITIVE(list_clear)
{
  wrenValueBufferClear(vm, &AS_LIST(args[0])->elements);
  RETURN_NULL;
}

DEF_PRIMITIVE(list_count)
{
  RETURN_NUM(AS_LIST(args[0])->elements.count);
}

DEF_PRIMITIVE(list_insert)
{
  ObjList* list = AS_LIST(args[0]);

  // count + 1 here so you can "insert" at the very end.
  uint32_t index = validateIndex(vm, args[1], list->elements.count + 1,
                                 "Index");
  if (index == UINT32_MAX) return false;

  wrenListInsert(vm, list, args[2], index);
  RETURN_VAL(args[2]);
}

DEF_PRIMITIVE(list_iterate)
{
  ObjList* list = AS_LIST(args[0]);

  // If we're starting the iteration, return the first index.
  if (IS_NULL(args[1]))
  {
    if (list->elements.count == 0) RETURN_FALSE;
    RETURN_NUM(0);
  }

  if (!validateInt(vm, args[1], "Iterator")) return false;

  // Stop if we're out of bounds.
  double index = AS_NUM(args[1]);
  if (index < 0 || index >= list->elements.count - 1) RETURN_FALSE;

  // Otherwise, move to the next index.
  RETURN_NUM(index + 1);
}

DEF_PRIMITIVE(list_iteratorValue)
{
  ObjList* list = AS_LIST(args[0]);
  uint32_t index = validateIndex(vm, args[1], list->elements.count, "Iterator");
  if (index == UINT32_MAX) return false;

  RETURN_VAL(list->elements.data[index]);
}

DEF_PRIMITIVE(list_removeAt)
{
  ObjList* list = AS_LIST(args[0]);
  uint32_t index = validateIndex(vm, args[1], list->elements.count, "Index");
  if (index == UINT32_MAX) return false;

  RETURN_VAL(wrenListRemoveAt(vm, list, index));
}

DEF_PRIMITIVE(list_removeValue) {
  ObjList* list = AS_LIST(args[0]);
  int index = wrenListIndexOf(vm, list, args[1]);
  if(index == -1) RETURN_NULL;
  RETURN_VAL(wrenListRemoveAt(vm, list, index));
}

DEF_PRIMITIVE(list_indexOf)
{
  ObjList* list = AS_LIST(args[0]);
  RETURN_NUM(wrenListIndexOf(vm, list, args[1]));
}

DEF_PRIMITIVE(list_swap)
{
  ObjList* list = AS_LIST(args[0]);
  uint32_t indexA = validateIndex(vm, args[1], list->elements.count, "Index 0");
  if (indexA == UINT32_MAX) return false;
  uint32_t indexB = validateIndex(vm, args[2], list->elements.count, "Index 1");
  if (indexB == UINT32_MAX) return false;

  Value a = list->elements.data[indexA];
  list->elements.data[indexA] = list->elements.data[indexB];
  list->elements.data[indexB] = a;

  RETURN_NULL;
}

DEF_PRIMITIVE(list_subscript)
{
  ObjList* list = AS_LIST(args[0]);

  if (IS_NUM(args[1]))
  {
    uint32_t index = validateIndex(vm, args[1], list->elements.count,
                                   "Subscript");
    if (index == UINT32_MAX) return false;

    RETURN_VAL(list->elements.data[index]);
  }

  if (!IS_RANGE(args[1]))
  {
    RETURN_ERROR("Subscript must be a number or a range.");
  }

  int step;
  uint32_t count = list->elements.count;
  uint32_t start = calculateRange(vm, AS_RANGE(args[1]), &count, &step);
  if (start == UINT32_MAX) return false;

  ObjList* result = wrenNewList(vm, count);
  for (uint32_t i = 0; i < count; i++)
  {
    result->elements.data[i] = list->elements.data[start + i * step];
  }

  RETURN_OBJ(result);
}

DEF_PRIMITIVE(list_subscriptSetter)
{
  ObjList* list = AS_LIST(args[0]);
  uint32_t index = validateIndex(vm, args[1], list->elements.count,
                                 "Subscript");
  if (index == UINT32_MAX) return false;

  list->elements.data[index] = args[2];
  RETURN_VAL(args[2]);
}

DEF_PRIMITIVE(map_new)
{
  RETURN_OBJ(wrenNewMap(vm));
}

DEF_PRIMITIVE(map_subscript)
{
  if (!validateKey(vm, args[1])) return false;

  ObjMap* map = AS_MAP(args[0]);
  Value value = wrenMapGet(map, args[1]);
  if (IS_UNDEFINED(value)) RETURN_NULL;

  RETURN_VAL(value);
}

DEF_PRIMITIVE(map_subscriptSetter)
{
  if (!validateKey(vm, args[1])) return false;

  wrenMapSet(vm, AS_MAP(args[0]), args[1], args[2]);
  RETURN_VAL(args[2]);
}

// Adds an entry to the map and then returns the map itself. This is called by
// the compiler when compiling map literals instead of using [_]=(_) to
// minimize stack churn.
DEF_PRIMITIVE(map_addCore)
{
  if (!validateKey(vm, args[1])) return false;
  
  wrenMapSet(vm, AS_MAP(args[0]), args[1], args[2]);
  
  // Return the map itself.
  RETURN_VAL(args[0]);
}

DEF_PRIMITIVE(map_clear)
{
  wrenMapClear(vm, AS_MAP(args[0]));
  RETURN_NULL;
}

DEF_PRIMITIVE(map_containsKey)
{
  if (!validateKey(vm, args[1])) return false;

  RETURN_BOOL(!IS_UNDEFINED(wrenMapGet(AS_MAP(args[0]), args[1])));
}

DEF_PRIMITIVE(map_count)
{
  RETURN_NUM(AS_MAP(args[0])->count);
}

DEF_PRIMITIVE(map_iterate)
{
  ObjMap* map = AS_MAP(args[0]);

  if (map->count == 0) RETURN_FALSE;

  // If we're starting the iteration, start at the first used entry.
  uint32_t index = 0;

  // Otherwise, start one past the last entry we stopped at.
  if (!IS_NULL(args[1]))
  {
    if (!validateInt(vm, args[1], "Iterator")) return false;

    if (AS_NUM(args[1]) < 0) RETURN_FALSE;
    index = (uint32_t)AS_NUM(args[1]);

    if (index >= map->capacity) RETURN_FALSE;

    // Advance the iterator.
    index++;
  }

  // Find a used entry, if any.
  for (; index < map->capacity; index++)
  {
    if (!IS_UNDEFINED(map->entries[index].key)) RETURN_NUM(index);
  }

  // If we get here, walked all of the entries.
  RETURN_FALSE;
}

DEF_PRIMITIVE(map_remove)
{
  if (!validateKey(vm, args[1])) return false;

  RETURN_VAL(wrenMapRemoveKey(vm, AS_MAP(args[0]), args[1]));
}

DEF_PRIMITIVE(map_keyIteratorValue)
{
  ObjMap* map = AS_MAP(args[0]);
  uint32_t index = validateIndex(vm, args[1], map->capacity, "Iterator");
  if (index == UINT32_MAX) return false;

  MapEntry* entry = &map->entries[index];
  if (IS_UNDEFINED(entry->key))
  {
    RETURN_ERROR("Invalid map iterator.");
  }

  RETURN_VAL(entry->key);
}

DEF_PRIMITIVE(map_valueIteratorValue)
{
  ObjMap* map = AS_MAP(args[0]);
  uint32_t index = validateIndex(vm, args[1], map->capacity, "Iterator");
  if (index == UINT32_MAX) return false;

  MapEntry* entry = &map->entries[index];
  if (IS_UNDEFINED(entry->key))
  {
    RETURN_ERROR("Invalid map iterator.");
  }

  RETURN_VAL(entry->value);
}

DEF_PRIMITIVE(null_not)
{
  RETURN_VAL(TRUE_VAL);
}

DEF_PRIMITIVE(null_toString)
{
  RETURN_VAL(CONST_STRING(vm, "null"));
}

DEF_PRIMITIVE(num_fromString)
{
  if (!validateString(vm, args[1], "Argument")) return false;

  ObjString* string = AS_STRING(args[1]);

  // Corner case: Can't parse an empty string.
  if (string->length == 0) RETURN_NULL;

  errno = 0;
  char* end;
  double number = strtod(string->value, &end);

  // Skip past any trailing whitespace.
  while (*end != '\0' && isspace((unsigned char)*end)) end++;

  if (errno == ERANGE) RETURN_ERROR("Number literal is too large.");

  // We must have consumed the entire string. Otherwise, it contains non-number
  // characters and we can't parse it.
  if (end < string->value + string->length) RETURN_NULL;

  RETURN_NUM(number);
}

// Defines a primitive on Num that calls infix [op] and returns [type].
#define DEF_NUM_CONSTANT(name, value)                                          \
    DEF_PRIMITIVE(num_##name)                                                  \
    {                                                                          \
      RETURN_NUM(value);                                                       \
    }

DEF_NUM_CONSTANT(infinity, INFINITY)
DEF_NUM_CONSTANT(nan,      WREN_DOUBLE_NAN)
DEF_NUM_CONSTANT(pi,       3.14159265358979323846264338327950288)
DEF_NUM_CONSTANT(tau,      6.28318530717958647692528676655900577)

DEF_NUM_CONSTANT(largest,  DBL_MAX)
DEF_NUM_CONSTANT(smallest, DBL_MIN)

DEF_NUM_CONSTANT(maxSafeInteger, 9007199254740991.0)
DEF_NUM_CONSTANT(minSafeInteger, -9007199254740991.0)

// Defines a primitive on Num that calls infix [op] and returns [type].
#define DEF_NUM_INFIX(name, op, type)                                          \
    DEF_PRIMITIVE(num_##name)                                                  \
    {                                                                          \
      if (!validateNum(vm, args[1], "Right operand")) return false;            \
      RETURN_##type(AS_NUM(args[0]) op AS_NUM(args[1]));                       \
    }

DEF_NUM_INFIX(minus,    -,  NUM)
DEF_NUM_INFIX(plus,     +,  NUM)
DEF_NUM_INFIX(multiply, *,  NUM)
DEF_NUM_INFIX(divide,   /,  NUM)
DEF_NUM_INFIX(lt,       <,  BOOL)
DEF_NUM_INFIX(gt,       >,  BOOL)
DEF_NUM_INFIX(lte,      <=, BOOL)
DEF_NUM_INFIX(gte,      >=, BOOL)

// Defines a primitive on Num that call infix bitwise [op].
#define DEF_NUM_BITWISE(name, op)                                              \
    DEF_PRIMITIVE(num_bitwise##name)                                           \
    {                                                                          \
      if (!validateNum(vm, args[1], "Right operand")) return false;            \
      uint32_t left = (uint32_t)AS_NUM(args[0]);                               \
      uint32_t right = (uint32_t)AS_NUM(args[1]);                              \
      RETURN_NUM(left op right);                                               \
    }

DEF_NUM_BITWISE(And,        &)
DEF_NUM_BITWISE(Or,         |)
DEF_NUM_BITWISE(Xor,        ^)
DEF_NUM_BITWISE(LeftShift,  <<)
DEF_NUM_BITWISE(RightShift, >>)

// Defines a primitive method on Num that returns the result of [fn].
#define DEF_NUM_FN(name, fn)                                                   \
    DEF_PRIMITIVE(num_##name)                                                  \
    {                                                                          \
      RETURN_NUM(fn(AS_NUM(args[0])));                                         \
    }

DEF_NUM_FN(abs,     fabs)
DEF_NUM_FN(acos,    acos)
DEF_NUM_FN(asin,    asin)
DEF_NUM_FN(atan,    atan)
DEF_NUM_FN(cbrt,    cbrt)
DEF_NUM_FN(ceil,    ceil)
DEF_NUM_FN(cos,     cos)
DEF_NUM_FN(floor,   floor)
DEF_NUM_FN(negate,  -)
DEF_NUM_FN(round,   round)
DEF_NUM_FN(sin,     sin)
DEF_NUM_FN(sqrt,    sqrt)
DEF_NUM_FN(tan,     tan)
DEF_NUM_FN(log,     log)
DEF_NUM_FN(log2,    log2)
DEF_NUM_FN(exp,     exp)

DEF_PRIMITIVE(num_mod)
{
  if (!validateNum(vm, args[1], "Right operand")) return false;
  RETURN_NUM(fmod(AS_NUM(args[0]), AS_NUM(args[1])));
}

DEF_PRIMITIVE(num_eqeq)
{
  if (!IS_NUM(args[1])) RETURN_FALSE;
  RETURN_BOOL(AS_NUM(args[0]) == AS_NUM(args[1]));
}

DEF_PRIMITIVE(num_bangeq)
{
  if (!IS_NUM(args[1])) RETURN_TRUE;
  RETURN_BOOL(AS_NUM(args[0]) != AS_NUM(args[1]));
}

DEF_PRIMITIVE(num_bitwiseNot)
{
  // Bitwise operators always work on 32-bit unsigned ints.
  RETURN_NUM(~(uint32_t)AS_NUM(args[0]));
}

DEF_PRIMITIVE(num_dotDot)
{
  if (!validateNum(vm, args[1], "Right hand side of range")) return false;

  double from = AS_NUM(args[0]);
  double to = AS_NUM(args[1]);
  RETURN_VAL(wrenNewRange(vm, from, to, true));
}

DEF_PRIMITIVE(num_dotDotDot)
{
  if (!validateNum(vm, args[1], "Right hand side of range")) return false;

  double from = AS_NUM(args[0]);
  double to = AS_NUM(args[1]);
  RETURN_VAL(wrenNewRange(vm, from, to, false));
}

DEF_PRIMITIVE(num_atan2)
{
  if (!validateNum(vm, args[1], "x value")) return false;

  RETURN_NUM(atan2(AS_NUM(args[0]), AS_NUM(args[1])));
}

DEF_PRIMITIVE(num_min)
{
  if (!validateNum(vm, args[1], "Other value")) return false;

  double value = AS_NUM(args[0]);
  double other = AS_NUM(args[1]);
  RETURN_NUM(value <= other ? value : other);
}

DEF_PRIMITIVE(num_max)
{
  if (!validateNum(vm, args[1], "Other value")) return false;

  double value = AS_NUM(args[0]);
  double other = AS_NUM(args[1]);
  RETURN_NUM(value > other ? value : other);
}

DEF_PRIMITIVE(num_clamp)
{
  if (!validateNum(vm, args[1], "Min value")) return false;
  if (!validateNum(vm, args[2], "Max value")) return false;

  double value = AS_NUM(args[0]);
  double min = AS_NUM(args[1]);
  double max = AS_NUM(args[2]);
  double result = (value < min) ? min : ((value > max) ? max : value);
  RETURN_NUM(result);
}

DEF_PRIMITIVE(num_pow)
{
  if (!validateNum(vm, args[1], "Power value")) return false;

  RETURN_NUM(pow(AS_NUM(args[0]), AS_NUM(args[1])));
}

DEF_PRIMITIVE(num_fraction)
{
  double unused;
  RETURN_NUM(modf(AS_NUM(args[0]) , &unused));
}

DEF_PRIMITIVE(num_isInfinity)
{
  RETURN_BOOL(isinf(AS_NUM(args[0])));
}

DEF_PRIMITIVE(num_isInteger)
{
  double value = AS_NUM(args[0]);
  if (isnan(value) || isinf(value)) RETURN_FALSE;
  RETURN_BOOL(trunc(value) == value);
}

DEF_PRIMITIVE(num_isNan)
{
  RETURN_BOOL(isnan(AS_NUM(args[0])));
}

DEF_PRIMITIVE(num_sign)
{
  double value = AS_NUM(args[0]);
  if (value > 0)
  {
    RETURN_NUM(1);
  }
  else if (value < 0)
  {
    RETURN_NUM(-1);
  }
  else
  {
    RETURN_NUM(0);
  }
}

DEF_PRIMITIVE(num_toString)
{
  RETURN_VAL(wrenNumToString(vm, AS_NUM(args[0])));
}

DEF_PRIMITIVE(num_truncate)
{
  double integer;
  modf(AS_NUM(args[0]) , &integer);
  RETURN_NUM(integer);
}

DEF_PRIMITIVE(object_same)
{
  RETURN_BOOL(wrenValuesEqual(args[1], args[2]));
}

DEF_PRIMITIVE(object_not)
{
  RETURN_VAL(FALSE_VAL);
}

DEF_PRIMITIVE(object_eqeq)
{
  RETURN_BOOL(wrenValuesEqual(args[0], args[1]));
}

DEF_PRIMITIVE(object_bangeq)
{
  RETURN_BOOL(!wrenValuesEqual(args[0], args[1]));
}

DEF_PRIMITIVE(object_is)
{
  if (!IS_CLASS(args[1]))
  {
    RETURN_ERROR("Right operand must be a class.");
  }

  ObjClass *classObj = wrenGetClass(vm, args[0]);
  ObjClass *baseClassObj = AS_CLASS(args[1]);

  // Walk the superclass chain looking for the class.
  do
  {
    if (baseClassObj == classObj) RETURN_BOOL(true);

    classObj = classObj->superclass;
  }
  while (classObj != NULL);

  RETURN_BOOL(false);
}

DEF_PRIMITIVE(object_toString)
{
  Obj* obj = AS_OBJ(args[0]);
  Value name = OBJ_VAL(obj->classObj->name);
  RETURN_VAL(wrenStringFormat(vm, "instance of @", name));
}

DEF_PRIMITIVE(object_type)
{
  RETURN_OBJ(wrenGetClass(vm, args[0]));
}

DEF_PRIMITIVE(range_from)
{
  RETURN_NUM(AS_RANGE(args[0])->from);
}

DEF_PRIMITIVE(range_to)
{
  RETURN_NUM(AS_RANGE(args[0])->to);
}

DEF_PRIMITIVE(range_min)
{
  ObjRange* range = AS_RANGE(args[0]);
  RETURN_NUM(fmin(range->from, range->to));
}

DEF_PRIMITIVE(range_max)
{
  ObjRange* range = AS_RANGE(args[0]);
  RETURN_NUM(fmax(range->from, range->to));
}

DEF_PRIMITIVE(range_isInclusive)
{
  RETURN_BOOL(AS_RANGE(args[0])->isInclusive);
}

DEF_PRIMITIVE(range_iterate)
{
  ObjRange* range = AS_RANGE(args[0]);

  // Special case: empty range.
  if (range->from == range->to && !range->isInclusive) RETURN_FALSE;

  // Start the iteration.
  if (IS_NULL(args[1])) RETURN_NUM(range->from);

  if (!validateNum(vm, args[1], "Iterator")) return false;

  double iterator = AS_NUM(args[1]);

  // Iterate towards [to] from [from].
  if (range->from < range->to)
  {
    iterator++;
    if (iterator > range->to) RETURN_FALSE;
  }
  else
  {
    iterator--;
    if (iterator < range->to) RETURN_FALSE;
  }

  if (!range->isInclusive && iterator == range->to) RETURN_FALSE;

  RETURN_NUM(iterator);
}

DEF_PRIMITIVE(range_iteratorValue)
{
  // Assume the iterator is a number so that is the value of the range.
  RETURN_VAL(args[1]);
}

DEF_PRIMITIVE(range_toString)
{
  ObjRange* range = AS_RANGE(args[0]);

  Value from = wrenNumToString(vm, range->from);
  wrenPushRoot(vm, AS_OBJ(from));

  Value to = wrenNumToString(vm, range->to);
  wrenPushRoot(vm, AS_OBJ(to));

  Value result = wrenStringFormat(vm, "@$@", from,
                                  range->isInclusive ? ".." : "...", to);

  wrenPopRoot(vm);
  wrenPopRoot(vm);
  RETURN_VAL(result);
}

DEF_PRIMITIVE(string_fromCodePoint)
{
  if (!validateInt(vm, args[1], "Code point")) return false;

  int codePoint = (int)AS_NUM(args[1]);
  if (codePoint < 0)
  {
    RETURN_ERROR("Code point cannot be negative.");
  }
  else if (codePoint > 0x10ffff)
  {
    RETURN_ERROR("Code point cannot be greater than 0x10ffff.");
  }

  RETURN_VAL(wrenStringFromCodePoint(vm, codePoint));
}

DEF_PRIMITIVE(string_fromByte)
{
  if (!validateInt(vm, args[1], "Byte")) return false;
  int byte = (int) AS_NUM(args[1]);
  if (byte < 0)
  {
    RETURN_ERROR("Byte cannot be negative.");
  }
  else if (byte > 0xff)
  {
    RETURN_ERROR("Byte cannot be greater than 0xff.");
  }
  RETURN_VAL(wrenStringFromByte(vm, (uint8_t) byte));
}

DEF_PRIMITIVE(string_byteAt)
{
  ObjString* string = AS_STRING(args[0]);

  uint32_t index = validateIndex(vm, args[1], string->length, "Index");
  if (index == UINT32_MAX) return false;

  RETURN_NUM((uint8_t)string->value[index]);
}

DEF_PRIMITIVE(string_byteCount)
{
  RETURN_NUM(AS_STRING(args[0])->length);
}

DEF_PRIMITIVE(string_codePointAt)
{
  ObjString* string = AS_STRING(args[0]);

  uint32_t index = validateIndex(vm, args[1], string->length, "Index");
  if (index == UINT32_MAX) return false;

  // If we are in the middle of a UTF-8 sequence, indicate that.
  const uint8_t* bytes = (uint8_t*)string->value;
  if ((bytes[index] & 0xc0) == 0x80) RETURN_NUM(-1);

  // Decode the UTF-8 sequence.
  RETURN_NUM(wrenUtf8Decode((uint8_t*)string->value + index,
                            string->length - index));
}

DEF_PRIMITIVE(string_contains)
{
  if (!validateString(vm, args[1], "Argument")) return false;

  ObjString* string = AS_STRING(args[0]);
  ObjString* search = AS_STRING(args[1]);

  RETURN_BOOL(wrenStringFind(string, search, 0) != UINT32_MAX);
}

DEF_PRIMITIVE(string_endsWith)
{
  if (!validateString(vm, args[1], "Argument")) return false;

  ObjString* string = AS_STRING(args[0]);
  ObjString* search = AS_STRING(args[1]);

  // Edge case: If the search string is longer then return false right away.
  if (search->length > string->length) RETURN_FALSE;

  RETURN_BOOL(memcmp(string->value + string->length - search->length,
                     search->value, search->length) == 0);
}

DEF_PRIMITIVE(string_indexOf1)
{
  if (!validateString(vm, args[1], "Argument")) return false;

  ObjString* string = AS_STRING(args[0]);
  ObjString* search = AS_STRING(args[1]);

  uint32_t index = wrenStringFind(string, search, 0);
  RETURN_NUM(index == UINT32_MAX ? -1 : (int)index);
}

DEF_PRIMITIVE(string_indexOf2)
{
  if (!validateString(vm, args[1], "Argument")) return false;

  ObjString* string = AS_STRING(args[0]);
  ObjString* search = AS_STRING(args[1]);
  uint32_t start = validateIndex(vm, args[2], string->length, "Start");
  if (start == UINT32_MAX) return false;
  
  uint32_t index = wrenStringFind(string, search, start);
  RETURN_NUM(index == UINT32_MAX ? -1 : (int)index);
}

DEF_PRIMITIVE(string_iterate)
{
  ObjString* string = AS_STRING(args[0]);

  // If we're starting the iteration, return the first index.
  if (IS_NULL(args[1]))
  {
    if (string->length == 0) RETURN_FALSE;
    RETURN_NUM(0);
  }

  if (!validateInt(vm, args[1], "Iterator")) return false;

  if (AS_NUM(args[1]) < 0) RETURN_FALSE;
  uint32_t index = (uint32_t)AS_NUM(args[1]);

  // Advance to the beginning of the next UTF-8 sequence.
  do
  {
    index++;
    if (index >= string->length) RETURN_FALSE;
  } while ((string->value[index] & 0xc0) == 0x80);

  RETURN_NUM(index);
}

DEF_PRIMITIVE(string_iterateByte)
{
  ObjString* string = AS_STRING(args[0]);

  // If we're starting the iteration, return the first index.
  if (IS_NULL(args[1]))
  {
    if (string->length == 0) RETURN_FALSE;
    RETURN_NUM(0);
  }

  if (!validateInt(vm, args[1], "Iterator")) return false;

  if (AS_NUM(args[1]) < 0) RETURN_FALSE;
  uint32_t index = (uint32_t)AS_NUM(args[1]);

  // Advance to the next byte.
  index++;
  if (index >= string->length) RETURN_FALSE;

  RETURN_NUM(index);
}

DEF_PRIMITIVE(string_iteratorValue)
{
  ObjString* string = AS_STRING(args[0]);
  uint32_t index = validateIndex(vm, args[1], string->length, "Iterator");
  if (index == UINT32_MAX) return false;

  RETURN_VAL(wrenStringCodePointAt(vm, string, index));
}

DEF_PRIMITIVE(string_startsWith)
{
  if (!validateString(vm, args[1], "Argument")) return false;

  ObjString* string = AS_STRING(args[0]);
  ObjString* search = AS_STRING(args[1]);

  // Edge case: If the search string is longer then return false right away.
  if (search->length > string->length) RETURN_FALSE;

  RETURN_BOOL(memcmp(string->value, search->value, search->length) == 0);
}

DEF_PRIMITIVE(string_plus)
{
  if (!validateString(vm, args[1], "Right operand")) return false;
  RETURN_VAL(wrenStringFormat(vm, "@@", args[0], args[1]));
}

DEF_PRIMITIVE(string_subscript)
{
  ObjString* string = AS_STRING(args[0]);

  if (IS_NUM(args[1]))
  {
    int index = validateIndex(vm, args[1], string->length, "Subscript");
    if (index == -1) return false;

    RETURN_VAL(wrenStringCodePointAt(vm, string, index));
  }

  if (!IS_RANGE(args[1]))
  {
    RETURN_ERROR("Subscript must be a number or a range.");
  }

  int step;
  uint32_t count = string->length;
  int start = calculateRange(vm, AS_RANGE(args[1]), &count, &step);
  if (start == -1) return false;

  RETURN_VAL(wrenNewStringFromRange(vm, string, start, count, step));
}

DEF_PRIMITIVE(string_toString)
{
  RETURN_VAL(args[0]);
}

DEF_PRIMITIVE(system_clock)
{
  RETURN_NUM((double)clock() / CLOCKS_PER_SEC);
}

DEF_PRIMITIVE(system_gc)
{
  wrenCollectGarbage(vm);
  RETURN_NULL;
}

DEF_PRIMITIVE(system_writeString)
{
  if (vm->config.writeFn != NULL)
  {
    vm->config.writeFn(vm, AS_CSTRING(args[1]));
  }

  RETURN_VAL(args[1]);
}

// Creates either the Object or Class class in the core module with [name].
static ObjClass* defineClass(WrenVM* vm, ObjModule* module, const char* name)
{
  ObjString* nameString = AS_STRING(wrenNewString(vm, name));
  wrenPushRoot(vm, (Obj*)nameString);

  ObjClass* classObj = wrenNewSingleClass(vm, 0, nameString);

  wrenDefineVariable(vm, module, name, nameString->length, OBJ_VAL(classObj), NULL);

  wrenPopRoot(vm);
  return classObj;
}

void wrenInitializeCore(WrenVM* vm)
{
  ObjModule* coreModule = wrenNewModule(vm, NULL);
  wrenPushRoot(vm, (Obj*)coreModule);
  
  // The core module's key is null in the module map.
  wrenMapSet(vm, vm->modules, NULL_VAL, OBJ_VAL(coreModule));
  wrenPopRoot(vm); // coreModule.

  // Define the root Object class. This has to be done a little specially
  // because it has no superclass.
  vm->objectClass = defineClass(vm, coreModule, "Object");
  PRIMITIVE(vm->objectClass, "!", object_not);
  PRIMITIVE(vm->objectClass, "==(_)", object_eqeq);
  PRIMITIVE(vm->objectClass, "!=(_)", object_bangeq);
  PRIMITIVE(vm->objectClass, "is(_)", object_is);
  PRIMITIVE(vm->objectClass, "toString", object_toString);
  PRIMITIVE(vm->objectClass, "type", object_type);

  // Now we can define Class, which is a subclass of Object.
  vm->classClass = defineClass(vm, coreModule, "Class");
  wrenBindSuperclass(vm, vm->classClass, vm->objectClass);
  PRIMITIVE(vm->classClass, "name", class_name);
  PRIMITIVE(vm->classClass, "supertype", class_supertype);
  PRIMITIVE(vm->classClass, "toString", class_toString);
  PRIMITIVE(vm->classClass, "attributes", class_attributes);

  // Finally, we can define Object's metaclass which is a subclass of Class.
  ObjClass* objectMetaclass = defineClass(vm, coreModule, "Object metaclass");

  // Wire up the metaclass relationships now that all three classes are built.
  vm->objectClass->obj.classObj = objectMetaclass;
  objectMetaclass->obj.classObj = vm->classClass;
  vm->classClass->obj.classObj = vm->classClass;

  // Do this after wiring up the metaclasses so objectMetaclass doesn't get
  // collected.
  wrenBindSuperclass(vm, objectMetaclass, vm->classClass);

  PRIMITIVE(objectMetaclass, "same(_,_)", object_same);

  // The core class diagram ends up looking like this, where single lines point
  // to a class's superclass, and double lines point to its metaclass:
  //
  //        .------------------------------------. .====.
  //        |                  .---------------. | #    #
  //        v                  |               v | v    #
  //   .---------.   .-------------------.   .-------.  #
  //   | Object  |==>| Object metaclass  |==>| Class |=="
  //   '---------'   '-------------------'   '-------'
  //        ^                                 ^ ^ ^ ^
  //        |                  .--------------' # | #
  //        |                  |                # | #
  //   .---------.   .-------------------.      # | # -.
  //   |  Base   |==>|  Base metaclass   |======" | #  |
  //   '---------'   '-------------------'        | #  |
  //        ^                                     | #  |
  //        |                  .------------------' #  | Example classes
  //        |                  |                    #  |
  //   .---------.   .-------------------.          #  |
  //   | Derived |==>| Derived metaclass |=========="  |
  //   '---------'   '-------------------'            -'

  // The rest of the classes can now be defined normally.
  wrenInterpret(vm, NULL, coreModuleSource);

  vm->boolClass = AS_CLASS(wrenFindVariable(vm, coreModule, "Bool"));
  PRIMITIVE(vm->boolClass, "toString", bool_toString);
  PRIMITIVE(vm->boolClass, "!", bool_not);

  vm->fiberClass = AS_CLASS(wrenFindVariable(vm, coreModule, "Fiber"));
  PRIMITIVE(vm->fiberClass->obj.classObj, "new(_)", fiber_new);
  PRIMITIVE(vm->fiberClass->obj.classObj, "abort(_)", fiber_abort);
  PRIMITIVE(vm->fiberClass->obj.classObj, "current", fiber_current);
  PRIMITIVE(vm->fiberClass->obj.classObj, "suspend()", fiber_suspend);
  PRIMITIVE(vm->fiberClass->obj.classObj, "yield()", fiber_yield);
  PRIMITIVE(vm->fiberClass->obj.classObj, "yield(_)", fiber_yield1);
  PRIMITIVE(vm->fiberClass, "call()", fiber_call);
  PRIMITIVE(vm->fiberClass, "call(_)", fiber_call1);
  PRIMITIVE(vm->fiberClass, "error", fiber_error);
  PRIMITIVE(vm->fiberClass, "isDone", fiber_isDone);
  PRIMITIVE(vm->fiberClass, "transfer()", fiber_transfer);
  PRIMITIVE(vm->fiberClass, "transfer(_)", fiber_transfer1);
  PRIMITIVE(vm->fiberClass, "transferError(_)", fiber_transferError);
  PRIMITIVE(vm->fiberClass, "try()", fiber_try);
  PRIMITIVE(vm->fiberClass, "try(_)", fiber_try1);

  vm->fnClass = AS_CLASS(wrenFindVariable(vm, coreModule, "Fn"));
  PRIMITIVE(vm->fnClass->obj.classObj, "new(_)", fn_new);

  PRIMITIVE(vm->fnClass, "arity", fn_arity);

  FUNCTION_CALL(vm->fnClass, "call()", fn_call0);
  FUNCTION_CALL(vm->fnClass, "call(_)", fn_call1);
  FUNCTION_CALL(vm->fnClass, "call(_,_)", fn_call2);
  FUNCTION_CALL(vm->fnClass, "call(_,_,_)", fn_call3);
  FUNCTION_CALL(vm->fnClass, "call(_,_,_,_)", fn_call4);
  FUNCTION_CALL(vm->fnClass, "call(_,_,_,_,_)", fn_call5);
  FUNCTION_CALL(vm->fnClass, "call(_,_,_,_,_,_)", fn_call6);
  FUNCTION_CALL(vm->fnClass, "call(_,_,_,_,_,_,_)", fn_call7);
  FUNCTION_CALL(vm->fnClass, "call(_,_,_,_,_,_,_,_)", fn_call8);
  FUNCTION_CALL(vm->fnClass, "call(_,_,_,_,_,_,_,_,_)", fn_call9);
  FUNCTION_CALL(vm->fnClass, "call(_,_,_,_,_,_,_,_,_,_)", fn_call10);
  FUNCTION_CALL(vm->fnClass, "call(_,_,_,_,_,_,_,_,_,_,_)", fn_call11);
  FUNCTION_CALL(vm->fnClass, "call(_,_,_,_,_,_,_,_,_,_,_,_)", fn_call12);
  FUNCTION_CALL(vm->fnClass, "call(_,_,_,_,_,_,_,_,_,_,_,_,_)", fn_call13);
  FUNCTION_CALL(vm->fnClass, "call(_,_,_,_,_,_,_,_,_,_,_,_,_,_)", fn_call14);
  FUNCTION_CALL(vm->fnClass, "call(_,_,_,_,_,_,_,_,_,_,_,_,_,_,_)", fn_call15);
  FUNCTION_CALL(vm->fnClass, "call(_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_)", fn_call16);
  
  PRIMITIVE(vm->fnClass, "toString", fn_toString);

  vm->nullClass = AS_CLASS(wrenFindVariable(vm, coreModule, "Null"));
  PRIMITIVE(vm->nullClass, "!", null_not);
  PRIMITIVE(vm->nullClass, "toString", null_toString);

  vm->numClass = AS_CLASS(wrenFindVariable(vm, coreModule, "Num"));
  PRIMITIVE(vm->numClass->obj.classObj, "fromString(_)", num_fromString);
  PRIMITIVE(vm->numClass->obj.classObj, "infinity", num_infinity);
  PRIMITIVE(vm->numClass->obj.classObj, "nan", num_nan);
  PRIMITIVE(vm->numClass->obj.classObj, "pi", num_pi);
  PRIMITIVE(vm->numClass->obj.classObj, "tau", num_tau);
  PRIMITIVE(vm->numClass->obj.classObj, "largest", num_largest);
  PRIMITIVE(vm->numClass->obj.classObj, "smallest", num_smallest);
  PRIMITIVE(vm->numClass->obj.classObj, "maxSafeInteger", num_maxSafeInteger);
  PRIMITIVE(vm->numClass->obj.classObj, "minSafeInteger", num_minSafeInteger);
  PRIMITIVE(vm->numClass, "-(_)", num_minus);
  PRIMITIVE(vm->numClass, "+(_)", num_plus);
  PRIMITIVE(vm->numClass, "*(_)", num_multiply);
  PRIMITIVE(vm->numClass, "/(_)", num_divide);
  PRIMITIVE(vm->numClass, "<(_)", num_lt);
  PRIMITIVE(vm->numClass, ">(_)", num_gt);
  PRIMITIVE(vm->numClass, "<=(_)", num_lte);
  PRIMITIVE(vm->numClass, ">=(_)", num_gte);
  PRIMITIVE(vm->numClass, "&(_)", num_bitwiseAnd);
  PRIMITIVE(vm->numClass, "|(_)", num_bitwiseOr);
  PRIMITIVE(vm->numClass, "^(_)", num_bitwiseXor);
  PRIMITIVE(vm->numClass, "<<(_)", num_bitwiseLeftShift);
  PRIMITIVE(vm->numClass, ">>(_)", num_bitwiseRightShift);
  PRIMITIVE(vm->numClass, "abs", num_abs);
  PRIMITIVE(vm->numClass, "acos", num_acos);
  PRIMITIVE(vm->numClass, "asin", num_asin);
  PRIMITIVE(vm->numClass, "atan", num_atan);
  PRIMITIVE(vm->numClass, "cbrt", num_cbrt);
  PRIMITIVE(vm->numClass, "ceil", num_ceil);
  PRIMITIVE(vm->numClass, "cos", num_cos);
  PRIMITIVE(vm->numClass, "floor", num_floor);
  PRIMITIVE(vm->numClass, "-", num_negate);
  PRIMITIVE(vm->numClass, "round", num_round);
  PRIMITIVE(vm->numClass, "min(_)", num_min);
  PRIMITIVE(vm->numClass, "max(_)", num_max);
  PRIMITIVE(vm->numClass, "clamp(_,_)", num_clamp);
  PRIMITIVE(vm->numClass, "sin", num_sin);
  PRIMITIVE(vm->numClass, "sqrt", num_sqrt);
  PRIMITIVE(vm->numClass, "tan", num_tan);
  PRIMITIVE(vm->numClass, "log", num_log);
  PRIMITIVE(vm->numClass, "log2", num_log2);
  PRIMITIVE(vm->numClass, "exp", num_exp);
  PRIMITIVE(vm->numClass, "%(_)", num_mod);
  PRIMITIVE(vm->numClass, "~", num_bitwiseNot);
  PRIMITIVE(vm->numClass, "..(_)", num_dotDot);
  PRIMITIVE(vm->numClass, "...(_)", num_dotDotDot);
  PRIMITIVE(vm->numClass, "atan(_)", num_atan2);
  PRIMITIVE(vm->numClass, "pow(_)", num_pow);
  PRIMITIVE(vm->numClass, "fraction", num_fraction);
  PRIMITIVE(vm->numClass, "isInfinity", num_isInfinity);
  PRIMITIVE(vm->numClass, "isInteger", num_isInteger);
  PRIMITIVE(vm->numClass, "isNan", num_isNan);
  PRIMITIVE(vm->numClass, "sign", num_sign);
  PRIMITIVE(vm->numClass, "toString", num_toString);
  PRIMITIVE(vm->numClass, "truncate", num_truncate);

  // These are defined just so that 0 and -0 are equal, which is specified by
  // IEEE 754 even though they have different bit representations.
  PRIMITIVE(vm->numClass, "==(_)", num_eqeq);
  PRIMITIVE(vm->numClass, "!=(_)", num_bangeq);

  vm->stringClass = AS_CLASS(wrenFindVariable(vm, coreModule, "String"));
  PRIMITIVE(vm->stringClass->obj.classObj, "fromCodePoint(_)", string_fromCodePoint);
  PRIMITIVE(vm->stringClass->obj.classObj, "fromByte(_)", string_fromByte);
  PRIMITIVE(vm->stringClass, "+(_)", string_plus);
  PRIMITIVE(vm->stringClass, "[_]", string_subscript);
  PRIMITIVE(vm->stringClass, "byteAt_(_)", string_byteAt);
  PRIMITIVE(vm->stringClass, "byteCount_", string_byteCount);
  PRIMITIVE(vm->stringClass, "codePointAt_(_)", string_codePointAt);
  PRIMITIVE(vm->stringClass, "contains(_)", string_contains);
  PRIMITIVE(vm->stringClass, "endsWith(_)", string_endsWith);
  PRIMITIVE(vm->stringClass, "indexOf(_)", string_indexOf1);
  PRIMITIVE(vm->stringClass, "indexOf(_,_)", string_indexOf2);
  PRIMITIVE(vm->stringClass, "iterate(_)", string_iterate);
  PRIMITIVE(vm->stringClass, "iterateByte_(_)", string_iterateByte);
  PRIMITIVE(vm->stringClass, "iteratorValue(_)", string_iteratorValue);
  PRIMITIVE(vm->stringClass, "startsWith(_)", string_startsWith);
  PRIMITIVE(vm->stringClass, "toString", string_toString);

  vm->listClass = AS_CLASS(wrenFindVariable(vm, coreModule, "List"));
  PRIMITIVE(vm->listClass->obj.classObj, "filled(_,_)", list_filled);
  PRIMITIVE(vm->listClass->obj.classObj, "new()", list_new);
  PRIMITIVE(vm->listClass, "[_]", list_subscript);
  PRIMITIVE(vm->listClass, "[_]=(_)", list_subscriptSetter);
  PRIMITIVE(vm->listClass, "add(_)", list_add);
  PRIMITIVE(vm->listClass, "addCore_(_)", list_addCore);
  PRIMITIVE(vm->listClass, "clear()", list_clear);
  PRIMITIVE(vm->listClass, "count", list_count);
  PRIMITIVE(vm->listClass, "insert(_,_)", list_insert);
  PRIMITIVE(vm->listClass, "iterate(_)", list_iterate);
  PRIMITIVE(vm->listClass, "iteratorValue(_)", list_iteratorValue);
  PRIMITIVE(vm->listClass, "removeAt(_)", list_removeAt);
  PRIMITIVE(vm->listClass, "remove(_)", list_removeValue);
  PRIMITIVE(vm->listClass, "indexOf(_)", list_indexOf);
  PRIMITIVE(vm->listClass, "swap(_,_)", list_swap);

  vm->mapClass = AS_CLASS(wrenFindVariable(vm, coreModule, "Map"));
  PRIMITIVE(vm->mapClass->obj.classObj, "new()", map_new);
  PRIMITIVE(vm->mapClass, "[_]", map_subscript);
  PRIMITIVE(vm->mapClass, "[_]=(_)", map_subscriptSetter);
  PRIMITIVE(vm->mapClass, "addCore_(_,_)", map_addCore);
  PRIMITIVE(vm->mapClass, "clear()", map_clear);
  PRIMITIVE(vm->mapClass, "containsKey(_)", map_containsKey);
  PRIMITIVE(vm->mapClass, "count", map_count);
  PRIMITIVE(vm->mapClass, "remove(_)", map_remove);
  PRIMITIVE(vm->mapClass, "iterate(_)", map_iterate);
  PRIMITIVE(vm->mapClass, "keyIteratorValue_(_)", map_keyIteratorValue);
  PRIMITIVE(vm->mapClass, "valueIteratorValue_(_)", map_valueIteratorValue);

  vm->rangeClass = AS_CLASS(wrenFindVariable(vm, coreModule, "Range"));
  PRIMITIVE(vm->rangeClass, "from", range_from);
  PRIMITIVE(vm->rangeClass, "to", range_to);
  PRIMITIVE(vm->rangeClass, "min", range_min);
  PRIMITIVE(vm->rangeClass, "max", range_max);
  PRIMITIVE(vm->rangeClass, "isInclusive", range_isInclusive);
  PRIMITIVE(vm->rangeClass, "iterate(_)", range_iterate);
  PRIMITIVE(vm->rangeClass, "iteratorValue(_)", range_iteratorValue);
  PRIMITIVE(vm->rangeClass, "toString", range_toString);

  ObjClass* systemClass = AS_CLASS(wrenFindVariable(vm, coreModule, "System"));
  PRIMITIVE(systemClass->obj.classObj, "clock", system_clock);
  PRIMITIVE(systemClass->obj.classObj, "gc()", system_gc);
  PRIMITIVE(systemClass->obj.classObj, "writeString_(_)", system_writeString);

  // While bootstrapping the core types and running the core module, a number
  // of string objects have been created, many of which were instantiated
  // before stringClass was stored in the VM. Some of them *must* be created
  // first -- the ObjClass for string itself has a reference to the ObjString
  // for its name.
  //
  // These all currently have a NULL classObj pointer, so go back and assign
  // them now that the string class is known.
  for (Obj* obj = vm->first; obj != NULL; obj = obj->next)
  {
    if (obj->type == OBJ_STRING) obj->classObj = vm->stringClass;
  }
}
// End file "wren_core.c"
// Begin file "wren_debug.c"
#include <stdio.h>


void wrenDebugPrintStackTrace(WrenVM* vm)
{
  // Bail if the host doesn't enable printing errors.
  if (vm->config.errorFn == NULL) return;
  
  ObjFiber* fiber = vm->fiber;
  if (IS_STRING(fiber->error))
  {
    vm->config.errorFn(vm, WREN_ERROR_RUNTIME,
                       NULL, -1, AS_CSTRING(fiber->error));
  }
  else
  {
    // TODO: Print something a little useful here. Maybe the name of the error's
    // class?
    vm->config.errorFn(vm, WREN_ERROR_RUNTIME,
                       NULL, -1, "[error object]");
  }

  for (int i = fiber->numFrames - 1; i >= 0; i--)
  {
    CallFrame* frame = &fiber->frames[i];
    ObjFn* fn = frame->closure->fn;

    // Skip over stub functions for calling methods from the C API.
    if (fn->module == NULL) continue;
    
    // The built-in core module has no name. We explicitly omit it from stack
    // traces since we don't want to highlight to a user the implementation
    // detail of what part of the core module is written in C and what is Wren.
    if (fn->module->name == NULL) continue;
    
    // -1 because IP has advanced past the instruction that it just executed.
    int line = fn->debug->sourceLines.data[frame->ip - fn->code.data - 1];
    vm->config.errorFn(vm, WREN_ERROR_STACK_TRACE,
                       fn->module->name->value, line,
                       fn->debug->name);
  }
}

static void dumpObject(Obj* obj)
{
  switch (obj->type)
  {
    case OBJ_CLASS:
      printf("[class %s %p]", ((ObjClass*)obj)->name->value, obj);
      break;
    case OBJ_CLOSURE: printf("[closure %p]", obj); break;
    case OBJ_FIBER: printf("[fiber %p]", obj); break;
    case OBJ_FN: printf("[fn %p]", obj); break;
    case OBJ_FOREIGN: printf("[foreign %p]", obj); break;
    case OBJ_INSTANCE: printf("[instance %p]", obj); break;
    case OBJ_LIST: printf("[list %p]", obj); break;
    case OBJ_MAP: printf("[map %p]", obj); break;
    case OBJ_MODULE: printf("[module %p]", obj); break;
    case OBJ_RANGE: printf("[range %p]", obj); break;
    case OBJ_STRING: printf("%s", ((ObjString*)obj)->value); break;
    case OBJ_UPVALUE: printf("[upvalue %p]", obj); break;
    default: printf("[unknown object %d]", obj->type); break;
  }
}

void wrenDumpValue(Value value)
{
#if WREN_NAN_TAGGING
  if (IS_NUM(value))
  {
    printf("%.14g", AS_NUM(value));
  }
  else if (IS_OBJ(value))
  {
    dumpObject(AS_OBJ(value));
  }
  else
  {
    switch (GET_TAG(value))
    {
      case TAG_FALSE:     printf("false"); break;
      case TAG_NAN:       printf("NaN"); break;
      case TAG_NULL:      printf("null"); break;
      case TAG_TRUE:      printf("true"); break;
      case TAG_UNDEFINED: UNREACHABLE();
    }
  }
#else
  switch (value.type)
  {
    case VAL_FALSE:     printf("false"); break;
    case VAL_NULL:      printf("null"); break;
    case VAL_NUM:       printf("%.14g", AS_NUM(value)); break;
    case VAL_TRUE:      printf("true"); break;
    case VAL_OBJ:       dumpObject(AS_OBJ(value)); break;
    case VAL_UNDEFINED: UNREACHABLE();
  }
#endif
}

static int dumpInstruction(WrenVM* vm, ObjFn* fn, int i, int* lastLine)
{
  int start = i;
  uint8_t* bytecode = fn->code.data;
  Code code = (Code)bytecode[i];

  int line = fn->debug->sourceLines.data[i];
  if (lastLine == NULL || *lastLine != line)
  {
    printf("%4d:", line);
    if (lastLine != NULL) *lastLine = line;
  }
  else
  {
    printf("     ");
  }

  printf(" %04d  ", i++);

  #define READ_BYTE() (bytecode[i++])
  #define READ_SHORT() (i += 2, (bytecode[i - 2] << 8) | bytecode[i - 1])

  #define BYTE_INSTRUCTION(name)                                               \
      printf("%-16s %5d\n", name, READ_BYTE());                                \
      break

  switch (code)
  {
    case CODE_CONSTANT:
    {
      int constant = READ_SHORT();
      printf("%-16s %5d '", "CONSTANT", constant);
      wrenDumpValue(fn->constants.data[constant]);
      printf("'\n");
      break;
    }

    case CODE_NULL:  printf("NULL\n"); break;
    case CODE_FALSE: printf("FALSE\n"); break;
    case CODE_TRUE:  printf("TRUE\n"); break;

    case CODE_LOAD_LOCAL_0: printf("LOAD_LOCAL_0\n"); break;
    case CODE_LOAD_LOCAL_1: printf("LOAD_LOCAL_1\n"); break;
    case CODE_LOAD_LOCAL_2: printf("LOAD_LOCAL_2\n"); break;
    case CODE_LOAD_LOCAL_3: printf("LOAD_LOCAL_3\n"); break;
    case CODE_LOAD_LOCAL_4: printf("LOAD_LOCAL_4\n"); break;
    case CODE_LOAD_LOCAL_5: printf("LOAD_LOCAL_5\n"); break;
    case CODE_LOAD_LOCAL_6: printf("LOAD_LOCAL_6\n"); break;
    case CODE_LOAD_LOCAL_7: printf("LOAD_LOCAL_7\n"); break;
    case CODE_LOAD_LOCAL_8: printf("LOAD_LOCAL_8\n"); break;

    case CODE_LOAD_LOCAL: BYTE_INSTRUCTION("LOAD_LOCAL");
    case CODE_STORE_LOCAL: BYTE_INSTRUCTION("STORE_LOCAL");
    case CODE_LOAD_UPVALUE: BYTE_INSTRUCTION("LOAD_UPVALUE");
    case CODE_STORE_UPVALUE: BYTE_INSTRUCTION("STORE_UPVALUE");

    case CODE_LOAD_MODULE_VAR:
    {
      int slot = READ_SHORT();
      printf("%-16s %5d '%s'\n", "LOAD_MODULE_VAR", slot,
             fn->module->variableNames.data[slot]->value);
      break;
    }

    case CODE_STORE_MODULE_VAR:
    {
      int slot = READ_SHORT();
      printf("%-16s %5d '%s'\n", "STORE_MODULE_VAR", slot,
             fn->module->variableNames.data[slot]->value);
      break;
    }

    case CODE_LOAD_FIELD_THIS: BYTE_INSTRUCTION("LOAD_FIELD_THIS");
    case CODE_STORE_FIELD_THIS: BYTE_INSTRUCTION("STORE_FIELD_THIS");
    case CODE_LOAD_FIELD: BYTE_INSTRUCTION("LOAD_FIELD");
    case CODE_STORE_FIELD: BYTE_INSTRUCTION("STORE_FIELD");

    case CODE_POP: printf("POP\n"); break;

    case CODE_CALL_0:
    case CODE_CALL_1:
    case CODE_CALL_2:
    case CODE_CALL_3:
    case CODE_CALL_4:
    case CODE_CALL_5:
    case CODE_CALL_6:
    case CODE_CALL_7:
    case CODE_CALL_8:
    case CODE_CALL_9:
    case CODE_CALL_10:
    case CODE_CALL_11:
    case CODE_CALL_12:
    case CODE_CALL_13:
    case CODE_CALL_14:
    case CODE_CALL_15:
    case CODE_CALL_16:
    {
      int numArgs = bytecode[i - 1] - CODE_CALL_0;
      int symbol = READ_SHORT();
      printf("CALL_%-11d %5d '%s'\n", numArgs, symbol,
             vm->methodNames.data[symbol]->value);
      break;
    }

    case CODE_SUPER_0:
    case CODE_SUPER_1:
    case CODE_SUPER_2:
    case CODE_SUPER_3:
    case CODE_SUPER_4:
    case CODE_SUPER_5:
    case CODE_SUPER_6:
    case CODE_SUPER_7:
    case CODE_SUPER_8:
    case CODE_SUPER_9:
    case CODE_SUPER_10:
    case CODE_SUPER_11:
    case CODE_SUPER_12:
    case CODE_SUPER_13:
    case CODE_SUPER_14:
    case CODE_SUPER_15:
    case CODE_SUPER_16:
    {
      int numArgs = bytecode[i - 1] - CODE_SUPER_0;
      int symbol = READ_SHORT();
      int superclass = READ_SHORT();
      printf("SUPER_%-10d %5d '%s' %5d\n", numArgs, symbol,
             vm->methodNames.data[symbol]->value, superclass);
      break;
    }

    case CODE_JUMP:
    {
      int offset = READ_SHORT();
      printf("%-16s %5d to %d\n", "JUMP", offset, i + offset);
      break;
    }

    case CODE_LOOP:
    {
      int offset = READ_SHORT();
      printf("%-16s %5d to %d\n", "LOOP", offset, i - offset);
      break;
    }

    case CODE_JUMP_IF:
    {
      int offset = READ_SHORT();
      printf("%-16s %5d to %d\n", "JUMP_IF", offset, i + offset);
      break;
    }

    case CODE_AND:
    {
      int offset = READ_SHORT();
      printf("%-16s %5d to %d\n", "AND", offset, i + offset);
      break;
    }

    case CODE_OR:
    {
      int offset = READ_SHORT();
      printf("%-16s %5d to %d\n", "OR", offset, i + offset);
      break;
    }

    case CODE_CLOSE_UPVALUE: printf("CLOSE_UPVALUE\n"); break;
    case CODE_RETURN:        printf("RETURN\n"); break;

    case CODE_CLOSURE:
    {
      int constant = READ_SHORT();
      printf("%-16s %5d ", "CLOSURE", constant);
      wrenDumpValue(fn->constants.data[constant]);
      printf(" ");
      ObjFn* loadedFn = AS_FN(fn->constants.data[constant]);
      for (int j = 0; j < loadedFn->numUpvalues; j++)
      {
        int isLocal = READ_BYTE();
        int index = READ_BYTE();
        if (j > 0) printf(", ");
        printf("%s %d", isLocal ? "local" : "upvalue", index);
      }
      printf("\n");
      break;
    }

    case CODE_CONSTRUCT:         printf("CONSTRUCT\n"); break;
    case CODE_FOREIGN_CONSTRUCT: printf("FOREIGN_CONSTRUCT\n"); break;
      
    case CODE_CLASS:
    {
      int numFields = READ_BYTE();
      printf("%-16s %5d fields\n", "CLASS", numFields);
      break;
    }

    case CODE_FOREIGN_CLASS: printf("FOREIGN_CLASS\n"); break;
    case CODE_END_CLASS: printf("END_CLASS\n"); break;

    case CODE_METHOD_INSTANCE:
    {
      int symbol = READ_SHORT();
      printf("%-16s %5d '%s'\n", "METHOD_INSTANCE", symbol,
             vm->methodNames.data[symbol]->value);
      break;
    }

    case CODE_METHOD_STATIC:
    {
      int symbol = READ_SHORT();
      printf("%-16s %5d '%s'\n", "METHOD_STATIC", symbol,
             vm->methodNames.data[symbol]->value);
      break;
    }
      
    case CODE_END_MODULE:
      printf("END_MODULE\n");
      break;
      
    case CODE_IMPORT_MODULE:
    {
      int name = READ_SHORT();
      printf("%-16s %5d '", "IMPORT_MODULE", name);
      wrenDumpValue(fn->constants.data[name]);
      printf("'\n");
      break;
    }
      
    case CODE_IMPORT_VARIABLE:
    {
      int variable = READ_SHORT();
      printf("%-16s %5d '", "IMPORT_VARIABLE", variable);
      wrenDumpValue(fn->constants.data[variable]);
      printf("'\n");
      break;
    }
      
    case CODE_END:
      printf("END\n");
      break;

    default:
      printf("UKNOWN! [%d]\n", bytecode[i - 1]);
      break;
  }

  // Return how many bytes this instruction takes, or -1 if it's an END.
  if (code == CODE_END) return -1;
  return i - start;

  #undef READ_BYTE
  #undef READ_SHORT
}

int wrenDumpInstruction(WrenVM* vm, ObjFn* fn, int i)
{
  return dumpInstruction(vm, fn, i, NULL);
}

void wrenDumpCode(WrenVM* vm, ObjFn* fn)
{
  printf("%s: %s\n",
         fn->module->name == NULL ? "<core>" : fn->module->name->value,
         fn->debug->name);

  int i = 0;
  int lastLine = -1;
  for (;;)
  {
    int offset = dumpInstruction(vm, fn, i, &lastLine);
    if (offset == -1) break;
    i += offset;
  }

  printf("\n");
}

void wrenDumpStack(ObjFiber* fiber)
{
  printf("(fiber %p) ", fiber);
  for (Value* slot = fiber->stack; slot < fiber->stackTop; slot++)
  {
    wrenDumpValue(*slot);
    printf(" | ");
  }
  printf("\n");
}
// End file "wren_debug.c"
// Begin file "wren_opt_random.c"

#if WREN_OPT_RANDOM

#include <string.h>
#include <time.h>


// Begin file "wren_opt_random.wren.inc"
// Generated automatically from src/optional/wren_opt_random.wren. Do not edit.
static const char* randomModuleSource =
"foreign class Random {\n"
"  construct new() {\n"
"    seed_()\n"
"  }\n"
"\n"
"  construct new(seed) {\n"
"    if (seed is Num) {\n"
"      seed_(seed)\n"
"    } else if (seed is Sequence) {\n"
"      if (seed.isEmpty) Fiber.abort(\"Sequence cannot be empty.\")\n"
"\n"
"      // TODO: Empty sequence.\n"
"      var seeds = []\n"
"      for (element in seed) {\n"
"        if (!(element is Num)) Fiber.abort(\"Sequence elements must all be numbers.\")\n"
"\n"
"        seeds.add(element)\n"
"        if (seeds.count == 16) break\n"
"      }\n"
"\n"
"      // Cycle the values to fill in any missing slots.\n"
"      var i = 0\n"
"      while (seeds.count < 16) {\n"
"        seeds.add(seeds[i])\n"
"        i = i + 1\n"
"      }\n"
"\n"
"      seed_(\n"
"          seeds[0], seeds[1], seeds[2], seeds[3],\n"
"          seeds[4], seeds[5], seeds[6], seeds[7],\n"
"          seeds[8], seeds[9], seeds[10], seeds[11],\n"
"          seeds[12], seeds[13], seeds[14], seeds[15])\n"
"    } else {\n"
"      Fiber.abort(\"Seed must be a number or a sequence of numbers.\")\n"
"    }\n"
"  }\n"
"\n"
"  foreign seed_()\n"
"  foreign seed_(seed)\n"
"  foreign seed_(n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11, n12, n13, n14, n15, n16)\n"
"\n"
"  foreign float()\n"
"  float(end) { float() * end }\n"
"  float(start, end) { float() * (end - start) + start }\n"
"\n"
"  foreign int()\n"
"  int(end) { (float() * end).floor }\n"
"  int(start, end) { (float() * (end - start)).floor + start }\n"
"\n"
"  sample(list) {\n"
"    if (list.count == 0) Fiber.abort(\"Not enough elements to sample.\")\n"
"    return list[int(list.count)]\n"
"  }\n"
"  sample(list, count) {\n"
"    if (count > list.count) Fiber.abort(\"Not enough elements to sample.\")\n"
"\n"
"    var result = []\n"
"\n"
"    // The algorithm described in \"Programming pearls: a sample of brilliance\".\n"
"    // Use a hash map for sample sizes less than 1/4 of the population size and\n"
"    // an array of booleans for larger samples. This simple heuristic improves\n"
"    // performance for large sample sizes as well as reduces memory usage.\n"
"    if (count * 4 < list.count) {\n"
"      var picked = {}\n"
"      for (i in list.count - count...list.count) {\n"
"        var index = int(i + 1)\n"
"        if (picked.containsKey(index)) index = i\n"
"        picked[index] = true\n"
"        result.add(list[index])\n"
"      }\n"
"    } else {\n"
"      var picked = List.filled(list.count, false)\n"
"      for (i in list.count - count...list.count) {\n"
"        var index = int(i + 1)\n"
"        if (picked[index]) index = i\n"
"        picked[index] = true\n"
"        result.add(list[index])\n"
"      }\n"
"    }\n"
"\n"
"    return result\n"
"  }\n"
"\n"
"  shuffle(list) {\n"
"    if (list.isEmpty) return\n"
"\n"
"    // Fisher-Yates shuffle.\n"
"    for (i in 0...list.count - 1) {\n"
"      var from = int(i, list.count)\n"
"      var temp = list[from]\n"
"      list[from] = list[i]\n"
"      list[i] = temp\n"
"    }\n"
"  }\n"
"}\n";
// End file "wren_opt_random.wren.inc"

// Implements the well equidistributed long-period linear PRNG (WELL512a).
//
// https://en.wikipedia.org/wiki/Well_equidistributed_long-period_linear
typedef struct
{
  uint32_t state[16];
  uint32_t index;
} Well512;

// Code from: http://www.lomont.org/Math/Papers/2008/Lomont_PRNG_2008.pdf
static uint32_t advanceState(Well512* well)
{
  uint32_t a, b, c, d;
  a = well->state[well->index];
  c = well->state[(well->index + 13) & 15];
  b =  a ^ c ^ (a << 16) ^ (c << 15);
  c = well->state[(well->index + 9) & 15];
  c ^= (c >> 11);
  a = well->state[well->index] = b ^ c;
  d = a ^ ((a << 5) & 0xda442d24U);

  well->index = (well->index + 15) & 15;
  a = well->state[well->index];
  well->state[well->index] = a ^ b ^ d ^ (a << 2) ^ (b << 18) ^ (c << 28);
  return well->state[well->index];
}

static void randomAllocate(WrenVM* vm)
{
  Well512* well = (Well512*)wrenSetSlotNewForeign(vm, 0, 0, sizeof(Well512));
  well->index = 0;
}

static void randomSeed0(WrenVM* vm)
{
  Well512* well = (Well512*)wrenGetSlotForeign(vm, 0);

  srand((uint32_t)time(NULL));
  for (int i = 0; i < 16; i++)
  {
    well->state[i] = rand();
  }
}

static void randomSeed1(WrenVM* vm)
{
  Well512* well = (Well512*)wrenGetSlotForeign(vm, 0);

  srand((uint32_t)wrenGetSlotDouble(vm, 1));
  for (int i = 0; i < 16; i++)
  {
    well->state[i] = rand();
  }
}

static void randomSeed16(WrenVM* vm)
{
  Well512* well = (Well512*)wrenGetSlotForeign(vm, 0);

  for (int i = 0; i < 16; i++)
  {
    well->state[i] = (uint32_t)wrenGetSlotDouble(vm, i + 1);
  }
}

static void randomFloat(WrenVM* vm)
{
  Well512* well = (Well512*)wrenGetSlotForeign(vm, 0);

  // A double has 53 bits of precision in its mantissa, and we'd like to take
  // full advantage of that, so we need 53 bits of random source data.

  // First, start with 32 random bits, shifted to the left 21 bits.
  double result = (double)advanceState(well) * (1 << 21);

  // Then add another 21 random bits.
  result += (double)(advanceState(well) & ((1 << 21) - 1));

  // Now we have a number from 0 - (2^53). Divide be the range to get a double
  // from 0 to 1.0 (half-inclusive).
  result /= 9007199254740992.0;

  wrenSetSlotDouble(vm, 0, result);
}

static void randomInt0(WrenVM* vm)
{
  Well512* well = (Well512*)wrenGetSlotForeign(vm, 0);

  wrenSetSlotDouble(vm, 0, (double)advanceState(well));
}

const char* wrenRandomSource()
{
  return randomModuleSource;
}

WrenForeignClassMethods wrenRandomBindForeignClass(WrenVM* vm,
                                                   const char* module,
                                                   const char* className)
{
  ASSERT(strcmp(className, "Random") == 0, "Should be in Random class.");
  WrenForeignClassMethods methods;
  methods.allocate = randomAllocate;
  methods.finalize = NULL;
  return methods;
}

WrenForeignMethodFn wrenRandomBindForeignMethod(WrenVM* vm,
                                                const char* className,
                                                bool isStatic,
                                                const char* signature)
{
  ASSERT(strcmp(className, "Random") == 0, "Should be in Random class.");
  
  if (strcmp(signature, "<allocate>") == 0) return randomAllocate;
  if (strcmp(signature, "seed_()") == 0) return randomSeed0;
  if (strcmp(signature, "seed_(_)") == 0) return randomSeed1;
  
  if (strcmp(signature, "seed_(_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_)") == 0)
  {
    return randomSeed16;
  }
  
  if (strcmp(signature, "float()") == 0) return randomFloat;
  if (strcmp(signature, "int()") == 0) return randomInt0;
  
  ASSERT(false, "Unknown method.");
  return NULL;
}

#endif
// End file "wren_opt_random.c"
// Begin file "wren_opt_meta.c"

#if WREN_OPT_META

#include <string.h>

// Begin file "wren_opt_meta.wren.inc"
// Generated automatically from src/optional/wren_opt_meta.wren. Do not edit.
static const char* metaModuleSource =
"class Meta {\n"
"  static getModuleVariables(module) {\n"
"    if (!(module is String)) Fiber.abort(\"Module name must be a string.\")\n"
"    var result = getModuleVariables_(module)\n"
"    if (result != null) return result\n"
"\n"
"    Fiber.abort(\"Could not find a module named '%(module)'.\")\n"
"  }\n"
"\n"
"  static eval(source) {\n"
"    if (!(source is String)) Fiber.abort(\"Source code must be a string.\")\n"
"\n"
"    var closure = compile_(source, false, false)\n"
"    // TODO: Include compile errors.\n"
"    if (closure == null) Fiber.abort(\"Could not compile source code.\")\n"
"\n"
"    closure.call()\n"
"  }\n"
"\n"
"  static compileExpression(source) {\n"
"    if (!(source is String)) Fiber.abort(\"Source code must be a string.\")\n"
"    return compile_(source, true, true)\n"
"  }\n"
"\n"
"  static compile(source) {\n"
"    if (!(source is String)) Fiber.abort(\"Source code must be a string.\")\n"
"    return compile_(source, false, true)\n"
"  }\n"
"\n"
"  foreign static compile_(source, isExpression, printErrors)\n"
"  foreign static getModuleVariables_(module)\n"
"}\n";
// End file "wren_opt_meta.wren.inc"

void metaCompile(WrenVM* vm)
{
  const char* source = wrenGetSlotString(vm, 1);
  bool isExpression = wrenGetSlotBool(vm, 2);
  bool printErrors = wrenGetSlotBool(vm, 3);

  // TODO: Allow passing in module?
  // Look up the module surrounding the callsite. This is brittle. The -2 walks
  // up the callstack assuming that the meta module has one level of
  // indirection before hitting the user's code. Any change to meta may require
  // this constant to be tweaked.
  ObjFiber* currentFiber = vm->fiber;
  ObjFn* fn = currentFiber->frames[currentFiber->numFrames - 2].closure->fn;
  ObjString* module = fn->module->name;

  ObjClosure* closure = wrenCompileSource(vm, module->value, source,
                                          isExpression, printErrors);
  
  // Return the result. We can't use the public API for this since we have a
  // bare ObjClosure*.
  if (closure == NULL)
  {
    vm->apiStack[0] = NULL_VAL;
  }
  else
  {
    vm->apiStack[0] = OBJ_VAL(closure);
  }
}

void metaGetModuleVariables(WrenVM* vm)
{
  wrenEnsureSlots(vm, 3);
  
  Value moduleValue = wrenMapGet(vm->modules, vm->apiStack[1]);
  if (IS_UNDEFINED(moduleValue))
  {
    vm->apiStack[0] = NULL_VAL;
    return;
  }
    
  ObjModule* module = AS_MODULE(moduleValue);
  ObjList* names = wrenNewList(vm, module->variableNames.count);
  vm->apiStack[0] = OBJ_VAL(names);

  // Initialize the elements to null in case a collection happens when we
  // allocate the strings below.
  for (int i = 0; i < names->elements.count; i++)
  {
    names->elements.data[i] = NULL_VAL;
  }
  
  for (int i = 0; i < names->elements.count; i++)
  {
    names->elements.data[i] = OBJ_VAL(module->variableNames.data[i]);
  }
}

const char* wrenMetaSource()
{
  return metaModuleSource;
}

WrenForeignMethodFn wrenMetaBindForeignMethod(WrenVM* vm,
                                              const char* className,
                                              bool isStatic,
                                              const char* signature)
{
  // There is only one foreign method in the meta module.
  ASSERT(strcmp(className, "Meta") == 0, "Should be in Meta class.");
  ASSERT(isStatic, "Should be static.");
  
  if (strcmp(signature, "compile_(_,_,_)") == 0)
  {
    return metaCompile;
  }
  
  if (strcmp(signature, "getModuleVariables_(_)") == 0)
  {
    return metaGetModuleVariables;
  }
  
  ASSERT(false, "Unknown method.");
  return NULL;
}

#endif
// End file "wren_opt_meta.c"
