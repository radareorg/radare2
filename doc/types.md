Types profiles
==============
Type matching algorithms needs help of compiled types profiles to work properly, types profiles are important because they hold information about both data types and functions for imported libraries.
 At time of writing this doc, tcc doesn't parse C files into sdb format correctly, so one will have to do all the parsing manually.
 What will be described in this document is how to create sdbs for types profiles, where to place them, and lastly naming conventions for integrating them with r2 source.

## Available Constructs

At the current time the following C constructs are supported:

- primitive types
- Structs
- Unions
- functions prototypes

### Primitive types

Defining primitive types requires understanding of basic pf formats, you can find the whole list of format specifier in `pf??`:
```
-----------------------------------------------------------------
|  format specifier  | explanation                              |
|---------------------------------------------------------------|
|         b          |  byte (unsigned)                         |
|         c          |  char (signed byte)                      |
|         d          |  0x%%08x hexadecimal value (4 bytes)     |
|         f          |  float value (4 bytes)                   |
|         F          |  double value (8 bytes)                  |
|         i          |  %%i integer value (4 bytes)             |
|         o          |  0x%%08o octal value (4 byte)            |
|         p          |  pointer reference (2, 4 or 8 bytes)     |
|         q          |  quadword (8 bytes)                      |
|         s          |  32bit pointer to string (4 bytes)       |
|         S          |  64bit pointer to string (8 bytes)       |
|         t          |  UNIX timestamp (4 bytes)                |
|         T          |  show Ten first bytes of buffer          |
|         u          |  uleb128 (variable length)               |
|         w          |  word (2 bytes unsigned short in hex)    |
|         x          |  0x%%08x hex value and flag (fd @ addr)  |
|         X          |  show formatted hexpairs                 |
|         z          |  \0 terminated string                    |
|         Z          |  \0 terminated wide string               |
-----------------------------------------------------------------
```
there are basically 3 mandatory keys for defining Primitive data types:
`X=type`
`type.X=format_specifier`
`type.X.size=size_in_bits`
For example, lets define `UNIT`, according to [Microsoft documentation](https://msdn.microsoft.com/en-us/library/windows/desktop/aa383751(v=vs.85).aspx#UINT) `UINT` is just equivalent of standard C `unsigned int` It will be defined as:
```
UINT=type
type.UINT=d
type.UINT.size=32
```
Now Their is forth entry that is optional:

`X.type.pointto=Y`

This one may only be used in case of pointer `type.X=p`, one good example is LPFILETIME definition, it is pointer to `_FILETIME` which happens to be a struct. Assuming that we are targeting only 32bit windows machine, it will be defined as the following:

```
LPFILETIME=type
type.LPFILETIME=p
type.LPFILETIME.size=32
type.LPFILETIME.pointto=_FILETIME
```
that last field is not mandatory because some times the data structure internals will be property, and we will not have a clean representation for it.

### Structures

Those are the basic keys for structs (with just two elements):

```
X=struct
struct.X=a,b
struct.X.a=a_type,a_offset,a_number_of_elements
struct.X.b=b_type,b_offset,b_number_of_elements
```
The first line is used to define a structure called `X`, second line defines the elements of `X` as comma separated values. After that we just define each element info.

for example we can have struct like this one:
```
struct _FILETIME {
	DWORD dwLowDateTime;
	DWORD dwHighDateTime;
}
```
assuming we have `DWORD` defined, the struct will look like this
```
 _FILETIME=struct
struct._FILETIME=dwLowDateTime,dwHighDateTime
struct._FILETIME.dwLowDateTime=DWORD,0,0
struct._FILETIME.dwHighDateTime=DWORD,4,0
```
Note that the number of elements filed is used in case of arrays only to identify how many elements are in arrays, other than that it is zero by default.

### Unions

Unions are defined exactly like structs the only difference is that you will replace the word `struct` with the word `union`.

### Function prototypes

Function prototypes representation is the most detail oriented and the most important one one of them all. Actually this is the one used directly for type matching

```
X=func
func.X.args=NumberOfArgs
func.x.arg0=Arg_type,arg_name
.
.
.
func.X.ret=Return_type
func.X.cc=calling_convention
```
It should be self explanatory lets do strncasecmp as an example for x86 arch for linux machines According to man pages, strncasecmp is defined as the following:
```
int strcasecmp(const char *s1, const char *s2);
```

when converting it into its sdb representation it will looks like the following:
```
strcasecmp=func
func.strcasecmp.args=3
func.strcasecmp.arg0=char *,s1
func.strcasecmp.arg1=char *,s2
func.strcasecmp.arg2=size_t,n
func.strcasecmp.ret=int
func.strcasecmp.cc=cdecl
```

Note that the `.cc` part is optional and if it didn't exist the default calling convention for your target architecture will be used instead.
Their is one extra optional key

```
func.x.noreturn=true/false
```
This key is used to mark functions that will not return once called like `exit` and `_exit`.
## Integrating with r2 source

in order to add definitions to r2 source there is very flexible naming convention. First the file should be located in `path/to/r2/libr/anal/d`. Then you should add an entry for it in `Makefile` that exist at the same directory. Make sure that the name follow this convention:
```
types[-arch][-OS][-bits]
```
All parts in square brackets are optional, but order is important, they are there to help you to create fine granularity type profiles. One extra note, It is not a must that all keys/value pairs for the one data types exist in the same file for example general windows datatypes exists in `types-windows` while only size of pointers are in `types-x86-windows-32` and `types-x86-windows-64`.
