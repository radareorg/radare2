# Examples of Macros

Macros are defined and executed with the parenthesis command, you may want to quote them using the `'` character at the begining of the line, because the `;` character is used to separate the statements inside them

* Hello, world

```
'(hello;?e Hello World)
.(hello)
```

* Looping inside a macro

```
'(loop_macro;f cnt=3;loop:;?e hello `?vi cnt`;f cnt=`?vi cnt-1`;?= cnt;?!();.loop:)
.(loop_macro)
```

## Backtrace implementation for x86-64:

```
'(backtrace;
aa
f prev @ rsp
f base@ rbp
loop:
f next @ `pq 1 @base~[1]`,
f cont @ `pq 1 @base+8~[1]`,
?= next
??()
?= next-0xffffffffffffffff
??()
?= cont-0xffffffffffffffff
??()
?e StackFrame at `?v next` with size `?vi base-prev`
x base-prev@base+16
?e Code: `?v cont`
pdf @ cont
f prev@base
f base@next
.loop:
)
.(backtrace)
```
