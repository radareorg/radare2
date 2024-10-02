o malloc://128 0x3000
f input 128 0x3000
f fd.input=`oqq`

o malloc://80*25 0x4000
f fd.screen=`oqq`
f screen 80*25 0x4000

o malloc://0x200 0x5000
f fd.stack=`oqq`
f stack 0x200 0x5000

o malloc://0x1000 0x6000
f fd.data=`oqq`
f data 0x1000 0x6000

ar
ar brk=stack
ar scr=screen
ar kbd=input
ar ptr=data
"e cmd.vprompt=pxa 32@stack;pxa 32@screen;pxa 32@data"
s 0
e asm.bits=32
e cmd.vprompt=pxa 32@stack;pxa 32@screen;pxa 32@data
