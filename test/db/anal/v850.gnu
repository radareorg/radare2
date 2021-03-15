NAME=v850.gnu proper imm32 handling
FILE=malloc://1024
CMDS=<<EOF
e asm.arch = v850.gnu
wx 210674060000210674061234
pi 2 @0
EOF
EXPECT=<<EOF
mov 0x674, r1
mov 0x34120674, r1
EOF
RUN
