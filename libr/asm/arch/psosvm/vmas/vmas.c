/*
 * Copyright (C) 2009-2011
 *       skurz0 <gmail.com>
 *
 * radare is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * radare is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with radare; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

// TODO: add radare related commands to stdout with -r (R printf..)

#include <r_types.h>
#include <ctype.h>
#if __UNIX__
#include <netinet/in.h>
#include <arpa/inet.h>
#elif __WINDOWS__
typedef unsigned short uint16_t;
#endif

#ifdef __HAIKU__
#include <stdint.h>
#endif

enum{
	P_NONE,
	P_U8,
	P_U16,
	P_LABEL,
	P_CODESEGMENT
};

typedef struct {
	int id;
	char* name;
	size_t ptype;
}InstructionDescription;

enum{
	I_NOP=0,
	I_THROW=1,
	I_CC=0x02,
	I_JMP=3,
	I_CALL=4,
	I_RET=5,
	I_RESERVED6=6,
	I_RESERVED7=7,
	I_PUSHCB=8,
	I_PUSHCW=9,
	I_DUP=0x0a,
	I_XCHG=0x0b,
	I_LVR=0x0c,
	I_LVP=0x0d,
	I_GLV=0x0e,
	I_SLV=0x0f,
	I_NOT=0x10,
	I_AND=0x11,
	I_OR=0x12,
	I_XOR=0x13,
	I_MASK8=0x14,
	I_TST=0x15,
	I_RESERVED16=0x16,
	I_RESERVED17=0x17,
	I_LC=0x18,
	I_EQ=0x19,
	I_GT=0x1a,
	I_GTE=0x1b,
	I_LT=0x1c,
	I_LTE=0x1d,
	I_LNOT=0x1e,
	I_LAND=0x1f,
	I_SHL=0x20,
	I_CSHL=0x21,
	I_SHL1=0x22,
	I_SHL8=0x23,
	I_SHR=0x24,
	I_CSHR=0x25,
	I_SHR1=0x26,
	I_SHR8=0x27,
	I_ADD=0x28,
	I_SUB=0x29,
	I_INC=0x2a,
	I_DEC=0x2b,
	I_MUL=0x2c,
	I_DIV=0x2d,
	I_MOD=0x2e,
	I_RESERVED2F=0x2f,
	I_RDB=0x30,
	I_RDW=0x31,
	I_STB=0x32,
	I_STW=0x33,
	I_CPY=0x34,
	I_CMP=0x35,
	I_SET=0x36,
	I_ZERO=0x37,
	I_SB=0x38
};

static const InstructionDescription ins_db[]=
{
	{
		.id=I_NOP,
		.name="NOP",
		.ptype=P_NONE
	},
	{
		.id=I_THROW,
		.name="THROW",
		.ptype=P_U16
	},
	{
		.id=I_CC,
		.name="CC",
		.ptype=P_NONE
	},
	{
		.id=I_JMP,
		.name="JMP",
		.ptype=P_LABEL
	},
	{
		.id=I_CALL,
		.name="CALL",
		.ptype=P_CODESEGMENT
	},
	{
		.id=I_RET,
		.name="RET",
		.ptype=P_NONE
	},
	{
		.id=I_PUSHCB,
		.name="PUSHCB",
		.ptype=P_U8
	},
	{
		.id=I_PUSHCW,
		.name="PUSHCW",
		.ptype=P_U16
	},
	{
		.id=I_DUP,
		.name="DUP",
		.ptype=P_NONE
	},
	{
		.id=I_XCHG,
		.name="XCHG",
		.ptype=P_NONE
	},
	{
		.id=I_LVR,
		.name="LVR",
		.ptype=P_U8
	},
	{
		.id=I_LVP,
		.name="LVP",
		.ptype=P_U8
	},
	{
		.id=I_GLV,
		.name="GLV",
		.ptype=P_U8
	},
	{
		.id=I_SLV,
		.name="SLV",
		.ptype=P_U8
	},
	{
		.id=I_NOT,
		.name="NOT",
		.ptype=P_NONE
	},
	{
		.id=I_AND,
		.name="AND",
		.ptype=P_NONE
	},
	{
		.id=I_OR,
		.name="OR",
		.ptype=P_NONE
	},
	{
		.id=I_XOR,
		.name="XOR",
		.ptype=P_NONE
	},
	{
		.id=I_MASK8,
		.name="MASK8",
		.ptype=P_NONE
	},
	{
		.id=I_TST,
		.name="TST",
		.ptype=P_NONE
	},
	{
		.id=I_LC,
		.name="LC",
		.ptype=P_NONE
	},
	{
		.id=I_EQ,
		.name="EQ",
		.ptype=P_NONE
	},
	{
		.id=I_GT,
		.name="GT",
		.ptype=P_NONE
	},
	{
		.id=I_GTE,
		.name="GTE",
		.ptype=P_NONE
	},
	{
		.id=I_LT,
		.name="LT",
		.ptype=P_NONE
	},
	{
		.id=I_LTE,
		.name="LTE",
		.ptype=P_NONE
	},
	{
		.id=I_LNOT,
		.name="LNOT",
		.ptype=P_NONE
	},
	{
		.id=I_LAND,
		.name="LAND",
		.ptype=P_NONE
	},
	{
		.id=I_SHL,
		.name="SHL",
		.ptype=P_NONE
	},
	{
		.id=I_CSHL,
		.name="CSHL",
		.ptype=P_NONE
	},
	{
		.id=I_SHL1,
		.name="SHL1",
		.ptype=P_NONE
	},
	{
		.id=I_SHL8,
		.name="SHL8",
		.ptype=P_NONE
	},
	{
		.id=I_SHR,
		.name="SHR",
		.ptype=P_NONE
	},
	{
		.id=I_CSHR,
		.name="CSHR",
		.ptype=P_NONE
	},
	{
		.id=I_SHR1,
		.name="SHR1",
		.ptype=P_NONE
	},
	{
		.id=I_SHR8,
		.name="SHR8",
		.ptype=P_NONE
	},
	{
		.id=I_ADD,
		.name="ADD",
		.ptype=P_NONE
	},
	{
		.id=I_SUB,
		.name="SUB",
		.ptype=P_NONE
	},
	{
		.id=I_INC,
		.name="INC",
		.ptype=P_NONE
	},
	{
		.id=I_DEC,
		.name="DEC",
		.ptype=P_NONE
	},
	{
		.id=I_MUL,
		.name="MUL",
		.ptype=P_NONE
	},
	{
		.id=I_DIV,
		.name="DIV",
		.ptype=P_NONE
	},
	{
		.id=I_MOD,
		.name="MOD",
		.ptype=P_NONE
	},
	{
		.id=I_RDB,
		.name="RDB",
		.ptype=P_NONE
	},
	{
		.id=I_RDW,
		.name="RDW",
		.ptype=P_NONE
	},
	{
		.id=I_STB,
		.name="STB",
		.ptype=P_NONE
	},
	{
		.id=I_STW,
		.name="STW",
		.ptype=P_NONE
	},
	{
		.id=I_CPY,
		.name="CPY",
		.ptype=P_NONE
	},
	{
		.id=I_CMP,
		.name="CMP",
		.ptype=P_NONE
	},
	{
		.id=I_SET,
		.name="SET",
		.ptype=P_NONE
	},
	{
		.id=I_ZERO,
		.name="ZERO",
		.ptype=P_NONE
	},
	{
		.id=I_SB,
		.name="SB",
		.ptype=P_NONE
	}
};
#define INSDB_SIZE (sizeof(ins_db)/sizeof(InstructionDescription))

static ut16 r_ntohs (ut16 foo) {
/* XXX BIGENDIAN NOT DEFINED HERE !!!1 */
#if BIGENDIAN
        /* do nothing */
#else
        ut8 *p = (ut8 *)&foo;
        foo = p[1] | p[0]<<8;
#endif
        return foo;
}


/**
 * @return length of the opcode
 */
int psosvm_disasm(const ut8 *bytes, char *output)
{
	int ret=-1;
	int i;
	output[0]=0;
	for(i = 0; (i < INSDB_SIZE) && (ins_db[i].id!=(bytes[0]&0x7f));i++);
	if(i!=INSDB_SIZE){
		switch(ins_db[i].ptype){
			case P_NONE:
				sprintf(output,"%s%s",((bytes[0]&0x80)!=0)?"C_":"",ins_db[i].name);
				ret=1;
				break;
			case P_U8:
				sprintf(output,"%s%s %d",((bytes[0]&0x80)!=0)?"C_":"",ins_db[i].name,bytes[1]);
				ret=2;
				break;
			case P_U16:
			case P_CODESEGMENT:
			case P_LABEL:
				sprintf(output,"%s%s %d",((bytes[0]&0x80)!=0)?"C_":"",ins_db[i].name,
					r_ntohs(*(uint16_t*)(bytes+1)));
				ret=3;
				break;
			default:
				abort();
		}
	}
	return ret;
}

static int getInt(char* s, unsigned *number)
{
	*number=0;
	if(s[0]=='0'){
		if(s[1]=='x'||s[1]=='X'){
			//hexadecimal
			s+=2;
			while(*s!=(char)0){
				if(isxdigit((int)*s)==0)
					return -1;
				*number*=16;
				*number+=*s-((isdigit((unsigned char)*s)!=0)?'0':((isupper((unsigned char)*s)!=0)?'A'-10:'a'-10));
				s++;
			}
		}else{
			//octal
			while(*s!=(char)0){
				if((isdigit((int)*s)==0)||(*s>'7'))
					return -1;
				*number*=8;
				*number+=(int)(*s-'0');
				s++;
			}
		}
	}else{
		//decimal
		while(*s!=(char)0){
			if(isdigit((int)*s)==0)
				return -1;
			*number*=10;
			*number+=(int)(*s-'0');
			s++;
		}
	}
	return 0;
}

int psosvm_assemble(unsigned char *bytes, const char *string)
{
	int ret=0;
	int i;
	char name[128];
	char parameter[128];
	unsigned p;

	sscanf(string, "%s %s", name, parameter);
	for(i = 0;(i<INSDB_SIZE)&&(strcmp(ins_db[i].name, name)!=0);i++);
	if(i!=INSDB_SIZE){
		bytes[0] = ins_db[i].id;
		switch(ins_db[i].ptype) {
			case P_NONE:
				ret=1;
				break;
			case P_U8:
				if(getInt(parameter,&p)!=0)
					return 0;
				bytes[1]=p&0xff;
				ret=2;
				break;
			case P_U16:
			case P_LABEL:
			case P_CODESEGMENT:
				if(getInt(parameter,&p)!=0)
					return 0;
				*(uint16_t*)(bytes+1)=r_ntohs(p);
				ret=3;
				break;
		}
	}
	return ret;
}

int psosvmasm_init()
{
	/* INIT PSOSVM DISASSEMBLER */
	return 0;
}
