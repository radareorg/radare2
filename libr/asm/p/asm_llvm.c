/* radare2 - LGPL3 - Copyright 2020 - Philoinovsky */
/* code not finished yet, Makefile didn't update */
/*Reference: https://llvm.org/docs/BitCodeFormat.html*/
#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

//-- Primitive Reads ------------------------------------------------
//Decode a 6-bit encoded character.
static ut8 getbool(ut8 **bp){
    ut8 lo = r_read_at_le8(*bp);
    *bp += 1;
    return lo & 0x01;
}

static ut8 char6(ut8 **bp){
    ut8 lo = r_read_at_le8(*bp);
    *bp += 6;
    if(0  <= lo & lo <= 25) return (lo + 97);
    if(26 <= lo & lo <= 51) return (lo + 39);
    if(52 <= lo & lo <= 61) return (lo - 4);
    if(lo == 62) return '.';
    if(lo == 63) return '_';
    return 0; //"invalid"
}

static int getn1hex(ut8 n){//gets 00111111(n's of 1) in binary
    int res = 0;
    while(n){
        res = res | 1 << n;
        n -= 1;
    }
    return res;
}

//Get a @BitString@ formatted as vbr
static int vbr(ut8 **bp, ut8 n){
    ut8 len = n - 1;
    int res = 0;
    ut8 lsl = 0;
    ut8 cont = 1;
    int chunk = 0;
    while(cont){
        chunk = r_read_at_le32(*bp) & getn1hex(n-1);
        *b += n - 1;
        res = res + chunk << lsl;
        lsl += n - 1;
        cont = chunk & 1 << (n - 1);
    }
    return res;
}

//Get a fixed width value
static int fwv(ut8 **bp, ut8 n){
    int res = r_read_at_le32(*bp) & getn1hex(n);
    *bp += n;
    return res;
}

//-- Bitstream Parsing ---------------------------------------------
const ut32 bcWrapperMagicConst = 0x0B17C0DE;
static void getBitCodeBitstream(ut8 *b){
    ut32 word32 = r_read_at_le32(b);
    if(word32 == bcWrapperMagicConst){
        getBitstream(b+5*8);
    }else{
        getBitstream(b);
    }
    return; //not done!
}

const ut32 bcMagicConst = 0x4342C0DE;
static ut8* getBitstream(ut8 *b){
    ut32 word32 = r_read_at_le32(b);
    if(word32 != bcMagicConst){
        eprintf("invalid bitcode magic number");
    }else{
        //entries = getTopLevelEntries
    }
}

typedef struct _Entry{//not defined
    BcBlock EntryBlock;
    UnabbrevRecord EntryUnabbrevRecord;
    DefineAbbrev EntryDefineAbbrev;
    AbbrevRecord EntryAbbrevRecord;
}Entry;

//getTopLevelEntries
//not done!

//-- Unabbreviated Records ----------------------------------
//not done!
typedef struct _UnabbrevRecord{
    int unabbrevCode;
    char* unabbrevOps;
}UnabbrevRecord;

//-- Abbreviation IDs -------------------------------------
typedef struct _AbbrevRecord{
    int AbbrevIdWidth;
    int RecordId;
    AbbrevOp AbbrevOperad;
}AbbrevRecord;

enum AbbrevId{
    END_BLOCK = 0,
    ENTER_SUBBLOCK = 1,
    DEFINE_ABBREV = 2,
    UNABBREV_RECORD = 3,
};

//-- Abbreviation Definitions ------------------------------------
typedef struct _DefineAbbrev{
    AbbrevOp* defineOps;
}DefineAbbrev;

//-- | Parse an abbreviation definition.
//getDefineAbbrev :: GetBits DefineAbbrev
//getDefineAbbrev  =
//label "define abbrev" (DefineAbbrev `fmap` (getAbbrevOps =<< vbrNum 5))

enum AbbrevOpType{
    OpLiteral = 0,
    OpFixed = 1,
    OpVBR = 2
    OpArray = 3,
    OpChar6 = 4,
    OpBlob = 5,
};

typedef struct _AbbrevOp{
    enum AbbrevOpType OpType;
    int OpValue;
    ut8* OpBlob;
}AbbrevOp;

//-- | Parse n abbreviation operands.
static AbbrevOp* getAbbrevOps(ut8 **bp, ut8 n){
    ut8* num = n;
    if(!n){
        return NULL;
    }else{
        AbbrevOp* op = getAbbrevOp(bp,n);
        AbbrevOp* rest = getAbbrevOps(ut8 **bp, ut8 n - 1);
        AbbrevOp* all; //Not Done: merge op and rest in memory
        return all;
    }
}

//-- | Parse an abbreviation operand.
static AbbrevOp* getAbbrevOp(ut8 **bp, ut8 n){
    ut8 isLiteral = getbool(bp);
    enum AbbrevOpType OpType;
    int OpValue;
    ut8* OpBlob = NULL;
    if(isLiteral){
        OpType = OpLiteral;
        OpValue = vbr(bp,8);
    }else{
        ut8 enc = r_read_at_le8(*bp) && 0x07;
        *bp += 3;
        switch (enc){
        case 1: //fixed width value
            OpType = OpFixed;
            ut8 wid = vbr(bp,5); //extra data
            OpValue = fwv(bp,wid);
            break;
        case 2: //variable width value
            OpType = OpVBR;
            ut8 wid = vbr(bp,5); //extra data
            OpValue = vbr(bp,wid);
            break;
        case 3: //array of values
            OpType = OpArray;
            OpValue = vbr(bp,6);
            break;
        case 4: //char6 encoded value
            OpType = OpChar6;
            OpValue = char6(bp);
            break;
        case 5: //blob
            OpType = OpBlob,
            OpValue = vbr(bp,6);//lenth of OpBlob
            align(bp,32);
            OpBlob = *bp;
            *bp += OpValue;
            align(bp,32);
            break;
        default:
            break; //fail with encoding value $enc
        }
    }
    AbbrevOp abop;
    abop.OpType = OpType;
    abop.OpValue = OpValue;
    abop.OpBlob = OpBlob;
    return &abop;
}

//-- Metadata Stypedef tring Lengths ---------------------------------
//not done!

//-- Blocks -------------------------------------------------
typedef struct _bcBlock{
    ut32 blockid;
    //AbbrevIdWidth blockNewAbbrevLen;
    ut32 blockLength;
    Entry *blockEntries;
}BcBlock;

//-- | Parse a block, optionally extending the known block info metadata.
//getBlock

//-- | A generic block.
static void getGenericBlock(ut8** bp){
    int blockid = vbr(bp,8);
    int newabbrevlen = vbr(bp,4);
    align(bp,32);
    int blocklen = vbr(bp,32);
    //am = lookupAbbrevMap blockid bim
    //(entries,bim') <- isolate blocklen (getEntries newabbrevlen bim am False)
    BcBlock blok;
    blok.blockid           = blockid;
    blok.blockNewAbbrevLen = newabbrevlen;
    blok.blockLength       = blocklen;
    blok.blockEntries      = entries;
    //return (block,bim')
}

//align *bp to multiples of n
static void align(ut8 **bp, ut8 n){
    ut8 diff = *bp % n;
    *bp += n - diff;
    return;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
    if (len < 2){
        eprintf("No instructions provided");
        return -1;
    }
    //return op->size
    return -1;
}

RAsmPlugin r_asm_plugin_mycpu = {
    .name = "llvm bitcode",
    .license = "LGPL3",
    .desc = "llvm disassembly plugin",
    .arch = "llvm bitcode",
    .author = 'Philoinovsky',
    .bits = 32,
    .endian = R_SYS_ENDIAN_LITTLE,
    .disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ASM,
    .data = &r_asm_plugin_mycpu,
    .version = R2_VERSION
};
#endif
