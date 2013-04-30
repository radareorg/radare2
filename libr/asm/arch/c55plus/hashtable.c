#include "ins.h"
#include "hashvector.h"
#include <r_types.h>

st32 loc_408000 = 0x2474f685;
st32 loc_408600 = 0x42fbc0b8;
st32 loc_402000 = 0x086a18eb;
st32 loc_418181 = 0x001d02e8;
st32 dword_480000 = 0;

extern ut8* ins_buff;
extern ut32 ins_buff_len;
extern HASHCODE_ENTRY_T ins_hash[];

extern st32 debug;

//----- (004060F0) --------------------------------------------------------
st32 sub_4060F0(st32 a1, st32 a2)
{
  return a1;
}

//----- (00406100) --------------------------------------------------------
st32 sub_406100(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  char v4; // zf@122

  v2 = a2 & 0xFE000000;
  if ( (a2 & 0xFE000000u) > 0x72000000 )
  {
    if ( (ut32)v2 <= 0xD8000000 )
    {
      if ( v2 != -671088640 )
      {
        if ( (ut32)v2 > 0xC4000000 )
        {
          if ( (ut32)v2 > 0xCE000000 )
          {
            if ( (ut32)v2 > 0xD4000000 )
            {
              if ( v2 == -704643072 )
                return 95;
              return a1;
            }
            if ( v2 != -738197504 && v2 != -805306368 )
            {
              if ( v2 == -771751936 )
                return 95;
              return a1;
            }
          }
          else
          {
            if ( v2 != -838860800 )
            {
              if ( (ut32)v2 > 0xCA000000 )
              {
                if ( v2 == -872415232 )
                  return 95;
                return a1;
              }
              if ( v2 != -905969664 && v2 != -973078528 )
              {
                if ( v2 == -939524096 )
                  return 95;
                return a1;
              }
            }
          }
        }
        else
        {
          if ( v2 != -1006632960 )
          {
            if ( (ut32)v2 <= 0x7E000000 )
            {
              if ( v2 != 2113929216 )
              {
                if ( (ut32)v2 > 0x78000000 )
                {
                  if ( v2 != 2046820352 && v2 != 2080374784 )
                    return a1;
                }
                else
                {
                  if ( v2 != 2013265920 && v2 != 1946157056 )
                  {
                    if ( v2 == 1979711488 )
                      return 226;
                    return a1;
                  }
                }
              }
              return 226;
            }
            if ( (ut32)v2 > 0xC0000000 )
            {
              if ( v2 == -1040187392 )
                return 95;
              return a1;
            }
            if ( v2 != -1073741824 )
            {
              if ( v2 == -1610612736 )
                return 540;
              if ( v2 == -1577058304 )
                return 541;
              return a1;
            }
          }
        }
      }
      return 95;
    }
    if ( (ut32)v2 > 0xEC000000 )
    {
      if ( (ut32)v2 > 0xF6000000 )
      {
        if ( (ut32)v2 > 0xFC000000 )
        {
          if ( v2 != -33554432 )
            return a1;
          return 96;
        }
        if ( v2 == -67108864 || v2 == -134217728 )
          return 96;
        v4 = v2 == -100663296;
      }
      else
      {
        if ( v2 == -167772160 )
          return 96;
        if ( (ut32)v2 > 0xF2000000 )
        {
          v4 = v2 == -201326592;
        }
        else
        {
          if ( v2 == -234881024 || v2 == -301989888 )
            return 96;
          v4 = v2 == -268435456;
        }
      }
    }
    else
    {
      if ( v2 == -335544320 )
        return 96;
      if ( (ut32)v2 > 0xE2000000 )
      {
        if ( (ut32)v2 > 0xE8000000 )
        {
          v4 = v2 == -369098752;
        }
        else
        {
          if ( v2 == -402653184 || v2 == -469762048 )
            return 96;
          v4 = v2 == -436207616;
        }
      }
      else
      {
        if ( v2 == -503316480 )
          return 96;
        if ( (ut32)v2 <= 0xDE000000 )
        {
          if ( v2 != -570425344 && v2 != -637534208 && v2 != -603979776 )
            return a1;
          return 95;
        }
        v4 = v2 == -536870912;
      }
    }
    if ( !v4 )
      return a1;
    return 96;
  }
  if ( (a2 & 0xFE000000) == 1912602624 )
    return 226;
  if ( (ut32)v2 > 0x48000000 )
  {
    if ( (ut32)v2 <= 0x5E000000 )
    {
      if ( v2 != 1577058304 )
      {
        if ( (ut32)v2 > 0x54000000 )
        {
          if ( (ut32)v2 > 0x5A000000 )
          {
            if ( v2 != 1543503872 )
              return a1;
          }
          else
          {
            if ( v2 != 1509949440 && v2 != 1442840576 )
            {
              if ( v2 == 1476395008 )
                return 178;
              return a1;
            }
          }
        }
        else
        {
          if ( v2 != 1409286144 )
          {
            if ( (ut32)v2 > 0x4E000000 )
            {
              if ( v2 != 1342177280 )
              {
                if ( v2 == 1375731712 )
                  return 178;
                return a1;
              }
            }
            else
            {
              if ( v2 != 1308622848 && v2 != 1241513984 )
              {
                if ( v2 == 1275068416 )
                  return 178;
                return a1;
              }
            }
          }
        }
      }
      return 178;
    }
    if ( (ut32)v2 > 0x68000000 )
    {
      if ( (ut32)v2 > 0x6E000000 )
      {
        if ( v2 == 1879048192 )
          return 226;
        return a1;
      }
      if ( v2 != 1845493760 && v2 != 1778384896 )
      {
        if ( v2 == 1811939328 )
          return 226;
        return a1;
      }
    }
    else
    {
      if ( v2 != 1744830464 )
      {
        if ( (ut32)v2 > 0x64000000 )
        {
          if ( v2 == 1711276032 )
            return 226;
          return a1;
        }
        if ( v2 != 1677721600 && v2 != 1610612736 )
        {
          if ( v2 == 1644167168 )
            return 226;
          return a1;
        }
      }
    }
    return 226;
  }
  if ( v2 == 1207959552 )
    return 178;
  if ( (ut32)v2 <= 0x14000000 )
  {
    if ( v2 != 335544320 )
    {
      if ( (ut32)v2 > 0xA000000 )
      {
        if ( (ut32)v2 > 0x10000000 )
        {
          if ( v2 == 301989888 )
            return 142;
          return a1;
        }
        if ( v2 != 268435456 && v2 != 201326592 )
        {
          if ( v2 == 234881024 )
            return 142;
          return a1;
        }
      }
      else
      {
        if ( v2 != 167772160 )
        {
          if ( (ut32)v2 > 0x4000000 )
          {
            if ( v2 != 100663296 )
            {
              if ( v2 == 134217728 )
                return 142;
              return a1;
            }
          }
          else
          {
            if ( v2 != 67108864 && v2 )
            {
              if ( v2 == 33554432 )
                return 142;
              return a1;
            }
          }
        }
      }
    }
    return 142;
  }
  if ( (ut32)v2 > 0x1E000000 )
  {
    if ( (ut32)v2 > 0x44000000 )
    {
      if ( v2 == 1174405120 )
        return 178;
      return a1;
    }
    if ( v2 != 1140850688 && v2 != 1073741824 )
    {
      if ( v2 == 1107296256 )
        return 178;
      return a1;
    }
    return 178;
  }
  if ( v2 == 503316480 )
    return 142;
  if ( (ut32)v2 <= 0x1A000000 )
  {
    if ( v2 != 436207616 && v2 != 369098752 )
    {
      if ( v2 == 402653184 )
        return 142;
      return a1;
    }
    return 142;
  }
  if ( v2 == 469762048 )
    return 142;
  return a1;
}

//----- (004064F0) --------------------------------------------------------
st32 sub_4064F0(st32 a1, st32 a2)
{
  st32 v2; // eax@1

  v2 = a2 & 0xE0000000;
  if ( (a2 & 0xE0000000u) <= 0x80000000 )
  {
    if ( (a2 & 0xE0000000) == -2147483648 )
      return 102;
    if ( !v2 )
      return 485;
    if ( v2 == 536870912 )
      return 486;
    return a1;
  }
  if ( v2 != -1610612736 )
    return a1;
  return 475;
}

//----- (00406540) --------------------------------------------------------
st32 sub_406540(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x80000000 )
  {
    if ( (a2 & 0x80000000) == -2147483648 )
      result = 99;
    else
      result = a1;
  }
  else
  {
    result = 100;
  }
  return result;
}

//----- (00406570) --------------------------------------------------------
st32 sub_406570(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x80000000 )
  {
    if ( (a2 & 0x80000000) == -2147483648 )
      result = 97;
    else
      result = a1;
  }
  else
  {
    result = 98;
  }
  return result;
}

//----- (004065A0) --------------------------------------------------------
st32 sub_4065A0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x80000000 )
  {
    if ( (st32)(a2 & 0x80000000) == -2147483648 )
      result = 228;
    else
      result = a1;
  }
  else
  {
    result = 227;
  }
  return result;
}

//----- (004065D0) --------------------------------------------------------
st32 sub_4065D0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x80000000 )
  {
    if ( (a2 & 0x80000000) == -2147483648 )
      result = 52;
    else
      result = a1;
  }
  else
  {
    result = 140;
  }
  return result;
}

//----- (00406600) --------------------------------------------------------
st32 sub_406600(st32 a1, st32 a2)
{
  st32 tmp; // eax@1

  tmp = a2 & 0xC0000000;
  if ( (a2 & 0xC0000000u) <= 0x80000000 )
  {
    if ( (a2 & 0xC0000000) == -2147483648 )
      return 87;
    if ( !tmp )
      return 85;
    if ( tmp == 1073741824 )
      return 86;
    return a1;
  }
  if ( tmp != -1073741824 )
    return a1;
  return 88;
}

//----- (00406650) --------------------------------------------------------
st32 sub_406650(st32 a1, st32 a2)
{
  st32 v2; // eax@1

  v2 = a2 & 0xC0000000;
  if ( (a2 & 0xC0000000u) <= 0x80000000 )
  {
    if ( (a2 & 0xC0000000) == -2147483648 )
      return 91;
    if ( !v2 )
      return 89;
    if ( v2 == 1073741824 )
      return 90;
    return a1;
  }
  if ( v2 != -1073741824 )
    return a1;
  return 92;
}

//----- (004066A0) --------------------------------------------------------
st32 sub_4066A0(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1

  v2 = a2;
  v3 = v2 & 0x500000;
  if ( (ut32)v3 <= 0x400000 )
  {
    if ( v3 == 4194304 )
      return 247;
    if ( !v3 )
      return 245;
    if ( v3 == 1048576 )
      return 249;
    return a1;
  }
  if ( v3 != 5242880 )
    return a1;
  return 248;
}

//----- (004066F0) --------------------------------------------------------
st32 sub_4066F0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  /* */

  if ( (ut32)dword_480000 & a2 )
  {
    if ( ((ut32)dword_480000 & a2) == 524288 )
      result = 460;
    else
      result = a1;
  }
  else
  {
    result = 244;
  }
  return result;
}
// 480000: using guessed type st32 dword_480000[4];

//----- (00406720) --------------------------------------------------------
st32 sub_406720(st32 a1, st32 a2)
{
  st32 tmp; // eax@1
  st32 v3; // eax@1
  st32 result; // eax@3

  tmp = a2;
  v3 = tmp & 0x400000;
  if ( v3 )
  {
    if ( v3 == 4194304 )
      result = 521;
    else
      result = a1;
  }
  else
  {
    result = 374;
  }
  return result;
}

//----- (00406750) --------------------------------------------------------
st32 sub_406750(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 30;
    else
      result = a1;
  }
  else
  {
    result = 32;
  }
  return result;
}

//----- (00406780) --------------------------------------------------------
st32 sub_406780(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 61;
    else
      result = a1;
  }
  else
  {
    result = 60;
  }
  return result;
}

//----- (004067B0) --------------------------------------------------------
st32 sub_4067B0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 63;
    else
      result = a1;
  }
  else
  {
    result = 62;
  }
  return result;
}

//----- (004067E0) --------------------------------------------------------
st32 sub_4067E0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 69;
    else
      result = a1;
  }
  else
  {
    result = 64;
  }
  return result;
}

//----- (00406810) --------------------------------------------------------
st32 sub_406810(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 68;
    else
      result = a1;
  }
  else
  {
    result = 67;
  }
  return result;
}

//----- (00406840) --------------------------------------------------------
st32 sub_406840(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 66;
    else
      result = a1;
  }
  else
  {
    result = 65;
  }
  return result;
}

//----- (00406870) --------------------------------------------------------
st32 sub_406870(st32 a1, st32 a2)
{
  st32 v2; // eax@1

  v2 = a2 & 0xC1000000;
  if ( (a2 & 0xC1000000u) > 0x40000000 )
  {
    if ( v2 != -2147483648 && v2 != -1073741824 )
      return a1;
  }
  else
  {
    if ( (a2 & 0xC1000000) != 1073741824 && v2 )
    {
      if ( v2 == 16777216 )
        return 469;
      return a1;
    }
  }
  return 59;
}

//----- (004068B0) --------------------------------------------------------
//AQUI 0x223, 0x61020000
st32 sub_4068B0(st32 a1, st32 a2)
{
  st32 v2; // eax@1

  v2 = a2 & 0x1400000;
  if ( (a2 & 0x1400000u) <= 0x1000000 )
  {
    if ( (a2 & 0x1400000) == 16777216 )
      return 75;
    if ( !v2 )
      return 74;
    if ( v2 == 4194304 )
      return 78;
    return a1;
  }
  if ( v2 != 20971520 )
    return a1;
  return 77;
}

//----- (00406900) --------------------------------------------------------
st32 sub_406900(st32 a1, st32 a2)
{
  st32 v2; // eax@1

  v2 = a2 & 0x1400000;
  if ( (a2 & 0x1400000u) <= 0x1000000 )
  {
    if ( (a2 & 0x1400000) == 16777216 )
      return 73;
    if ( !v2 )
      return 72;
    if ( v2 == 4194304 )
      return 108;
    return a1;
  }
  if ( v2 != 20971520 )
    return a1;
  return 109;
}

//----- (00406950) --------------------------------------------------------
st32 sub_406950(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x8200 )
  {
    if ( (unsigned short)(a2 & 0x8200) == 512 )
      result = 364;
    else
      result = a1;
  }
  else
  {
    result = 357;
  }
  return result;
}

//----- (00406980) --------------------------------------------------------
st32 sub_406980(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1

  v2 = a2;
  v3 = v2 & 0x41C000;
  if ( (ut32)v3 <= 0x400000 )
  {
    if ( v3 == 4194304 )
      return 323;
    if ( (ut32)v3 <= 0xC000 )
    {
      if ( v3 != 49152 )
      {
        if ( !v3 )
          return 324;
        if ( v3 == 16384 )
          return 370;
        if ( v3 == 32768 )
          return 325;
        return a1;
      }
      return 372;
    }
    if ( v3 != 65536 )
    {
      if ( v3 != 81920 )
      {
        if ( v3 == 114688 )
          return 371;
        return a1;
      }
      return 373;
    }
    return 314;
  }
  if ( (ut32)v3 <= 0x410000 )
  {
    if ( v3 != 4259840 )
    {
      if ( v3 == 4210688 )
        return 369;
    
      if ( (st32 (*)(char))v3 == (char *)loc_408000 )
        return 325;
      if ( v3 != 4243456 )
        return a1;
      return 372;
    }
    return 314;
  }
  if ( v3 != 4276224 )
  {
    if ( v3 == 4308992 )
      return 371;
    return a1;
  }
  return 373;
}
// 408000: using guessed type st32 loc_408000(char);

//----- (00406A30) --------------------------------------------------------
st32 sub_406A30(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1

  v2 = a2;
  v3 = v2 & 0x418000;
  if ( (ut32)v3 <= 0x400000 )
  {
    if ( v3 == 4194304 )
      return 330;
    if ( (ut32)v3 <= 0x10000 )
    {
      if ( v3 != 65536 )
      {
        if ( !v3 )
          return 329;
        if ( v3 == 32768 )
          return 307;
        return a1;
      }
      return 480;
    }
    if ( v3 == 98304 )
      return 467;
    return a1;
  }
  if ( (st32 (*)(char))v3 != (char *)loc_408000 )
  {
    if ( v3 == 4259840 )
      return 480;
    if ( v3 == 4292608 )
      return 467;
    return a1;
  }
  return 308;
}
// 408000: using guessed type st32 loc_408000(char);

//----- (00406AA0) --------------------------------------------------------
st32 sub_406AA0(st32 a1, st32 a2)
{
  ut32 v2; // eax@1

  v2 = (ut32)loc_408600 & a2;
  if ( ((ut32)loc_408600 & a2) <= 0x8000 )
  {
    if ( ((ut32)loc_408600 & a2) != 32768 )
    {
      if ( v2 <= 0x400 )
      {
        if ( v2 != 1024 && v2 )
        {
          if ( v2 == 512 )
            return 365;
          return a1;
        }
        return 365;
      }
      if ( v2 == 1536 )
        return 365;
      return a1;
    }
    return 382;
  }
  if ( v2 <= 0x8600 )
  {
    if ( v2 != 34304 && v2 != 33280 && v2 != 33792 )
      return a1;
    return 382;
  }
  if ( (st32 (*)(char))v2 != (char *)loc_408000 )
    return a1;
  return 380;
}
// 408000: using guessed type st32 loc_408000(char);
// 408600: using guessed type st32 loc_408600();

//----- (00406B10) --------------------------------------------------------
st32 sub_406B10(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1

  v2 = a2;
  v3 = v2 & 0x41C000;
  if ( (ut32)v3 <= 0x404000 )
  {
    if ( v3 == 4210688 || v3 == 16384 )
      return 310;
    if ( v3 != 49152 )
    {
      if ( v3 == 4194304 )
        return 312;
      return a1;
    }
    return 311;
  }
  if ( (st32 (*)(char))v3 != (st32 (*)(char))loc_408000 )
  {
    if ( v3 != 4243456 )
      return a1;
    return 311;
  }
  return 313;
}
// 408000: using guessed type st32 loc_408000(char);

//----- (00406B70) --------------------------------------------------------
st32 sub_406B70(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1
  st32 result; // eax@4

  v2 = a2;
  v3 = v2 & 0x18000;
  if ( v3 )
  {
    if ( v3 == 32768 )
    {
      result = 376;
    }
    else
    {
      if ( v3 == 65536 )
        result = 377;
      else
        result = a1;
    }
  }
  else
  {
    result = 375;
  }
  return result;
}

//----- (00406BA0) --------------------------------------------------------
st32 sub_406BA0(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1
  char v5; // zf@34

  v2 = a2;
  v3 = v2 & 0x1F800;
  if ( (ut32)v3 <= 0xA000 )
  {
    if ( v3 != 40960 )
    {
      if ( (ut32)v3 <= 0x3000 )
      {
        if ( v3 == 12288 )
          return 384;
        if ( (ut32)v3 <= 0x1800 )
        {
          if ( v3 != 6144 && v3 && v3 != 2048 )
          {
            if ( v3 == 4096 )
              return 384;
            return a1;
          }
          return 384;
        }
        if ( v3 == 8192 || v3 == 10240 )
          return 384;
        return a1;
      }
      if ( (ut32)v3 > 0x8800 )
      {
        if ( v3 != 36864 )
        {
          if ( v3 == 38912 )
            return 385;
          return a1;
        }
      }
      else
      {
        if ( v3 != 34816 )
        {
          if ( v3 != 14336 )
          {
            if ( v3 == 24576 )
              return 388;
            if ( v3 == 32768 )
              return 385;
            return a1;
          }
          return 384;
        }
      }
    }
    return 385;
  }
  if ( (ut32)v3 <= 0x11000 )
  {
    if ( v3 == 69632 )
      return 386;
    if ( (ut32)v3 <= 0xE000 )
    {
      if ( v3 == 57344 )
        return 387;
      if ( v3 != 43008 && v3 != 45056 && v3 != 47104 )
        return a1;
      return 385;
    }
    if ( v3 == 65536 )
      return 386;
    v5 = v3 == 67584;
LABEL_35:
    if ( !v5 )
      return a1;
    return 386;
  }
  if ( (ut32)v3 <= 0x13000 )
  {
    if ( v3 == 77824 || v3 == 71680 || v3 == 73728 )
      return 386;
    v5 = v3 == 75776;
    goto LABEL_35;
  }
  if ( v3 == 79872 )
    return 386;
  if ( v3 != 90112 )
    return a1;
  return 389;
}

//----- (00406CC0) --------------------------------------------------------
st32 sub_406CC0(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1

  v2 = a2;
  v3 = v2 & 0x40F800;
  if ( v3 <= (ut32)loc_402000 )
  {
    if ( (st32 (*)(int, int, int))v3 == (st32 (*)(int, int, int))loc_402000)
      return 305;
    if ( v3 == 40960 )
      return 306;
    if ( v3 == 57344 )
      return 391;
    return a1;
  }
  if ( v3 != 4218880 )
    return a1;
  return 390;
}
// 402000: using guessed type st32 loc_402000(int, int, int);

//----- (00406D10) --------------------------------------------------------
st32 sub_406D10(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1
  st32 result; // eax@4

  v2 = a2;
  v3 = v2 & 0x18000;
  if ( v3 )
  {
    if ( v3 == 32768 )
    {
      result = 303;
    }
    else
    {
      if ( v3 == 65536 )
        result = 304;
      else
        result = a1;
    }
  }
  else
  {
    result = 302;
  }
  return result;
}

//----- (00406D40) --------------------------------------------------------
st32 sub_406D40(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1
  st32 result; // eax@7

  v2 = a2;
  v3 = v2 & 0x380000;
  if ( (ut32)v3 <= 0x200000 )
  {
    if ( v3 == 2097152 )
      return 271;
    if ( (ut32)v3 > 0x100000 )
    {
      if ( v3 == 1572864 )
        return 534;
    }
    else
    {
      if ( v3 == 1048576 )
        return 317;
      if ( !v3 )
        return 319;
      if ( v3 == 524288 )
        return 533;
    }
    return a1;
  }
  if ( v3 == 2621440 )
  {
    result = 535;
  }
  else
  {
    if ( v3 == 3145728 )
    {
      result = 321;
    }
    else
    {
      if ( v3 != 3670016 )
        return a1;
      result = 536;
    }
  }
  return result;
}

//----- (00406DC0) --------------------------------------------------------
st32 sub_406DC0(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1
  st32 result; // eax@4

  v2 = a2;
  v3 = v2 & 0x18000;
  if ( v3 )
  {
    if ( v3 == 32768 )
    {
      result = 258;
    }
    else
    {
      if ( v3 == 65536 )
        result = 259;
      else
        result = a1;
    }
  }
  else
  {
    result = 261;
  }
  return result;
}

//----- (00406DF0) --------------------------------------------------------
st32 sub_406DF0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x8000 )
  {
    if ( (unsigned short)(a2 & 0x8000) == 32768 )
      result = 327;
    else
      result = a1;
  }
  else
  {
    result = 326;
  }
  return result;
}

//----- (00406E20) --------------------------------------------------------
st32 sub_406E20(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1
  st32 result; // eax@6

  v2 = a2;
  v3 = v2 & 0x580000;
  if ( (ut32)v3 <= 0x180000 )
  {
    if ( v3 == 1572864 )
      return 471;
    if ( !v3 )
      return 392;
    if ( v3 == 524288 )
      return 470;
    if ( v3 == 1048576 )
      return 393;
    return a1;
  }
  if ( v3 == 4194304 )
  {
    result = 394;
  }
  else
  {
    if ( v3 != 5242880 )
      return a1;
    result = 395;
  }
  return result;
}

//----- (00406E80) --------------------------------------------------------
st32 sub_406E80(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 189;
    else
      result = a1;
  }
  else
  {
    result = 186;
  }
  return result;
}

//----- (00406EB0) --------------------------------------------------------
st32 sub_406EB0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1C00000 )
  {
    if ( (a2 & 0x1C00000) == 16777216 )
      result = 188;
    else
      result = a1;
  }
  else
  {
    result = 187;
  }
  return result;
}

//----- (00406EE0) --------------------------------------------------------
st32 sub_406EE0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( (a2 & 0x1800000) == 8388608 )
  {
    result = 473;
  }
  else
  {
    if ( (a2 & 0x1800000) == 25165824 )
      result = 474;
    else
      result = a1;
  }
  return result;
}

//----- (00406F10) --------------------------------------------------------
st32 sub_406F10(st32 a1, st32 a2)
{
  st32 v2; // eax@1

  v2 = a2 & 0x1010000;
  if ( (a2 & 0x1010000u) <= 0x1000000 )
  {
    if ( (a2 & 0x1010000) == 16777216 )
      return 472;
    if ( !v2 )
      return 23;
    if ( v2 == 65536 )
      return 24;
    return a1;
  }
  if ( v2 != 16842752 )
    return a1;
  return 26;
}

//----- (00406F60) --------------------------------------------------------
st32 sub_406F60(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( (a2 & 0x1010000) == 65536 )
  {
    result = 25;
  }
  else
  {
    if ( (a2 & 0x1010000) == 16842752 )
      result = 27;
    else
      result = a1;
  }
  return result;
}

//----- (00406F90) --------------------------------------------------------
st32 sub_406F90(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1010000 )
  {
    if ( (a2 & 0x1010000) == 16777216 )
      result = 135;
    else
      result = a1;
  }
  else
  {
    result = 134;
  }
  return result;
}

//----- (00406FC0) --------------------------------------------------------
st32 sub_406FC0(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 result; // eax@4

  v2 = a2 & 0x1010000;
  if ( a2 & 0x1010000 )
  {
    if ( v2 == 16777216 )
    {
      result = 138;
    }
    else
    {
      if ( v2 == 16842752 )
        result = 139;
      else
        result = a1;
    }
  }
  else
  {
    result = 137;
  }
  return result;
}

//----- (00406FF0) --------------------------------------------------------
st32 sub_406FF0(st32 a1, st32 a2)
{
  st32 v2; // eax@1

  v2 = a2 & 0x1010000;
  if ( (a2 & 0x1010000u) <= 0x1000000 )
  {
    if ( (a2 & 0x1010000) == 16777216 )
      return 12;
    if ( !v2 )
      return 11;
    if ( v2 == 65536 )
      return 8;
    return a1;
  }
  if ( v2 != 16842752 )
    return a1;
  return 9;
}

//----- (00407040) --------------------------------------------------------
st32 sub_407040(st32 a1, st32 a2)
{
  st32 v2; // eax@1

  v2 = a2 & 0x1010000;
  if ( (a2 & 0x1010000u) <= 0x1000000 )
  {
    if ( (a2 & 0x1010000) == 16777216 )
      return 13;
    if ( !v2 )
      return 15;
    if ( v2 == 65536 )
      return 10;
    return a1;
  }
  if ( v2 != 16842752 )
    return a1;
  return 14;
}

//----- (00407090) --------------------------------------------------------
st32 sub_407090(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 29;
    else
      result = a1;
  }
  else
  {
    result = 28;
  }
  return result;
}

//----- (004070C0) --------------------------------------------------------
st32 sub_4070C0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 17;
    else
      result = a1;
  }
  else
  {
    result = 16;
  }
  return result;
}

//----- (004070F0) --------------------------------------------------------
st32 sub_4070F0(st32 a1, st32 a2)
{
  st32 v2; // eax@1

  v2 = a2 & 0xC1000000;
  if ( (a2 & 0xC1000000u) > 0x40000000 )
  {
    if ( v2 != -2147483648 && v2 != -1073741824 )
      return a1;
  }
  else
  {
    if ( (a2 & 0xC1000000) != 1073741824 && v2 )
    {
      if ( v2 == 16777216 )
        return 136;
      return a1;
    }
  }
  return 18;
}

//----- (00407130) --------------------------------------------------------
st32 sub_407130(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 130;
    else
      result = a1;
  }
  else
  {
    result = 132;
  }
  return result;
}

//----- (00407160) --------------------------------------------------------
st32 sub_407160(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 133;
    else
      result = a1;
  }
  else
  {
    result = 131;
  }
  return result;
}

//----- (00407190) --------------------------------------------------------
st32 sub_407190(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x80000000 )
  {
    if ( (a2 & 0x80000000) == -2147483648 )
      result = 33;
    else
      result = a1;
  }
  else
  {
    result = 35;
  }
  return result;
}

//----- (004071C0) --------------------------------------------------------
st32 sub_4071C0(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1

  v2 = a2;
  v3 = v2 & 0x780000;
  if ( (ut32)v3 <= 0x400000 )
  {
    if ( v3 == 4194304 )
      return 522;
    if ( (ut32)v3 > 0x180000 )
    {
      if ( v3 == 2621440 )
        return 402;
      if ( v3 == 3145728 )
        return 411;
    }
    else
    {
      if ( v3 == 1572864 )
        return 401;
      if ( !v3 )
        return 403;
      if ( v3 == 524288 )
        return 400;
    }
    return a1;
  }
  if ( (ut32)v3 <= 0x680000 )
  {
    if ( v3 == 6815744 )
      return 526;
    if ( (st32 *)v3 == (st32 *)dword_480000 )
      return 524;
    if ( v3 == 5767168 )
      return 525;
    return a1;
  }
  if ( v3 != 7340032 )
    return a1;
  return 523;
}
// 480000: using guessed type st32 dword_480000[4];

//----- (00407260) --------------------------------------------------------
st32 sub_407260(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1

  v2 = a2;
  v3 = v2 & 0x180000;
  if ( (ut32)v3 > 0x100000 )
  {
    if ( v3 != 1572864 )
      return a1;
  }
  else
  {
    if ( v3 != 1048576 )
    {
      if ( !v3 )
        return 396;
      if ( v3 == 524288 )
        return 532;
      return a1;
    }
  }
  return 398;
}

//----- (004072A0) --------------------------------------------------------
st32 sub_4072A0(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1

  v2 = a2;
  v3 = v2 & 0x18000;
  if ( (ut32)v3 <= 0x10000 )
  {
    if ( v3 == 65536 )
      return 296;
    if ( !v3 )
      return 298;
    if ( v3 == 32768 )
      return 300;
    return a1;
  }
  if ( v3 != 98304 )
    return a1;
  return 301;
}

//----- (004072F0) --------------------------------------------------------
st32 sub_4072F0(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 result; // eax@4

  v2 = a2 & 0x8200;
  if ( a2 & 0x8200 )
  {
    if ( v2 == 512 )
    {
      result = 530;
    }
    else
    {
      if ( v2 == 32768 )
        result = 297;
      else
        result = a1;
    }
  }
  else
  {
    result = 355;
  }
  return result;
}

//----- (00407320) --------------------------------------------------------
st32 sub_407320(st32 a1, st32 a2)
{
  st32 v2; // eax@1

  v2 = a2 & 0x8200;
  if ( (ut32)v2 <= 0x8000 )
  {
    if ( v2 == 32768 )
      return 316;
    if ( !(a2 & 0x8200) )
      return 410;
    if ( v2 == 512 )
      return 531;
    return a1;
  }
  if ( v2 != 33280 )
    return a1;
  return 315;
}

//----- (00407370) --------------------------------------------------------
st32 sub_407370(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x8000 )
  {
    if ( (unsigned short)(a2 & 0x8000) == 32768 )
      result = 295;
    else
      result = a1;
  }
  else
  {
    result = 294;
  }
  return result;
}

//----- (004073A0) --------------------------------------------------------
st32 sub_4073A0(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1
  st32 result; // eax@6

  v2 = a2;
  v3 = v2 & 0x18180;
  if ( (ut32)v3 <= 0x8080 )
  {
    if ( v3 == 32896 )
      return 528;
    if ( !v3 )
      return 406;
    if ( v3 == 128 )
      return 527;
    if ( v3 == 32768 )
      return 407;
    return a1;
  }
  if ( v3 == 98304 )
  {
    result = 408;
  }
  else
  {
    if ( v3 != 98432 )
      return a1;
    result = 529;
  }
  return result;
}

//----- (00407400) --------------------------------------------------------
st32 sub_407400(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x8000 )
  {
    if ( (unsigned short)(a2 & 0x8000) == 32768 )
      result = 405;
    else
      result = a1;
  }
  else
  {
    result = 404;
  }
  return result;
}

//----- (00407430) --------------------------------------------------------
st32 sub_407430(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1
  st32 result; // eax@4

  v2 = a2;
  v3 = v2 & 0x18000;
  if ( v3 )
  {
    if ( v3 == 32768 )
    {
      result = 263;
    }
    else
    {
      if ( v3 == 65536 )
        result = 264;
      else
        result = a1;
    }
  }
  else
  {
    result = 262;
  }
  return result;
}

//----- (00407460) --------------------------------------------------------
st32 sub_407460(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 result; // eax@5

  v2 = a2 & 0x8180;
  if ( (ut32)v2 <= 0x100 )
  {
    if ( v2 == 256 )
      return 505;
    if ( !(a2 & 0x8180) )
      return 503;
    if ( v2 == 128 )
      return 504;
    return a1;
  }
  if ( v2 == 384 )
  {
    result = 506;
  }
  else
  {
    if ( v2 != 32768 )
      return a1;
    result = 507;
  }
  return result;
}

//----- (004074B0) --------------------------------------------------------
st32 sub_4074B0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 173;
    else
      result = a1;
  }
  else
  {
    result = 172;
  }
  return result;
}

//----- (004074E0) --------------------------------------------------------
st32 sub_4074E0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 175;
    else
      result = a1;
  }
  else
  {
    result = 174;
  }
  return result;
}

//----- (00407510) --------------------------------------------------------
st32 sub_407510(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 152;
    else
      result = a1;
  }
  else
  {
    result = 151;
  }
  return result;
}

//----- (00407540) --------------------------------------------------------
st32 sub_407540(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 154;
    else
      result = a1;
  }
  else
  {
    result = 153;
  }
  return result;
}

//----- (00407570) --------------------------------------------------------
st32 sub_407570(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 180;
    else
      result = a1;
  }
  else
  {
    result = 179;
  }
  return result;
}

//----- (004075A0) --------------------------------------------------------
st32 sub_4075A0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 182;
    else
      result = a1;
  }
  else
  {
    result = 181;
  }
  return result;
}

//----- (004075D0) --------------------------------------------------------
st32 sub_4075D0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( (a2 & 0x1C00000) == 12582912 )
  {
    result = 157;
  }
  else
  {
    if ( (a2 & 0x1C00000) == 29360128 )
      result = 158;
    else
      result = a1;
  }
  return result;
}

//----- (00407600) --------------------------------------------------------
st32 sub_407600(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 57;
    else
      result = a1;
  }
  else
  {
    result = 56;
  }
  return result;
}

//----- (00407630) --------------------------------------------------------
st32 sub_407630(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 208;
    else
      result = a1;
  }
  else
  {
    result = 207;
  }
  return result;
}

//----- (00407660) --------------------------------------------------------
st32 sub_407660(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 209;
    else
      result = a1;
  }
  else
  {
    result = 210;
  }
  return result;
}

//----- (00407690) --------------------------------------------------------
st32 sub_407690(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 result; // eax@4

  v2 = a2 & 0x1400000;
  if ( a2 & 0x1400000 )
  {
    if ( v2 == 16777216 )
    {
      result = 217;
    }
    else
    {
      if ( v2 == 20971520 )
        result = 212;
      else
        result = a1;
    }
  }
  else
  {
    result = 216;
  }
  return result;
}

//----- (004076C0) --------------------------------------------------------
st32 sub_4076C0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1400000 )
  {
    if ( (a2 & 0x1400000) == 4194304 )
      result = 211;
    else
      result = a1;
  }
  else
  {
    result = 218;
  }
  return result;
}

//----- (004076F0) --------------------------------------------------------
st32 sub_4076F0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 221;
    else
      result = a1;
  }
  else
  {
    result = 220;
  }
  return result;
}

//----- (00407720) --------------------------------------------------------
st32 sub_407720(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1010000 )
  {
    if ( (a2 & 0x1010000) == 16777216 )
      result = 215;
    else
      result = a1;
  }
  else
  {
    result = 214;
  }
  return result;
}

//----- (00407750) --------------------------------------------------------
st32 sub_407750(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( (a2 & 0x1010000) == 65536 )
  {
    result = 213;
  }
  else
  {
    if ( (a2 & 0x1010000) == 16842752 )
      result = 426;
    else
      result = a1;
  }
  return result;
}

//----- (00407780) --------------------------------------------------------
st32 sub_407780(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x80000000 )
  {
    if ( (a2 & 0x80000000) == -2147483648 )
      result = 457;
    else
      result = a1;
  }
  else
  {
    result = 459;
  }
  return result;
}

//----- (004077B0) --------------------------------------------------------
st32 sub_4077B0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 21;
    else
      result = a1;
  }
  else
  {
    result = 19;
  }
  return result;
}

//----- (004077E0) --------------------------------------------------------
st32 sub_4077E0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 22;
    else
      result = a1;
  }
  else
  {
    result = 20;
  }
  return result;
}

//----- (00407810) --------------------------------------------------------
st32 sub_407810(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1

  v2 = a2;
  v3 = v2 & 0x18000;
  if ( (ut32)v3 <= 0x10000 )
  {
    if ( v3 == 65536 )
      return 429;
    if ( !v3 )
      return 427;
    if ( v3 == 32768 )
      return 428;
    return a1;
  }
  if ( v3 != 98304 )
    return a1;
  return 252;
}

//----- (00407860) --------------------------------------------------------
st32 sub_407860(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1
  st32 result; // eax@8

  v2 = a2;
  v3 = v2 & 0x18180;
  if ( (ut32)v3 <= 0x8100 )
  {
    if ( v3 == 33024 )
      return 437;
    if ( (ut32)v3 > 0x180 )
    {
      if ( v3 == 32768 )
        return 431;
      if ( v3 == 32896 )
        return 435;
    }
    else
    {
      if ( v3 == 384 )
        return 440;
      if ( !v3 )
        return 430;
      if ( v3 == 128 )
        return 432;
      if ( v3 == 256 )
        return 434;
    }
    return a1;
  }
  if ( (ut32)v3 <= 0x10100 )
  {
    if ( v3 == 65792 )
      return 442;
    if ( v3 == 33152 )
      return 441;
    if ( v3 == 65536 )
      return 433;
    if ( v3 == 65664 )
      return 436;
    return a1;
  }
  if ( v3 == 65920 )
  {
    result = 439;
  }
  else
  {
    if ( v3 != 98688 )
      return a1;
    result = 438;
  }
  return result;
}

//----- (00407920) --------------------------------------------------------
st32 sub_407920(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1
  st32 result; // eax@8

  v2 = a2;
  v3 = v2 & 0x18180;
  if ( (ut32)v3 <= 0x8100 )
  {
    if ( v3 == 33024 )
      return 450;
    if ( (ut32)v3 > 0x180 )
    {
      if ( v3 == 32768 )
        return 444;
      if ( v3 == 32896 )
        return 448;
    }
    else
    {
      if ( v3 == 384 )
        return 453;
      if ( !v3 )
        return 443;
      if ( v3 == 128 )
        return 445;
      if ( v3 == 256 )
        return 447;
    }
    return a1;
  }
  if ( (ut32)v3 <= 0x10100 )
  {
    if ( v3 == 65792 )
      return 455;
    if ( v3 == 33152 )
      return 454;
    if ( v3 == 65536 )
      return 446;
    if ( v3 == 65664 )
      return 449;
    return a1;
  }
  if ( v3 == 65920 )
  {
    result = 452;
  }
  else
  {
    if ( v3 != 98688 )
      return a1;
    result = 451;
  }
  return result;
}

//----- (004079E0) --------------------------------------------------------
st32 sub_4079E0(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 result; // eax@7

  v2 = a2 & 0x1000180;
  if ( (a2 & 0x1000180u) <= 0x1000000 )
  {
    if ( (a2 & 0x1000180) == 16777216 )
      return 191;
    if ( (ut32)v2 > 0x100 )
    {
      if ( v2 == 384 )
        return 200;
    }
    else
    {
      if ( v2 == 256 )
        return 538;
      if ( !v2 )
        return 190;
      if ( v2 == 128 )
        return 537;
    }
    return a1;
  }
  if ( v2 == 16777344 )
  {
    result = 194;
  }
  else
  {
    if ( v2 == 16777472 )
    {
      result = 539;
    }
    else
    {
      if ( v2 != 16777600 )
        return a1;
      result = 201;
    }
  }
  return result;
}

//----- (00407A60) --------------------------------------------------------
st32 sub_407A60(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 result; // eax@5

  v2 = a2 & 0x1000180;
  if ( (a2 & 0x1000180u) <= 0x100 )
  {
    if ( (a2 & 0x1000180) == 256 )
      return 203;
    if ( !v2 )
      return 192;
    if ( v2 == 128 )
      return 195;
    return a1;
  }
  if ( v2 == 384 )
  {
    result = 198;
  }
  else
  {
    if ( v2 != 16777600 )
      return a1;
    result = 196;
  }
  return result;
}

//----- (00407AB0) --------------------------------------------------------
st32 sub_407AB0(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 result; // eax@9
  char v4; // zf@10

  v2 = a2 & 0x1810180;
  if ( (a2 & 0x1810180u) <= 0x800080 )
  {
    if ( (a2 & 0x1810180) != 8388736 )
    {
      if ( (ut32)v2 <= 0x10000 )
      {
        if ( v2 == 65536 )
          return 193;
        if ( (ut32)v2 <= 0x100 )
        {
          if ( v2 != 256 )
          {
            if ( v2 )
            {
              if ( v2 == 128 )
                return 197;
              return a1;
            }
            return 193;
          }
          return 202;
        }
        v4 = v2 == 384;
LABEL_11:
        if ( v4 )
          return 199;
        return a1;
      }
      if ( (ut32)v2 > 0x10180 )
      {
        if ( v2 == 8388608 )
          return 193;
        return a1;
      }
      if ( v2 == 65920 )
        return 199;
      if ( v2 != 65664 )
      {
        if ( v2 == 65792 )
          return 202;
        return a1;
      }
    }
    return 197;
  }
  if ( (ut32)v2 <= 0x810100 )
  {
    if ( v2 == 8454400 )
      return 202;
    if ( (ut32)v2 <= 0x810000 )
    {
      if ( v2 == 8454144 )
        return 193;
      if ( v2 == 8388864 )
        return 202;
      v4 = v2 == 8388992;
      goto LABEL_11;
    }
    if ( v2 != 8454272 )
      return a1;
    return 197;
  }
  if ( v2 == 8454528 )
    return 199;
  if ( v2 == 16777216 )
  {
    result = 205;
  }
  else
  {
    if ( v2 != 16777344 )
      return a1;
    result = 206;
  }
  return result;
}

//----- (00407B80) --------------------------------------------------------
st32 sub_407B80(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 result; // eax@4

  v2 = a2 & 0x1000180;
  if ( a2 & 0x1000180 )
  {
    if ( v2 == 16777344 )
    {
      result = 509;
    }
    else
    {
      if ( v2 == 16777472 )
        result = 510;
      else
        result = a1;
    }
  }
  else
  {
    result = 508;
  }
  return result;
}

//----- (00407BB0) --------------------------------------------------------
st32 sub_407BB0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( (a2 & 0x1000180) == 128 )
  {
    result = 511;
  }
  else
  {
    if ( (a2 & 0x1000180) == 256 )
      result = 512;
    else
      result = a1;
  }
  return result;
}

//----- (00407BE0) --------------------------------------------------------
st32 sub_407BE0(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( a2 & 0x1000000 )
  {
    if ( (a2 & 0x1000000) == 16777216 )
      result = 171;
    else
      result = a1;
  }
  else
  {
    result = 170;
  }
  return result;
}

//----- (00407C10) --------------------------------------------------------
st32 sub_407C10(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1
  st32 result; // eax@4

  v2 = a2;
  v3 = v2 & 0x79B981;
  if ( v3 == 33024 || v3 == 4227328 )
  {
    result = 490;
  }
  else
  {
    if ( v3 == 4260097 )
      result = 491;
    else
      result = a1;
  }
  return result;
}

//----- (00407C40) --------------------------------------------------------
st32 sub_407C40(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v3; // eax@1

  v2 = a2;
  v3 = v2 & 0x79B981;
  if ( (ut32)v3 <= 0x410101 )
  {
    if ( v3 == 4260097 )
      return 493;
    if ( v3 == 33024 || v3 == 4227328 )
      return 492;
    return a1;
  }
  if ( (st32 (*)())v3 != (st32 (*)())loc_418181 )
    return a1;
  return 494;
}
// 418181: using guessed type st32 loc_418181();

//----- (00407C80) --------------------------------------------------------
st32 sub_407C80(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( (a2 & 0x1B901B9) == 16777600 )
  {
    result = 488;
  }
  else
  {
    if ( (a2 & 0x1B901B9) == 25231616 )
      result = 495;
    else
      result = a1;
  }
  return result;
}

//----- (00407CB0) --------------------------------------------------------
st32 sub_407CB0(st32 a1, st32 a2)
{
  st32 v2; // eax@1
  st32 v4; // eax@12
  st32 v5; // eax@13

  v2 = a2 & 0x1F901B9;
  if ( (a2 & 0x1F901B9u) <= 0x1810101 )
  {
    if ( (a2 & 0x1F901B9) == 25231617 )
      return 498;
    if ( (ut32)v2 <= 0x1000180 )
    {
      if ( v2 != 16777600 )
      {
        if ( v2 == 8454401 )
          return 497;
        if ( v2 == 8454529 )
          return 499;
        return a1;
      }
      return 489;
    }
    if ( v2 == 20971904 )
      return 489;
    return a1;
  }
  v4 = v2 - 25231744;
  if ( v4 )
  {
    v5 = v4 - 1;
    if ( !v5 )
      return 500;

    /* FIX */
    v5 -= 0x3FFFFF;
    if(v5 != 0) {
	return a1;
    }
    /*
    if ( (_UNKNOWN *)v5 != &unk_3FFFFF )
      return a1;
    */
  }
  return 496;
}

//----- (00407D20) --------------------------------------------------------
st32 sub_407D20(st32 a1, st32 a2)
{
  st32 result; // eax@3

  if ( (a2 & 0x1F901BF) == 8454145 )
  {
    result = 501;
  }
  else
  {
    if ( (a2 & 0x1F901BF) == 25231361 )
      result = 502;
    else
      result = a1;
  }
  return result;
}


//get hashcode from instruction bytecode
st32 get_hash_code(ut32 ins_pos)
{
  ut32 len, ins_part1;
  ut32 opcode, pos;
  st32 (*get_hashcode_func)(st32 arg, st32 arg2);
  ut32 ins_len;
  st32 arg, ins_part2, hash_code;

  ins_part1 = 0;
  ins_part2 = 0;

  opcode = get_ins_part(ins_pos, 1);
  ins_len = get_ins_len(opcode);

  if(debug) {
	printf("opcode: 0x%x part: %d\n", opcode, ins_pos);
	printf("ins_len: 0x%x\n", ins_len);
  }

  if (ins_len > 1 )
  {
    len = ins_len - 1;
    if (len >= 4 )
      len = 4;

    ins_part1 = get_ins_part(ins_pos + 1, len) << (8 * (4 - len));
    ins_part2 = 0;
    if (ins_len > 5 )
      ins_part2 = get_ins_part(ins_pos + 5, 1);
  }

  pos = (2 * opcode | (ins_part1 >> 31));
  //arg = *(ut32 *)(((ut8 *)ins_hash)+ pos * 8);
  arg = ins_hash[pos].code;

  ins_part2 >>= 7;
  ins_part2 |= (ins_part1 * 2);

  //get_hashcode_func = *(ut32 *)(((ut8 *)ins_hash + sizeof(ut32)) + pos * 8);
  get_hashcode_func = ins_hash[pos].hash_func;

	
  if(debug) {
  	printf("hashfunc => 0x%x 0x%x\n", (unsigned int)get_hashcode_func, pos);
  	printf("hashargs => 0x%x 0x%x 0x%x\n", (unsigned int)arg, ins_part1, ins_part2);
  }


  hash_code = get_hashcode_func(arg, ins_part2);
  if(debug) {
	printf("ret hashcode: 0x%x\n", hash_code);
  }
 
  return hash_code;
}
