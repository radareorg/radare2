
/* This file is for the gdb wrapper internals. It is not meant to be
   included. */

#define     GDBWRAP_PACKET_NO_BEGIN(_tocmp, _ptr)               \
              assert(_tocmp);                                   \
              _ptr = (strstr(_tocmp, GDBWRAP_BEGIN_PACKET) + 1)

#define     __DEBUG_GDBWRAP__      FALSE
#define     MSG_BUF                80

#if __DEBUG_GDBWRAP__
#define DEBUGMSG(_command)				\
   do							\
      {							\
         _command;					\
      } while(0)
#else
#define DEBUGMSG(_command)				
#endif

#define     CONSTSTRDEC(_name, _value)  const char * const  _name = _value
#define     CONSTCHRDEC(_name, _value)  const char          _name = _value
#define     CTRL_C                  0x3
CONSTSTRDEC(GDBWRAP_BEGIN_PACKET,    "$");
CONSTSTRDEC(GDBWRAP_END_PACKET,      "#");
CONSTSTRDEC(GDBWRAP_QSUPPORTED,      "qSupported");
CONSTSTRDEC(GDBWRAP_DISCONNECT,      "k");
CONSTSTRDEC(GDBWRAP_CONTINUEWITH,    "vCont");
CONSTSTRDEC(GDBWRAP_CONTINUE,        "c"); //"vCont;c");
CONSTSTRDEC(GDBWRAP_SIGNAL,          "C");
CONSTSTRDEC(GDBWRAP_GENPURPREG,      "g");
CONSTSTRDEC(GDBWRAP_WGENPURPREG,     "G");
CONSTSTRDEC(GDBWRAP_MEMCONTENT,      "m");
CONSTSTRDEC(GDBWRAP_MEMWRITE,        "X");
CONSTSTRDEC(GDBWRAP_MEMWRITE2,       "M");
CONSTSTRDEC(GDBWRAP_INSERTBP,        "Z0");
CONSTSTRDEC(GDBWRAP_REMOVEBP,        "z0");
CONSTSTRDEC(GDBWRAP_INSERTHWBP,	     "Z1");
CONSTSTRDEC(GDBWRAP_REMOVEHWBP,	     "z1");
CONSTSTRDEC(GDBWRAP_STEPI,           "s");
CONSTSTRDEC(GDBWRAP_WRITEREG,        "P");
CONSTSTRDEC(GDBWRAP_ERROR,           "E");
CONSTSTRDEC(GDBWRAP_COR_CHECKSUM,    "+");
CONSTSTRDEC(GDBWRAP_WHY_HALTED,      "?");
CONSTSTRDEC(GDBWRAP_START_ENCOD,     "*");
CONSTSTRDEC(GDBWRAP_SEP_COLON,       ":");
CONSTSTRDEC(GDBWRAP_SEP_SEMICOLON,   ";");
CONSTSTRDEC(GDBWRAP_SEP_COMMA,       ",");
CONSTSTRDEC(GDBWRAP_RCMD,            "qRcmd");
CONSTSTRDEC(GDBWRAP_PACKETSIZE,      "PacketSize=");
CONSTSTRDEC(GDBWRAP_REPLAY_OK,       "OK");
CONSTSTRDEC(GDBWRAP_NO_SPACE,        "nospace");
CONSTSTRDEC(GDBWRAP_NO_TABLE,        "notable");
CONSTSTRDEC(GDBWRAP_DEAD,            "dead");
CONSTSTRDEC(GDBWRAP_MEMORYMAP_READ,  "qXfer:memory-map:read");

CONSTCHRDEC(GDBWRAP_NULL_CHAR,       '\0');
CONSTCHRDEC(GDBWRAP_REPLAY_ERROR,    'E');
CONSTCHRDEC(GDBWRAP_SIGNAL_RECV,     'T');
CONSTCHRDEC(GDBWRAP_SIGNAL_RECV2,    'S');
CONSTCHRDEC(GDBWRAP_EXIT_W_STATUS,   'W');
CONSTCHRDEC(GDBWRAP_EXIT_W_SIGNAL,   'X');
CONSTCHRDEC(GDBWRAP_END_PACKETC,     '#');
CONSTCHRDEC(GDBWRAP_START_ENCODC,    '*');
CONSTCHRDEC(GDBWRAP_COR_CHECKSUMC,   '+');
CONSTCHRDEC(GDBWRAP_BAD_CHECKSUM,    '-');

extern int errno;
