/* radare - LGPL - 2021 - murphy */

//Format definition: https://doomwiki.org/wiki/WAD

#ifndef _WAD_H
#define _WAD_H

#include <r_types_base.h>

#define IWAD_MAGIC                          "\x49\x57\x41\x44"
#define PWAD_MAGIC                          "\x50\x57\x41\x44"

#define WAD_HDR_SIZE                       sizeof (wad_hdr)


R_PACKED (
struct wad_hdr
{
	ut32 magic;  // "IWAD" or "PWAD", not NULL-terminated
	ut32 numlumps;  // number of lumps in the WAD.
	ut32 diroffset;  //  Offset  to the location of the directory
});

R_PACKED (
struct directory_entry
{
	ut32 filepos;  // Start of the lump's data in the file
	ut32 size;  // Size of the lump in bytes
	ut32 name;  // Name of lump
});

#endif // _WAD_H
