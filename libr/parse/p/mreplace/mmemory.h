//
// Library: Memory Manage Module v1.10, Copyleft, 2009-02-25
// Author : Mandingo, mandingo [ at ] yoire.com
//

#define USE_BCOPY		1

#define MEM_STATE_BAD		0
#define MEM_STATE_OK		1

typedef struct {
	char *address;
	long size;
} memChunk;

typedef struct {
	long allocated;
	char state;
} memInfo;

memChunk *memReserve(long size);
void      memCopy(memChunk *dest,memChunk *source);
memInfo  *memInformation();
long	  memAllocated();
void      memFree(memChunk *chunk);
void      memCheckState();

void      memStrCat(memChunk *dest,char *string);
memChunk *memString(char *string);
void      memStringRealloc(memChunk *chunk);
memChunk *memStringReserve(char *string,long nbytes);

