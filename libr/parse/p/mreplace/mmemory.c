//
// Library: Memory Manage Module v1.10, Copyleft, 2009-02-25
// Author : Mandingo, mandingo [ at ]yoire.com
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include "mmemory.h"

memInfo *mInfo;

void memStringRealloc(memChunk *chunk){
	memCheckState();
	memChunk *temp;
	temp=memString(chunk->address);
	//printf("Reallocating chunk size %d to size %d\n",chunk->size,temp->size);
	memCopy(chunk,temp);
	memFree(temp);
}

void memFree(memChunk *chunk){
	memCheckState();
	if(chunk && chunk->address){
		mInfo->allocated-=chunk->size;
		free(chunk->address);
		free(chunk);
	}
}
void memInit(){
	mInfo=(memInfo*)malloc(sizeof(memInfo));
	bzero(mInfo,sizeof(memInfo));
	mInfo->state=MEM_STATE_OK;
	mInfo->allocated+=sizeof(memInfo);
}
void memCheckState(){
	if(mInfo==NULL) memInit();
	if(mInfo->state!=MEM_STATE_OK){
		fprintf(stderr,"\rMMemmory not initialized :p\n");
		exit(0);
	}
}
memInfo *memInformation(){
	memCheckState();
	return mInfo;
}
long memAllocated(){
	memCheckState();
	return mInfo->allocated;
}
memChunk *memReserve(long size){
	static memChunk *buffer;
	memCheckState();
	buffer=(memChunk*)malloc(sizeof(memChunk));
 	 if((buffer->address=(char*)malloc(size))==NULL){
		perror("memReserve");
		exit(0);
  	}
	//printf("- reservando %d bytes\n",size);
	buffer->size=size;
	bzero(buffer->address,buffer->size);
	mInfo->allocated+=size;
	return buffer;
}
memChunk *memStringReserve(char *string,long nbytes){
	static memChunk *buffer;
	buffer=memReserve(nbytes);
	memCopy(buffer,memString(string));
	return buffer;
}
memChunk *memString(char *string){
	static memChunk *buffer;
	memCheckState();
	buffer=memReserve(strlen(string)+1);
	#if USE_BCOPY
		bcopy(string,buffer->address,strlen(string));
	#else
		memcpy(buffer->address,string,strlen(string));
	#endif
	return buffer;
}

void memCopy(memChunk *dest,memChunk *source){
	long nbytes;
	if(!dest->address){
		dest=memString(source->address);
	}else{
		nbytes=dest->size > source->size ? source->size : dest->size;
		memCheckState();
		//printf("Copying %d bytes to dest (size %d)\n",nbytes,dest->address,dest->size);
		#if USE_BCOPY
			bcopy(source->address,dest->address,nbytes);
		#else
			memcpy(dest->address,source->address,nbytes);
		#endif
	}
}

void memStrCat(memChunk *dest,char *string){
	//long nbytes;
	memChunk result,*temp;

	temp           = memReserve(dest->size+strlen(string)+1);

	result.address = dest->address+strlen(dest->address);
	result.size    = dest->size-strlen(dest->address)+1;

	memCopy(temp,memString(string));
	memCopy(&result,temp);

	memFree(temp);
}
