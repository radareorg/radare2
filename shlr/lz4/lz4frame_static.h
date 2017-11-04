/*
   LZ4 auto-framing library
   Header File for static linking only
   Copyright (C) 2011-2016, Yann Collet.

   BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are
   met:

       * Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
       * Redistributions in binary form must reproduce the above
   copyright notice, this list of conditions and the following disclaimer
   in the documentation and/or other materials provided with the
   distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   You can contact the author at :
   - LZ4 source repository : https://github.com/lz4/lz4
   - LZ4 public forum : https://groups.google.com/forum/#!forum/lz4c
*/

#ifndef LZ4FRAME_STATIC_H_0398209384
#define LZ4FRAME_STATIC_H_0398209384

#if defined (__cplusplus)
extern "C" {
#endif

/* lz4frame_static.h should be used solely in the context of static linking.
 * It contains definitions which are not stable and may change in the future.
 * Never use it in the context of DLL linking.
 */


/* ---   Dependency   --- */
#include "lz4frame.h"


/* ---   Error List   --- */
#define LZ4F_LIST_ERRORS(ITEM) \
        ITEM(OK_NoError) \
        ITEM(ERROR_GENERIC) \
        ITEM(ERROR_maxBlockSize_invalid) \
        ITEM(ERROR_blockMode_invalid) \
        ITEM(ERROR_contentChecksumFlag_invalid) \
        ITEM(ERROR_compressionLevel_invalid) \
        ITEM(ERROR_headerVersion_wrong) \
        ITEM(ERROR_blockChecksum_invalid) \
        ITEM(ERROR_reservedFlag_set) \
        ITEM(ERROR_allocation_failed) \
        ITEM(ERROR_srcSize_tooLarge) \
        ITEM(ERROR_dstMaxSize_tooSmall) \
        ITEM(ERROR_frameHeader_incomplete) \
        ITEM(ERROR_frameType_unknown) \
        ITEM(ERROR_frameSize_wrong) \
        ITEM(ERROR_srcPtr_wrong) \
        ITEM(ERROR_decompressionFailed) \
        ITEM(ERROR_headerChecksum_invalid) \
        ITEM(ERROR_contentChecksum_invalid) \
        ITEM(ERROR_frameDecoding_alreadyStarted) \
        ITEM(ERROR_maxCode)

#define LZ4F_GENERATE_ENUM(ENUM) LZ4F_##ENUM,

/* enum list is exposed, to handle specific errors */
typedef enum { LZ4F_LIST_ERRORS(LZ4F_GENERATE_ENUM) } LZ4F_errorCodes;

LZ4F_errorCodes LZ4F_getErrorCode(size_t functionResult);



/**********************************
 *  Bulk processing dictionary API
 *********************************/
typedef struct LZ4F_CDict_s LZ4F_CDict;

/*! LZ4_createCDict() :
 *  When compressing multiple messages / blocks with the same dictionary, it's recommended to load it just once.
 *  LZ4_createCDict() will create a digested dictionary, ready to start future compression operations without startup delay.
 *  LZ4_CDict can be created once and shared by multiple threads concurrently, since its usage is read-only.
 * `dictBuffer` can be released after LZ4_CDict creation, since its content is copied within CDict */
LZ4F_CDict* LZ4F_createCDict(const void* dictBuffer, size_t dictSize);
void        LZ4F_freeCDict(LZ4F_CDict* CDict);


/*! LZ4_compressFrame_usingCDict() :
 *  Compress an entire srcBuffer into a valid LZ4 frame using a digested Dictionary.
 *  If cdict==NULL, compress without a dictionary.
 *  dstBuffer MUST be >= LZ4F_compressFrameBound(srcSize, preferencesPtr).
 *  If this condition is not respected, function will fail (@return an errorCode).
 *  The LZ4F_preferences_t structure is optional : you may provide NULL as argument,
 *  but it's not recommended, as it's the only way to provide dictID in the frame header.
 * @return : number of bytes written into dstBuffer.
 *           or an error code if it fails (can be tested using LZ4F_isError()) */
size_t LZ4F_compressFrame_usingCDict(void* dst, size_t dstCapacity,
                               const void* src, size_t srcSize,
                               const LZ4F_CDict* cdict,
                               const LZ4F_preferences_t* preferencesPtr);


/*! LZ4F_compressBegin_usingCDict() :
 *  Inits streaming dictionary compression, and writes the frame header into dstBuffer.
 *  dstCapacity must be >= LZ4F_HEADER_SIZE_MAX bytes.
 * `prefsPtr` is optional : you may provide NULL as argument,
 *  however, it's the only way to provide dictID in the frame header.
 * @return : number of bytes written into dstBuffer for the header,
 *           or an error code (which can be tested using LZ4F_isError()) */
size_t LZ4F_compressBegin_usingCDict(LZ4F_cctx* cctx,
                                     void* dstBuffer, size_t dstCapacity,
                                     const LZ4F_CDict* cdict,
                                     const LZ4F_preferences_t* prefsPtr);


/*! LZ4F_decompress_usingDict() :
 *  Same as LZ4F_decompress(), using a predefined dictionary.
 *  Dictionary is used "in place", without any preprocessing.
 *  It must remain accessible throughout the entire frame decoding. */
size_t LZ4F_decompress_usingDict(LZ4F_dctx* dctxPtr,
                       void* dstBuffer, size_t* dstSizePtr,
                       const void* srcBuffer, size_t* srcSizePtr,
                       const void* dict, size_t dictSize,
                       const LZ4F_decompressOptions_t* decompressOptionsPtr);


#if defined (__cplusplus)
}
#endif

#endif /* LZ4FRAME_STATIC_H_0398209384 */
