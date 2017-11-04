/*
   LZ4 auto-framing library
   Header File
   Copyright (C) 2011-2017, Yann Collet.
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

/* LZ4F is a stand-alone API to create LZ4-compressed frames
 * conformant with specification v1.5.1.
 * It also offers streaming capabilities.
 * lz4.h is not required when using lz4frame.h.
 * */

#ifndef LZ4F_H_09782039843
#define LZ4F_H_09782039843

#if defined (__cplusplus)
extern "C" {
#endif

/* ---   Dependency   --- */
#include <stddef.h>   /* size_t */


/**
  Introduction

  lz4frame.h implements LZ4 frame specification (doc/lz4_Frame_format.md).
  lz4frame.h provides frame compression functions that take care
  of encoding standard metadata alongside LZ4-compressed blocks.
*/

/*-***************************************************************
 *  Compiler specifics
 *****************************************************************/
/*  LZ4_DLL_EXPORT :
 *  Enable exporting of functions when building a Windows DLL
 *  LZ4FLIB_API :
 *  Control library symbols visibility.
 */
#if defined(LZ4_DLL_EXPORT) && (LZ4_DLL_EXPORT==1)
#  define LZ4FLIB_API __declspec(dllexport)
#elif defined(LZ4_DLL_IMPORT) && (LZ4_DLL_IMPORT==1)
#  define LZ4FLIB_API __declspec(dllimport)
#elif defined(__GNUC__) && (__GNUC__ >= 4)
#  define LZ4FLIB_API __attribute__ ((__visibility__ ("default")))
#else
#  define LZ4FLIB_API
#endif

#ifdef LZ4F_DISABLE_DEPRECATE_WARNINGS
#  define LZ4F_DEPRECATE(x) x
#else
#  if defined(_MSC_VER)
#    define LZ4F_DEPRECATE(x) x   /* __declspec(deprecated) x - only works with C++ */
#  elif defined(__clang__) || (defined(__GNUC__) && (__GNUC__ >= 6))
#    define LZ4F_DEPRECATE(x) x __attribute__((deprecated))
#  else
#    define LZ4F_DEPRECATE(x) x   /* no deprecation warning for this compiler */
#  endif
#endif


/*-************************************
 *  Error management
 **************************************/
typedef size_t LZ4F_errorCode_t;

LZ4FLIB_API unsigned    LZ4F_isError(LZ4F_errorCode_t code);   /**< tells if a `LZ4F_errorCode_t` function result is an error code */
LZ4FLIB_API const char* LZ4F_getErrorName(LZ4F_errorCode_t code);   /**< return error code string; useful for debugging */


/*-************************************
 *  Frame compression types
 **************************************/
/* #define LZ4F_ENABLE_OBSOLETE_ENUMS   // uncomment to enable obsolete enums */
#ifdef LZ4F_ENABLE_OBSOLETE_ENUMS
#  define LZ4F_OBSOLETE_ENUM(x) , LZ4F_DEPRECATE(x) = LZ4F_##x
#else
#  define LZ4F_OBSOLETE_ENUM(x)
#endif

/* The larger the block size, the (slightly) better the compression ratio,
 * though there are diminishing returns.
 * Larger blocks also increase memory usage on both compression and decompression sides. */
typedef enum {
    LZ4F_default=0,
    LZ4F_max64KB=4,
    LZ4F_max256KB=5,
    LZ4F_max1MB=6,
    LZ4F_max4MB=7
    LZ4F_OBSOLETE_ENUM(max64KB)
    LZ4F_OBSOLETE_ENUM(max256KB)
    LZ4F_OBSOLETE_ENUM(max1MB)
    LZ4F_OBSOLETE_ENUM(max4MB)
} LZ4F_blockSizeID_t;

/* Linked blocks sharply reduce inefficiencies when using small blocks,
 * they compress better.
 * However, some LZ4 decoders are only compatible with independent blocks */
typedef enum {
    LZ4F_blockLinked=0,
    LZ4F_blockIndependent
    LZ4F_OBSOLETE_ENUM(blockLinked)
    LZ4F_OBSOLETE_ENUM(blockIndependent)
} LZ4F_blockMode_t;

typedef enum {
    LZ4F_noContentChecksum=0,
    LZ4F_contentChecksumEnabled
    LZ4F_OBSOLETE_ENUM(noContentChecksum)
    LZ4F_OBSOLETE_ENUM(contentChecksumEnabled)
} LZ4F_contentChecksum_t;

typedef enum {
    LZ4F_noBlockChecksum=0,
    LZ4F_blockChecksumEnabled
} LZ4F_blockChecksum_t;

typedef enum {
    LZ4F_frame=0,
    LZ4F_skippableFrame
    LZ4F_OBSOLETE_ENUM(skippableFrame)
} LZ4F_frameType_t;

#ifdef LZ4F_ENABLE_OBSOLETE_ENUMS
typedef LZ4F_blockSizeID_t blockSizeID_t;
typedef LZ4F_blockMode_t blockMode_t;
typedef LZ4F_frameType_t frameType_t;
typedef LZ4F_contentChecksum_t contentChecksum_t;
#endif

/*! LZ4F_frameInfo_t :
 *  makes it possible to set or read frame parameters.
 *  It's not required to set all fields, as long as the structure was initially memset() to zero.
 *  For all fields, 0 sets it to default value */
typedef struct {
  LZ4F_blockSizeID_t     blockSizeID;          /* max64KB, max256KB, max1MB, max4MB ; 0 == default */
  LZ4F_blockMode_t       blockMode;            /* LZ4F_blockLinked, LZ4F_blockIndependent ; 0 == default */
  LZ4F_contentChecksum_t contentChecksumFlag;  /* if enabled, frame is terminated with a 32-bits checksum of decompressed data ; 0 == disabled (default)  */
  LZ4F_frameType_t       frameType;            /* read-only field : LZ4F_frame or LZ4F_skippableFrame */
  unsigned long long     contentSize;          /* Size of uncompressed content ; 0 == unknown */
  unsigned               dictID;               /* Dictionary ID, sent by the compressor to help decoder select the correct dictionary; 0 == no dictID provided */
  LZ4F_blockChecksum_t   blockChecksumFlag;    /* if enabled, each block is followed by a checksum of block's compressed data ; 0 == disabled (default)  */
} LZ4F_frameInfo_t;

/*! LZ4F_preferences_t :
 *  makes it possible to supply detailed compression parameters to the stream interface.
 *  It's not required to set all fields, as long as the structure was initially memset() to zero.
 *  All reserved fields must be set to zero. */
typedef struct {
  LZ4F_frameInfo_t frameInfo;
  int      compressionLevel;       /* 0 == default (fast mode); values above LZ4HC_CLEVEL_MAX count as LZ4HC_CLEVEL_MAX; values below 0 trigger "fast acceleration", proportional to value */
  unsigned autoFlush;              /* 1 == always flush, to reduce usage of internal buffers */
  unsigned reserved[4];            /* must be zero for forward compatibility */
} LZ4F_preferences_t;

LZ4FLIB_API int LZ4F_compressionLevel_max(void);


/*-*********************************
*  Simple compression function
***********************************/
/*! LZ4F_compressFrameBound() :
 *  Returns the maximum possible size of a frame compressed with LZ4F_compressFrame() given srcSize content and preferences.
 *  Note : this result is only usable with LZ4F_compressFrame(), not with multi-segments compression.
 */
LZ4FLIB_API size_t LZ4F_compressFrameBound(size_t srcSize, const LZ4F_preferences_t* preferencesPtr);

/*! LZ4F_compressFrame() :
 *  Compress an entire srcBuffer into a valid LZ4 frame.
 *  dstCapacity MUST be >= LZ4F_compressFrameBound(srcSize, preferencesPtr).
 *  The LZ4F_preferences_t structure is optional : you can provide NULL as argument. All preferences will be set to default.
 * @return : number of bytes written into dstBuffer.
 *           or an error code if it fails (can be tested using LZ4F_isError())
 */
LZ4FLIB_API size_t LZ4F_compressFrame(void* dstBuffer, size_t dstCapacity,
                                const void* srcBuffer, size_t srcSize,
                                const LZ4F_preferences_t* preferencesPtr);


/*-***********************************
*  Advanced compression functions
*************************************/
typedef struct LZ4F_cctx_s LZ4F_cctx;   /* incomplete type */
typedef LZ4F_cctx* LZ4F_compressionContext_t;   /* for compatibility with previous API version */

typedef struct {
  unsigned stableSrc;    /* 1 == src content will remain present on future calls to LZ4F_compress(); skip copying src content within tmp buffer */
  unsigned reserved[3];
} LZ4F_compressOptions_t;

/*---   Resource Management   ---*/

#define LZ4F_VERSION 100
LZ4FLIB_API unsigned LZ4F_getVersion(void);
/*! LZ4F_createCompressionContext() :
 * The first thing to do is to create a compressionContext object, which will be used in all compression operations.
 * This is achieved using LZ4F_createCompressionContext(), which takes as argument a version.
 * The version provided MUST be LZ4F_VERSION. It is intended to track potential version mismatch, notably when using DLL.
 * The function will provide a pointer to a fully allocated LZ4F_cctx object.
 * If @return != zero, there was an error during context creation.
 * Object can release its memory using LZ4F_freeCompressionContext();
 */
LZ4FLIB_API LZ4F_errorCode_t LZ4F_createCompressionContext(LZ4F_cctx** cctxPtr, unsigned version);
LZ4FLIB_API LZ4F_errorCode_t LZ4F_freeCompressionContext(LZ4F_cctx* cctx);


/*----    Compression    ----*/

#define LZ4F_HEADER_SIZE_MAX 19
/*! LZ4F_compressBegin() :
 *  will write the frame header into dstBuffer.
 *  dstCapacity must be >= LZ4F_HEADER_SIZE_MAX bytes.
 * `prefsPtr` is optional : you can provide NULL as argument, all preferences will then be set to default.
 * @return : number of bytes written into dstBuffer for the header
 *           or an error code (which can be tested using LZ4F_isError())
 */
LZ4FLIB_API size_t LZ4F_compressBegin(LZ4F_cctx* cctx,
                                      void* dstBuffer, size_t dstCapacity,
                                      const LZ4F_preferences_t* prefsPtr);

/*! LZ4F_compressBound() :
 * Provides dstCapacity given a srcSize to guarantee operation success in worst case situations.
 * prefsPtr is optional : you can provide NULL as argument, preferences will be set to cover worst case scenario.
 * Result is always the same for a srcSize and prefsPtr, so it can be trusted to size reusable buffers.
 * When srcSize==0, LZ4F_compressBound() provides an upper bound for LZ4F_flush() and LZ4F_compressEnd() operations.
 */
LZ4FLIB_API size_t LZ4F_compressBound(size_t srcSize, const LZ4F_preferences_t* prefsPtr);

/*! LZ4F_compressUpdate() :
 * LZ4F_compressUpdate() can be called repetitively to compress as much data as necessary.
 * An important rule is that dstCapacity MUST be large enough to ensure operation success even in worst case situations.
 * This value is provided by LZ4F_compressBound().
 * If this condition is not respected, LZ4F_compress() will fail (result is an errorCode).
 * LZ4F_compressUpdate() doesn't guarantee error recovery. When an error occurs, compression context must be freed or resized.
 * `cOptPtr` is optional : NULL can be provided, in which case all options are set to default.
 * @return : number of bytes written into `dstBuffer` (it can be zero, meaning input data was just buffered).
 *           or an error code if it fails (which can be tested using LZ4F_isError())
 */
LZ4FLIB_API size_t LZ4F_compressUpdate(LZ4F_cctx* cctx, void* dstBuffer, size_t dstCapacity, const void* srcBuffer, size_t srcSize, const LZ4F_compressOptions_t* cOptPtr);

/*! LZ4F_flush() :
 * When data must be generated and sent immediately, without waiting for a block to be completely filled,
 * it's possible to call LZ4_flush(). It will immediately compress any data buffered within cctx.
 * `dstCapacity` must be large enough to ensure the operation will be successful.
 * `cOptPtr` is optional : it's possible to provide NULL, all options will be set to default.
 * @return : number of bytes written into dstBuffer (it can be zero, which means there was no data stored within cctx)
 *           or an error code if it fails (which can be tested using LZ4F_isError())
 */
LZ4FLIB_API size_t LZ4F_flush(LZ4F_cctx* cctx, void* dstBuffer, size_t dstCapacity, const LZ4F_compressOptions_t* cOptPtr);

/*! LZ4F_compressEnd() :
 *  To properly finish an LZ4 frame, invoke LZ4F_compressEnd().
 *  It will flush whatever data remained within `cctx` (like LZ4_flush())
 *  and properly finalize the frame, with an endMark and a checksum.
 * `cOptPtr` is optional : NULL can be provided, in which case all options will be set to default.
 * @return : number of bytes written into dstBuffer (necessarily >= 4 (endMark), or 8 if optional frame checksum is enabled)
 *           or an error code if it fails (which can be tested using LZ4F_isError())
 *  A successful call to LZ4F_compressEnd() makes `cctx` available again for another compression task.
 */
LZ4FLIB_API size_t LZ4F_compressEnd(LZ4F_cctx* cctx, void* dstBuffer, size_t dstCapacity, const LZ4F_compressOptions_t* cOptPtr);


/*-*********************************
*  Decompression functions
***********************************/
typedef struct LZ4F_dctx_s LZ4F_dctx;   /* incomplete type */
typedef LZ4F_dctx* LZ4F_decompressionContext_t;   /* compatibility with previous API versions */

typedef struct {
  unsigned stableDst;    /* pledge that at least 64KB+64Bytes of previously decompressed data remain unmodifed where it was decoded. This optimization skips storage operations in tmp buffers */
  unsigned reserved[3];  /* must be set to zero for forward compatibility */
} LZ4F_decompressOptions_t;


/* Resource management */

/*!LZ4F_createDecompressionContext() :
 * Create an LZ4F_dctx object, to track all decompression operations.
 * The version provided MUST be LZ4F_VERSION.
 * The function provides a pointer to an allocated and initialized LZ4F_dctx object.
 * The result is an errorCode, which can be tested using LZ4F_isError().
 * dctx memory can be released using LZ4F_freeDecompressionContext();
 * The result of LZ4F_freeDecompressionContext() is indicative of the current state of decompressionContext when being released.
 * That is, it should be == 0 if decompression has been completed fully and correctly.
 */
LZ4FLIB_API LZ4F_errorCode_t LZ4F_createDecompressionContext(LZ4F_dctx** dctxPtr, unsigned version);
LZ4FLIB_API LZ4F_errorCode_t LZ4F_freeDecompressionContext(LZ4F_dctx* dctx);


/*-***********************************
*  Streaming decompression functions
*************************************/

/*! LZ4F_getFrameInfo() :
 *  This function extracts frame parameters (max blockSize, dictID, etc.).
 *  Its usage is optional.
 *  Extracted information is typically useful for allocation and dictionary.
 *  This function works in 2 situations :
 *   - At the beginning of a new frame, in which case
 *     it will decode information from `srcBuffer`, starting the decoding process.
 *     Input size must be large enough to successfully decode the entire frame header.
 *     Frame header size is variable, but is guaranteed to be <= LZ4F_HEADER_SIZE_MAX bytes.
 *     It's allowed to provide more input data than this minimum.
 *   - After decoding has been started.
 *     In which case, no input is read, frame parameters are extracted from dctx.
 *   - If decoding has barely started, but not yet extracted information from header,
 *     LZ4F_getFrameInfo() will fail.
 *  The number of bytes consumed from srcBuffer will be updated within *srcSizePtr (necessarily <= original value).
 *  Decompression must resume from (srcBuffer + *srcSizePtr).
 * @return : an hint about how many srcSize bytes LZ4F_decompress() expects for next call,
 *           or an error code which can be tested using LZ4F_isError().
 *  note 1 : in case of error, dctx is not modified. Decoding operation can resume from beginning safely.
 *  note 2 : frame parameters are *copied into* an already allocated LZ4F_frameInfo_t structure.
 */
LZ4FLIB_API size_t LZ4F_getFrameInfo(LZ4F_dctx* dctx,
                                     LZ4F_frameInfo_t* frameInfoPtr,
                                     const void* srcBuffer, size_t* srcSizePtr);

/*! LZ4F_decompress() :
 *  Call this function repetitively to regenerate compressed data from `srcBuffer`.
 *  The function will attempt to decode up to *srcSizePtr bytes from srcBuffer, into dstBuffer of capacity *dstSizePtr.
 *
 *  The number of bytes regenerated into dstBuffer is provided within *dstSizePtr (necessarily <= original value).
 *
 *  The number of bytes consumed from srcBuffer is provided within *srcSizePtr (necessarily <= original value).
 *  Number of bytes consumed can be < number of bytes provided.
 *  It typically happens when dstBuffer is not large enough to contain all decoded data.
 *  Unconsumed source data must be presented again in subsequent invocations.
 *
 * `dstBuffer` content is expected to be flushed between each invocation, as its content will be overwritten.
 * `dstBuffer` itself can be changed at will between each consecutive function invocation.
 *
 * @return : an hint of how many `srcSize` bytes LZ4F_decompress() expects for next call.
 *  Schematically, it's the size of the current (or remaining) compressed block + header of next block.
 *  Respecting the hint provides some small speed benefit, because it skips intermediate buffers.
 *  This is just a hint though, it's always possible to provide any srcSize.
 *  When a frame is fully decoded, @return will be 0 (no more data expected).
 *  If decompression failed, @return is an error code, which can be tested using LZ4F_isError().
 *
 *  After a frame is fully decoded, dctx can be used again to decompress another frame.
 *  After a decompression error, use LZ4F_resetDecompressionContext() before re-using dctx, to return to clean state.
 */
LZ4FLIB_API size_t LZ4F_decompress(LZ4F_dctx* dctx,
                                   void* dstBuffer, size_t* dstSizePtr,
                                   const void* srcBuffer, size_t* srcSizePtr,
                                   const LZ4F_decompressOptions_t* dOptPtr);


/*! LZ4F_resetDecompressionContext() : v1.8.0
 *  In case of an error, the context is left in "undefined" state.
 *  In which case, it's necessary to reset it, before re-using it.
 *  This method can also be used to abruptly stop an unfinished decompression,
 *  and start a new one using the same context. */
LZ4FLIB_API void LZ4F_resetDecompressionContext(LZ4F_dctx* dctx);   /* always successful */



#if defined (__cplusplus)
}
#endif

#endif  /* LZ4F_H_09782039843 */
