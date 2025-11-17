/***************************************************************************************************

  Zyan Disassembler Library (Zydis)

  Original Author : Florian Bernd

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.

***************************************************************************************************/

/**
 * @file
 * Master include file. Includes everything else.
 */

#ifndef ZYDIS_H
#define ZYDIS_H

#include <Zycore/Defines.h>
#include <Zycore/Types.h>

#if !defined(ZYDIS_DISABLE_DECODER)
#   include <Zydis/Decoder.h>
#   include <Zydis/DecoderTypes.h>
#endif

#if !defined(ZYDIS_DISABLE_ENCODER)
#   include <Zydis/Encoder.h>
#endif

#if !defined(ZYDIS_DISABLE_FORMATTER)
#   include <Zydis/Formatter.h>
#endif

#if !defined(ZYDIS_DISABLE_SEGMENT)
#   include <Zydis/Segment.h>
#endif

#if !defined(ZYDIS_DISABLE_DECODER) && !defined(ZYDIS_DISABLE_FORMATTER)
#   include <Zydis/Disassembler.h>
#endif

#include <Zydis/MetaInfo.h>
#include <Zydis/Mnemonic.h>
#include <Zydis/Register.h>
#include <Zydis/SharedTypes.h>
#include <Zydis/Status.h>
#include <Zydis/Utils.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup version Version
 *
 * Functions for checking the library version and build options.
 *
 * @{
 */

/* ============================================================================================== */
/* Macros                                                                                         */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* Constants                                                                                      */
/* ---------------------------------------------------------------------------------------------- */

/**
 * A macro that defines the zydis version.
 */
#define ZYDIS_VERSION 0x0004000100000000ULL

/* ---------------------------------------------------------------------------------------------- */
/* Helper macros                                                                                  */
/* ---------------------------------------------------------------------------------------------- */

/**
 * Extracts the major-part of the zydis version.
 *
 * @param   version The zydis version value
 */
#define ZYDIS_VERSION_MAJOR(version) (((version) & 0xFFFF000000000000) >> 48)

/**
 * Extracts the minor-part of the zydis version.
 *
 * @param   version The zydis version value
 */
#define ZYDIS_VERSION_MINOR(version) (((version) & 0x0000FFFF00000000) >> 32)

/**
 * Extracts the patch-part of the zydis version.
 *
 * @param   version The zydis version value
 */
#define ZYDIS_VERSION_PATCH(version) (((version) & 0x00000000FFFF0000) >> 16)

/**
 * Extracts the build-part of the zydis version.
 *
 * @param   version The zydis version value
 */
#define ZYDIS_VERSION_BUILD(version) ((version) & 0x000000000000FFFF)

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */
/* Enums and types                                                                                */
/* ============================================================================================== */

/**
 * Defines the `ZydisFeature` enum.
 */
typedef enum ZydisFeature_
{
    ZYDIS_FEATURE_DECODER,
    ZYDIS_FEATURE_ENCODER,
    ZYDIS_FEATURE_FORMATTER,
    ZYDIS_FEATURE_AVX512,
    ZYDIS_FEATURE_KNC,
    ZYDIS_FEATURE_SEGMENT,

    /**
     * Maximum value of this enum.
     */
    ZYDIS_FEATURE_MAX_VALUE = ZYDIS_FEATURE_SEGMENT,
    /**
     * The minimum number of bits required to represent all values of this enum.
     */
    ZYDIS_FEATURE_REQUIRED_BITS = ZYAN_BITS_TO_REPRESENT(ZYDIS_FEATURE_MAX_VALUE)
} ZydisFeature;

/* ============================================================================================== */
/* Exported functions                                                                             */
/* ============================================================================================== */

/**
 * Returns the zydis version.
 *
 * @return  The zydis version.
 *
 * Use the macros provided in this file to extract the major, minor, patch and build part from the
 * returned version value.
 */
ZYDIS_EXPORT ZyanU64 ZydisGetVersion(void);

/**
 * Checks, if the specified feature is enabled in the current zydis library instance.
 *
 * @param   feature The feature.
 *
 * @return  `ZYAN_STATUS_TRUE` if the feature is enabled, `ZYAN_STATUS_FALSE` if not. Another
 *          zyan status code, if an error occured.
 */
ZYDIS_EXPORT ZyanStatus ZydisIsFeatureEnabled(ZydisFeature feature);

/* ============================================================================================== */

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* ZYDIS_H */
