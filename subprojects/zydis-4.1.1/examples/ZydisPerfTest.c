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

#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <Zycore/API/Terminal.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>

#if defined(ZYAN_WINDOWS)
#   include <windows.h>
#elif defined(ZYAN_APPLE)
#   include <mach/mach_time.h>
#elif defined(ZYAN_LINUX) || defined(ZYAN_SOLARIS)
#   include <sys/time.h>
#   include <pthread.h>
#elif defined(ZYAN_FREEBSD)
#   include <sys/time.h>
#   include <pthread.h>
#   include <pthread_np.h>
#else
#   error "Unsupported platform detected"
#endif

/* ============================================================================================== */
/* Colors                                                                                         */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* Configuration                                                                                  */
/* ---------------------------------------------------------------------------------------------- */

#define COLOR_DEFAULT       ZYAN_VT100SGR_FG_DEFAULT
#define COLOR_ERROR         ZYAN_VT100SGR_FG_BRIGHT_RED
#define COLOR_VALUE_R       ZYAN_VT100SGR_FG_BRIGHT_RED
#define COLOR_VALUE_G       ZYAN_VT100SGR_FG_BRIGHT_GREEN
#define COLOR_VALUE_B       ZYAN_VT100SGR_FG_CYAN

/* ---------------------------------------------------------------------------------------------- */
/* Global variables                                                                               */
/* ---------------------------------------------------------------------------------------------- */

static ZyanBool g_vt100_stdout;
static ZyanBool g_vt100_stderr;

/* ---------------------------------------------------------------------------------------------- */
/* Helper macros                                                                                  */
/* ---------------------------------------------------------------------------------------------- */

/**
 * Conditionally expands to the passed VT100 sequence, if `g_colors_stdout` is
 * `ZYAN_TRUE`, or an empty string, if not.
 *
 * @param   The VT100 SGT sequence.
 */
#define CVT100_OUT(sequence) (g_vt100_stdout ? (sequence) : "")

/**
 * Conditionally expands to the passed VT100 sequence, if `g_colors_stderr` is
 * `ZYAN_TRUE`, or an empty string, if not.
 *
 * @param   The VT100 SGT sequence.
 */
#define CVT100_ERR(sequence) (g_vt100_stderr ? (sequence) : "")

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */
/* Helper functions                                                                               */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* Time measurement                                                                               */
/* ---------------------------------------------------------------------------------------------- */

#if defined(ZYAN_WINDOWS)

double  counter_freq  = 0.0;
ZyanU64 counter_start = 0;

static void StartCounter(void)
{
    LARGE_INTEGER li;
    if (!QueryPerformanceFrequency(&li))
    {
        ZYAN_FPRINTF(ZYAN_STDERR, "%sError: QueryPerformanceFrequency failed!%s\n",
            CVT100_ERR(COLOR_ERROR), CVT100_ERR(ZYAN_VT100SGR_RESET));
        exit(EXIT_FAILURE);
    }
    counter_freq = (double)li.QuadPart / 1000.0;
    QueryPerformanceCounter(&li);
    counter_start = li.QuadPart;
}

static double GetCounter(void)
{
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return (double)(li.QuadPart - counter_start) / counter_freq;
}

#elif defined(ZYAN_APPLE)

ZyanU64 counter_start = 0;
mach_timebase_info_data_t timebase_info;

static void StartCounter(void)
{
    counter_start = mach_absolute_time();
}

static double GetCounter(void)
{
    ZyanU64 elapsed = mach_absolute_time() - counter_start;

    if (timebase_info.denom == 0)
    {
        mach_timebase_info(&timebase_info);
    }

    return (double)elapsed * timebase_info.numer / timebase_info.denom / 1000000;
}

#elif defined(ZYAN_LINUX) || defined(ZYAN_FREEBSD) || defined(ZYAN_SOLARIS)

struct timeval t1;

static void StartCounter(void)
{
    gettimeofday(&t1, NULL);
}

static double GetCounter(void)
{
    struct timeval t2;
    gettimeofday(&t2, NULL);

    double t = (t2.tv_sec - t1.tv_sec) * 1000.0;
    return t + (t2.tv_usec - t1.tv_usec) / 1000.0;
}

#endif

/* ---------------------------------------------------------------------------------------------- */
/* Process & Thread Priority                                                                      */
/* ---------------------------------------------------------------------------------------------- */

static void AdjustProcessAndThreadPriority(void)
{
#if defined(ZYAN_WINDOWS)

    SYSTEM_INFO info;
    GetSystemInfo(&info);
    if (info.dwNumberOfProcessors > 1)
    {
        if (!SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1))
        {
            ZYAN_FPRINTF(ZYAN_STDERR, "%sWarning: Could not set thread affinity mask%s\n",
                CVT100_ERR(ZYAN_VT100SGR_FG_YELLOW), CVT100_ERR(ZYAN_VT100SGR_RESET));
        }
        if (!SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS))
        {
            ZYAN_FPRINTF(ZYAN_STDERR, "%sWarning: Could not set process priority class%s\n",
                CVT100_ERR(ZYAN_VT100SGR_FG_YELLOW), CVT100_ERR(ZYAN_VT100SGR_RESET));
        }
        if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL))
        {
            ZYAN_FPRINTF(ZYAN_STDERR, "%sWarning: Could not set thread priority class%s\n",
                CVT100_ERR(ZYAN_VT100SGR_FG_YELLOW), CVT100_ERR(ZYAN_VT100SGR_RESET));
        }
    }

#elif defined(ZYAN_LINUX) || defined(ZYAN_FREEBSD)

    pthread_t thread = pthread_self();

#if defined(ZYAN_LINUX)
    cpu_set_t cpus;
#else  // FreeBSD
    cpuset_t cpus;
#endif

    CPU_ZERO(&cpus);
    CPU_SET(0, &cpus);
    if (pthread_setaffinity_np(thread, sizeof(cpus), &cpus))
    {
        ZYAN_FPRINTF(ZYAN_STDERR, "%sWarning: Could not set thread affinity mask%s\n",
            CVT100_ERR(ZYAN_VT100SGR_FG_YELLOW), CVT100_ERR(ZYAN_VT100SGR_RESET));
    }

#endif
}

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */
/* Internal functions                                                                             */
/* ============================================================================================== */

typedef struct TestContext_
{
    ZydisDecoderContext context;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    char format_buffer[256];
    ZyanBool minimal_mode;
    ZyanBool format;
    ZyanBool tokenize;
} TestContext;

static ZyanU64 ProcessBuffer(const ZydisDecoder* decoder, const ZydisFormatter* formatter,
    TestContext* context, const ZyanU8* buffer, ZyanUSize length)
{
    ZyanU64 count = 0;
    ZyanUSize offset = 0;
    ZyanStatus status;

    while (length > offset)
    {
        status = ZydisDecoderDecodeInstruction(decoder, &context->context, buffer + offset,
            length - offset, &context->instruction);

        if (status == ZYDIS_STATUS_NO_MORE_DATA)
        {
            break;
        }
        if (!context->minimal_mode && ZYAN_SUCCESS(status))
        {
            status = ZydisDecoderDecodeOperands(decoder, &context->context, &context->instruction,
                context->operands, context->instruction.operand_count);
        }
        if (!ZYAN_SUCCESS(status))
        {
            ZYAN_FPRINTF(ZYAN_STDERR, "%sUnexpected decoding error. Data: ",
                CVT100_ERR(COLOR_ERROR));
            for (ZyanUSize i = 0; i < ZYAN_MIN(ZYDIS_MAX_INSTRUCTION_LENGTH,
                length - offset); ++i)
            {
                ZYAN_FPRINTF(ZYAN_STDERR, "%02X ", (ZyanU8)buffer[offset + i]);
            }
            ZYAN_FPRINTF(ZYAN_STDERR, "%s\n", CVT100_ERR(ZYAN_VT100SGR_RESET));
            ZYAN_ASSERT(ZYAN_FALSE);
            exit(EXIT_FAILURE);
        }

        if (context->format)
        {
            if (context->tokenize)
            {
                const ZydisFormatterToken* token;
                ZydisFormatterTokenizeInstruction(formatter, &context->instruction,
                    context->operands, context->instruction.operand_count_visible, 
                    context->format_buffer, sizeof(context->format_buffer), offset, &token,
                    ZYAN_NULL);
            } else
            {
                ZydisFormatterFormatInstruction(formatter, &context->instruction,
                    context->operands, context->instruction.operand_count_visible, 
                    context->format_buffer, sizeof(context->format_buffer), offset, ZYAN_NULL);
            }
        }

        offset += context->instruction.length;
        ++count;
    }

    return count;
}

static void TestPerformance(const ZyanU8* buffer, ZyanUSize length, ZyanBool minimal_mode,
    ZyanBool format, ZyanBool tokenize, ZyanBool use_cache)
{
    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64)))
    {
        ZYAN_FPRINTF(ZYAN_STDERR, "%sFailed to initialize decoder%s\n",
            CVT100_ERR(COLOR_ERROR), CVT100_ERR(ZYAN_VT100SGR_RESET));
        exit(EXIT_FAILURE);
    }
    if (!ZYAN_SUCCESS(ZydisDecoderEnableMode(&decoder, ZYDIS_DECODER_MODE_MINIMAL, minimal_mode)))
    {
        ZYAN_FPRINTF(ZYAN_STDERR, "%sFailed to adjust decoder-mode%s\n",
            CVT100_ERR(COLOR_ERROR), CVT100_ERR(ZYAN_VT100SGR_RESET));
        exit(EXIT_FAILURE);
    }

    // ZydisCacheTable cache;
    // if (use_cache && !ZYAN_SUCCESS(ZydisDecoderInitCache(&decoder, &cache)))
    // {
    //     ZYAN_FPRINTF(ZYAN_STDERR, "%sFailed to initialize decoder-cache%s\n",
    //         CVT100_ERR(COLOR_ERROR), CVT100_ERR(ZYAN_VT100SGR_RESET));
    //     exit(EXIT_FAILURE);
    // }

    ZydisFormatter formatter;
    if (format)
    {
        if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)) ||
            !ZYAN_SUCCESS(ZydisFormatterSetProperty(&formatter,
                ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE)) ||
            !ZYAN_SUCCESS(ZydisFormatterSetProperty(&formatter,
                ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE)))
        {
            ZYAN_FPRINTF(ZYAN_STDERR, "%sFailed to initialize instruction-formatter%s\n",
                CVT100_ERR(COLOR_ERROR), CVT100_ERR(ZYAN_VT100SGR_RESET));
            exit(EXIT_FAILURE);
        }
    }

    TestContext context;
    context.minimal_mode = minimal_mode;
    context.format = format;
    context.tokenize = tokenize;

    // Cache warmup
    ProcessBuffer(&decoder, &formatter, &context, buffer, length);

    // Testing
    ZyanU64 count = 0;
    StartCounter();
    for (ZyanU8 j = 0; j < 100; ++j)
    {
        count += ProcessBuffer(&decoder, &formatter, &context, buffer, length);
    }
    const char* color[4];
    color[0] = minimal_mode ? CVT100_OUT(COLOR_VALUE_G) : CVT100_OUT(COLOR_VALUE_B);
    color[1] = format       ? CVT100_OUT(COLOR_VALUE_G) : CVT100_OUT(COLOR_VALUE_B);
    color[2] = tokenize     ? CVT100_OUT(COLOR_VALUE_G) : CVT100_OUT(COLOR_VALUE_B);
    color[3] = use_cache    ? CVT100_OUT(COLOR_VALUE_G) : CVT100_OUT(COLOR_VALUE_B);
    ZYAN_PRINTF("Minimal-Mode %s%d%s, Format %s%d%s, Tokenize %s%d%s, Caching %s%d%s, " \
        "Instructions: %s%6.2fM%s, Time: %s%8.2f%s msec\n",
        color[0], minimal_mode, CVT100_OUT(COLOR_DEFAULT),
        color[1], format, CVT100_OUT(COLOR_DEFAULT),
        color[2], tokenize, CVT100_OUT(COLOR_DEFAULT),
        color[3], use_cache, CVT100_OUT(COLOR_DEFAULT),
        CVT100_OUT(COLOR_VALUE_B), (double)count / 1000000, CVT100_OUT(COLOR_DEFAULT),
        CVT100_OUT(COLOR_VALUE_G), GetCounter(), CVT100_OUT(COLOR_DEFAULT));
}

static void GenerateTestData(FILE* file, ZyanU8 encoding)
{
    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
    {
        ZYAN_FPRINTF(ZYAN_STDERR, "%sFailed to initialize decoder%s\n", CVT100_ERR(COLOR_ERROR),
            CVT100_ERR(ZYAN_VT100SGR_RESET));
        exit(EXIT_FAILURE);
    }

    ZyanU8 last = 0;
    ZyanU32 count = 0;
    ZydisDecodedInstruction instruction;
    while (count < 100000)
    {
        ZyanU8 data[ZYDIS_MAX_INSTRUCTION_LENGTH];
        for (int i = 0; i < ZYDIS_MAX_INSTRUCTION_LENGTH; ++i)
        {
            data[i] = rand() % 256;
        }
        const ZyanU8 offset = rand() % (ZYDIS_MAX_INSTRUCTION_LENGTH - 2);
        switch (encoding)
        {
        case 0:
            break;
        case 1:
            data[offset    ] = 0x0F;
            data[offset + 1] = 0x0F;
            break;
        case 2:
            data[offset    ] = 0x8F;
            break;
        case 3:
            data[offset    ] = 0xC4;
            break;
        case 4:
            data[offset    ] = 0xC5;
            break;
        case 5:
        case 6:
            data[offset    ] = 0x62;
            break;
        default:
            ZYAN_UNREACHABLE;
        }
        if (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, ZYAN_NULL, data, 
            sizeof(data), &instruction)))
        {
            ZyanBool b = ZYAN_FALSE;
            switch (encoding)
            {
            case 0:
                b = (instruction.encoding == ZYDIS_INSTRUCTION_ENCODING_LEGACY);
                break;
            case 1:
                b = (instruction.encoding == ZYDIS_INSTRUCTION_ENCODING_3DNOW);
                break;
            case 2:
                b = (instruction.encoding == ZYDIS_INSTRUCTION_ENCODING_XOP);
                break;
            case 3:
            case 4:
                b = (instruction.encoding == ZYDIS_INSTRUCTION_ENCODING_VEX);
                break;
            case 5:
                b = (instruction.encoding == ZYDIS_INSTRUCTION_ENCODING_EVEX);
                break;
            case 6:
                b = (instruction.encoding == ZYDIS_INSTRUCTION_ENCODING_MVEX);
                break;
            default:
                ZYAN_UNREACHABLE;
            }
            if (b)
            {
                fwrite(&data[0], sizeof(ZyanU8), instruction.length, file);
                ++count;

                const ZyanU8 p = (ZyanU8)((double)count / 100000 * 100);
                if (last < p)
                {
                    last = p;
                    ZYAN_PRINTF("%3.0d%%\n", p);
                }
            }
        }
    }
}

/* ============================================================================================== */
/* Entry point                                                                                    */
/* ============================================================================================== */

int main(int argc, char** argv)
{
    // Enable VT100 escape sequences on Windows, if the output is not redirected
    g_vt100_stdout = (ZyanTerminalIsTTY(ZYAN_STDSTREAM_OUT) == ZYAN_STATUS_TRUE) &&
                     ZYAN_SUCCESS(ZyanTerminalEnableVT100(ZYAN_STDSTREAM_OUT));
    g_vt100_stderr = (ZyanTerminalIsTTY(ZYAN_STDSTREAM_ERR) == ZYAN_STATUS_TRUE) &&
                     ZYAN_SUCCESS(ZyanTerminalEnableVT100(ZYAN_STDSTREAM_ERR));

    if (ZydisGetVersion() != ZYDIS_VERSION)
    {
        ZYAN_FPRINTF(ZYAN_STDERR, "%sInvalid zydis version%s\n",
            CVT100_ERR(COLOR_ERROR), CVT100_ERR(ZYAN_VT100SGR_RESET));
        return EXIT_FAILURE;
    }

    if (argc < 3 || (ZYAN_STRCMP(argv[1], "-test") && ZYAN_STRCMP(argv[1], "-generate")))
    {
        ZYAN_FPRINTF(ZYAN_STDERR, "%sUsage: %s -[test|generate] [directory]%s\n",
            CVT100_ERR(COLOR_ERROR), (argc > 0 ? argv[0] : "PerfTest"),
            CVT100_ERR(ZYAN_VT100SGR_RESET));
        return EXIT_FAILURE;
    }

    ZyanBool generate = ZYAN_FALSE;
    if (!ZYAN_STRCMP(argv[1], "-generate"))
    {
        generate = ZYAN_TRUE;
    }
    const char* directory = argv[2];

    static const struct
    {
        const char* encoding;
        const char* filename;
    } tests[7] =
    {
        { "DEFAULT", "enc_default.dat" },
        { "3DNOW"  , "enc_3dnow.dat"   },
        { "XOP"    , "enc_xop.dat"     },
        { "VEX_C4" , "enc_vex_c4.dat"  },
        { "VEX_C5" , "enc_vex_c5.dat"  },
        { "EVEX"   , "enc_evex.dat"    },
        { "MVEX"   , "enc_mvex.dat"    }
    };

    if (generate)
    {
        time_t t;
        srand((unsigned)time(&t));
    } else
    {
        AdjustProcessAndThreadPriority();
    }

    for (ZyanU8 i = 0; i < ZYAN_ARRAY_LENGTH(tests); ++i)
    {
        FILE* file;

        const ZyanUSize len = strlen(directory);
        char buf[1024];
        strncpy(&buf[0], directory, sizeof(buf) - 1);
        if (generate)
        {
            file = fopen(strncat(buf, tests[i].filename, sizeof(buf) - len - 1), "wb");
        } else
        {
            file = fopen(strncat(buf, tests[i].filename, sizeof(buf) - len - 1), "rb");
        }
        if (!file)
        {
            ZYAN_FPRINTF(ZYAN_STDERR, "%sCould not open file \"%s\": %s%s\n",
                CVT100_ERR(COLOR_ERROR), &buf[0], strerror(ZYAN_ERRNO),
                CVT100_ERR(ZYAN_VT100SGR_RESET));
            continue;
        }

        if (generate)
        {
            ZYAN_PRINTF("Generating %s%s%s ...\n", CVT100_OUT(COLOR_VALUE_B), tests[i].encoding,
                CVT100_OUT(ZYAN_VT100SGR_RESET));
            GenerateTestData(file, i);
        } else
        {
            fseek(file, 0L, SEEK_END);
            const long length = ftell(file);
            void* buffer = malloc(length);
            if (!buffer)
            {
                ZYAN_FPRINTF(ZYAN_STDERR,
                    "%sFailed to allocate %" PRIu64 " bytes on the heap%s\n",
                    CVT100_ERR(COLOR_ERROR), (ZyanU64)length, CVT100_ERR(ZYAN_VT100SGR_RESET));
                goto NextFile2;
            }

            rewind(file);
            if (fread(buffer, 1, length, file) != (ZyanUSize)length)
            {
                ZYAN_FPRINTF(ZYAN_STDERR,
                    "%sCould not read %" PRIu64 " bytes from file \"%s\"%s\n",
                    CVT100_ERR(COLOR_ERROR), (ZyanU64)length, &buf[0],
                    CVT100_ERR(ZYAN_VT100SGR_RESET));
                goto NextFile1;
            }

            ZYAN_PRINTF("%sTesting %s%s%s ...\n", CVT100_OUT(ZYAN_VT100SGR_FG_MAGENTA),
                CVT100_OUT(ZYAN_VT100SGR_FG_BRIGHT_MAGENTA), tests[i].encoding,
                CVT100_OUT(COLOR_DEFAULT));
            TestPerformance(buffer, length, ZYAN_TRUE , ZYAN_FALSE, ZYAN_FALSE, ZYAN_FALSE);
            TestPerformance(buffer, length, ZYAN_FALSE, ZYAN_FALSE, ZYAN_FALSE, ZYAN_FALSE);
            // TestPerformance(buffer, length, ZYAN_FALSE, ZYAN_FALSE, ZYAN_FALSE, ZYAN_TRUE);
            TestPerformance(buffer, length, ZYAN_FALSE, ZYAN_TRUE , ZYAN_FALSE, ZYAN_FALSE);
            // TestPerformance(buffer, length, ZYAN_FALSE, ZYAN_TRUE , ZYAN_FALSE, ZYAN_TRUE);
            TestPerformance(buffer, length, ZYAN_FALSE, ZYAN_TRUE , ZYAN_TRUE , ZYAN_FALSE);
            // TestPerformance(buffer, length, ZYAN_FALSE, ZYAN_TRUE , ZYAN_TRUE , ZYAN_TRUE);
            ZYAN_PUTS("");

        NextFile1:
            free(buffer);
        }

    NextFile2:
        fclose(file);
    }

    return 0;
}

/* ============================================================================================== */
