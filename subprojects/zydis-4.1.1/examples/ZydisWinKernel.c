/***************************************************************************************************

  Zyan Disassembler Engine (Zydis)

  Original Author : Matthijs Lavrijsen

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
 * Windows kernel mode driver sample.
 *
 * This is a Windows kernel mode driver. It links against the kernel mode-compatible version of Zydis.
 * The driver finds its own entry point and decodes and prints the disassembly of this function.
 * To view the log, either attach a kernel debugger or use a tool like Sysinternals DebugView.
 */

#include <wdm.h>
#include <ntimage.h>
#include <stdio.h>
#include <stdarg.h>
#include "Zydis/Zydis.h"

/* ============================================================================================== */
/* Forward declarations                                                                           */
/* ============================================================================================== */

NTKERNELAPI
PVOID
NTAPI
RtlPcToFileHeader(
    _In_ PVOID PcValue,
    _Out_ PVOID *BaseOfImage
    );

NTKERNELAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
    _In_ PVOID ImageBase
    );

#if defined(ZYAN_CLANG) || defined(ZYAN_GNUC)
__attribute__((section("INIT")))
#endif
DRIVER_INITIALIZE
DriverEntry;

#if defined(ALLOC_PRAGMA) && !(defined(ZYAN_CLANG) || defined(ZYAN_GNUC))
#pragma alloc_text(INIT, DriverEntry)
#endif

/* ============================================================================================== */
/* Helper functions                                                                               */
/* ============================================================================================== */

VOID
Print(
    _In_ PCCH Format,
    _In_ ...
    )
{
    CHAR message[512];
    va_list argList;
    va_start(argList, Format);
    const int n = _vsnprintf_s(message, sizeof(message), sizeof(message) - 1, Format, argList);
    message[n] = '\0';
    vDbgPrintExWithPrefix("[ZYDIS] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, message, argList);
    va_end(argList);
}

/* ============================================================================================== */
/* Entry point                                                                                    */
/* ============================================================================================== */

_Use_decl_annotations_
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(RegistryPath);

    if (ZydisGetVersion() != ZYDIS_VERSION)
    {
        Print("Invalid zydis version\n");
        return STATUS_UNKNOWN_REVISION;
    }

    // Get the driver's image base and PE headers
    ULONG_PTR imageBase;
    RtlPcToFileHeader((PVOID)DriverObject->DriverInit, (PVOID*)&imageBase);
    if (imageBase == 0)
        return STATUS_DRIVER_ENTRYPOINT_NOT_FOUND;
    const PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader((PVOID)imageBase);
    if (ntHeaders == NULL)
        return STATUS_INVALID_IMAGE_FORMAT;

    // Get the section headers of the INIT section
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    PIMAGE_SECTION_HEADER initSection = NULL;
    for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
    {
        if (memcmp(section->Name, "INIT", sizeof("INIT") - 1) == 0)
        {
            initSection = section;
            break;
        }
        section++;
    }
    if (initSection == NULL)
        return STATUS_NOT_FOUND;

    // Get the RVAs of the entry point and import directory. If the import directory lies within the INIT section,
    // stop disassembling when its address is reached. Otherwise, disassemble until the end of the INIT section.
    const ULONG entryPointRva = (ULONG)((ULONG_PTR)DriverObject->DriverInit - imageBase);
    const ULONG importDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    SIZE_T length = initSection->VirtualAddress + initSection->SizeOfRawData - entryPointRva;
    if (importDirRva > entryPointRva && importDirRva > initSection->VirtualAddress &&
        importDirRva < initSection->VirtualAddress + initSection->SizeOfRawData)
        length = importDirRva - entryPointRva;

    Print("Driver image base: 0x%p, size: 0x%X\n", (PVOID)imageBase, ntHeaders->OptionalHeader.SizeOfImage);
    Print("Entry point RVA: 0x%X (0x%p)\n", entryPointRva, DriverObject->DriverInit);

    // Initialize Zydis decoder and formatter
    ZydisDecoder decoder;
#ifdef _M_AMD64
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
#else
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32)))
#endif
        return STATUS_DRIVER_INTERNAL_ERROR;

    ZydisFormatter formatter;
    if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
        return STATUS_DRIVER_INTERNAL_ERROR;

    SIZE_T readOffset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZyanStatus status;
    CHAR printBuffer[128];

    // Start the decode loop
    while ((status = ZydisDecoderDecodeFull(&decoder, 
        (PVOID)(imageBase + entryPointRva + readOffset), length - readOffset, &instruction,
        operands)) != ZYDIS_STATUS_NO_MORE_DATA)
    {
        NT_ASSERT(ZYAN_SUCCESS(status));
        if (!ZYAN_SUCCESS(status))
        {
            readOffset++;
            continue;
        }

        // Format and print the instruction
        const ZyanU64 instrAddress = (ZyanU64)(imageBase + entryPointRva + readOffset);
        ZydisFormatterFormatInstruction(
            &formatter, &instruction, operands, instruction.operand_count_visible, printBuffer, 
            sizeof(printBuffer), instrAddress, NULL);
        Print("+%-4X 0x%-16llX\t\t%hs\n", (ULONG)readOffset, instrAddress, printBuffer);

        readOffset += instruction.length;
    }

    // Return an error status so that the driver does not have to be unloaded after running.
    return STATUS_UNSUCCESSFUL;
}

/* ============================================================================================== */
