## Readme

This directory contains MSVC project files to build Zydis and the included tools and examples.

There are five build configurations, each with 32/64 bit and debug/release versions:
- Static with dynamic run-time library (MD)
- Static with static run-time library (MT)
- Dynamic (DLL) with dynamic run-time library (MD)
- Dynamic (DLL) with static run-time library (MT)
- Kernel mode

In order to build the kernel mode configuration you must have the Microsoft WDK installed, available at https://developer.microsoft.com/en-us/windows/hardware/windows-driver-kit.
The kernel mode configuration only builds `Zydis` and the `ZydisWinKernel` driver sample. The other configurations build all projects except for `ZydisWinKernel`.

NOTE: If you already have the WDK installed, make sure it is updated to at least the Windows 10 1709 version (10.0.16299.0) in order to prevent issues opening the solution file. This is due to a bug in older WDK toolsets.

All Zydis features are enabled by default. In order to disable specific features you can define preprocessor directives such as `ZYDIS_DISABLE_FORMATTER`. Refer to `CMakeLists.txt` for the full list of feature switches.
