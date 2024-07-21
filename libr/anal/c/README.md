# TinyCC

This is a stripped down version of tcc 0.9.26 without the code and binary generators.

So, we only use the C parser for loading structures, enums and function signatures into r2.

The main interop function is `tcc_appendf()` and it appends sdb queries to be executed from the r2 core.

This code is licensed under the LGPLv2.
