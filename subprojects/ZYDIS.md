Zydis
=====

The x86_zydis arch plugin builds against the Zydis disassembler. The sources are
vendored in-tree under `subprojects/zydis/amalgamated-dist`, so no wrap file and
no network access are needed: both the acr (`subprojects/zydis.mk`) and the meson
(`subprojects/zydis/meson.build`) builds compile that single translation unit.

Bundled version
---------------

There is no 5.x release tagged upstream yet: the newest tag is v4.1.1, from
2025. We track a snapshot of the 5.0.0 development branch instead, for the APX
(REX2/EEVEX) decoding and the reworked `ZydisShortString` that 4.x lacks:

	https://github.com/zyantific/zydis
	commit a95bb71013436547f689fc0b380f48edf663066e (2026-07-27)
	bundled zycore: 75a36c45ae1ad382b0f4e0ede0af84c11ee69928 (v1.5.2-7)

Upgrading
---------

	git clone --recursive https://github.com/zyantific/zydis
	cd zydis && git checkout <commit> && git submodule update --recursive
	python3 assets/amalgamate.py
	cp amalgamated-dist/Zydis.[ch] .../subprojects/zydis/amalgamated-dist

Then update the commit hashes above, bump the version in
`subprojects/zydis/meson.build` and re-run the `arch/x86_zydis` tests: the
`ZydisMnemonic` enum is generated, so the `id` field in `test/db/anal/x86_zydis`
shifts whenever upstream adds instructions.

The amalgamated files are kept byte-identical to the generator output, so we
ship no patches against them. Any local change would have to be minimal and
listed in this file. The previous `unused-rex-token-aliases.patch` is gone: it
silenced `-Wunused-const-variable` on the `TOK_PREF_REX_*` aliases, which
upstream has since removed.

Notes for upstream
------------------

Cosmetic issues observed in the current snapshot. They do not affect radare2 and
are deliberately not patched here, but are worth reporting upstream:

* `Zydis.h`: `ZydisEncoderRequest.evex.broadcast` is documented as "Specify
  `ZYDIS_BROADCAST_MODE_INVALID` for instructions with no EVEX broadcast", but
  the enum only has `ZYDIS_BROADCAST_MODE_NONE`; there is no `*_INVALID`
  constant.
* `Zydis.h`: typo "Supress" (single p) in the `ZydisEncoderRequest.apx.no_flags`
  documentation.
* `Zydis.c`: clang reports `ZydisStringAppendCase` as unused in the amalgamated
  build (`-Wunused-function`). Harmless, but it is the only warning the
  amalgamated TU produces with `-Wall`.

Also note that Zydis 4.1.0 defines `ZYDIS_VERSION` as `(ZyanU64)0x...`, so
`#if ZYDIS_VERSION >= ...` is a preprocessor syntax error against those headers.
This was fixed in 4.1.1, but `libr/arch/p/x86/plugin_zydis.c` still has to sniff
a real macro (`ZYDIS_ATTRIB_HAS_REX2`) instead of comparing versions, so that a
system-wide 4.1.0 keeps building.

License
-------

Zydis is distributed under the MIT license, see
`subprojects/zydis/LICENSE.MIT`.
