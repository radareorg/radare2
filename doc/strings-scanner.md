# Raw string scanner investigation

Keep the existing Unicode scanner as the default and develop charset decoding
that preserves source offsets behind a separate selector. The main obstacle is
the loss of source positions during whole-buffer conversion. Stronger text
heuristics cannot repair those positions or distinguish game control codes from
printable text.

The measurements below use radare2 commit `a6a4ee1fc2`, before the accompanying
fixes, on Linux AArch64 on 2026-10-19. The changes add charset selection and repair
three data-loss cases while preserving the existing detection heuristics.

## Current implementation

`libr/bin/bfile.c` owns range selection, buffer conversion, encoding detection,
candidate extraction, Unicode block filtering, address calculation and raw
printing. `r_bin_file_get_strings()` chooses data sections or the complete blob;
`string_scan_range()` copies each entire range into memory. Format plugins can
replace string extraction through `RBinPlugin.strings`.

`bin.str.enc` controls the Unicode interpretation. `RABIN2_CHARSET` previously
selected a muta conversion of the entire range before the Unicode scanner ran.
The conversion copied at most the original input length and reused decoded
positions as source positions. `libr/search/strings.c` is another scanner, but its
ASCII and CP850 detection is not a substitute for the bin scanner's Unicode
handling.

The new `bin.charset` setting takes precedence over `RABIN2_CHARSET`, followed by
`RBinInfo.charset`. The scanner reads plugin metadata directly, including for raw
scans and libr_bin callers. `bin.charset=none` bypasses conversion; an empty value
restores automatic selection. `bin.charset=?` lists available charset plugins.
The setting uses RBin's existing Sdb and introduces no public struct changes.

`cfg.charset` still configures raw-memory printing, and its existing callback
exports `RABIN2_CHARSET`. This compatibility behavior can affect later scans in
the same process; an explicit `bin.charset` overrides it. Charset selection does
not bypass a format plugin's own `strings` callback.

## Real binary measurements

Elapsed time is the median of seven complete `rabin2 -zzzq` invocations with
stdout redirected to `/dev/null`. RSS is the median peak resident memory from
GNU time, in KiB. This configured developer build includes process startup,
loading, scanning and rendering; these are not isolated scanner throughput
measurements. Counts come from the first JSON value produced by `-zzzj`.

| Input | Bytes | Charset | Candidates | Time ms | RSS KiB |
| --- | ---: | --- | ---: | ---: | ---: |
| `/bin/ls`, AArch64 ELF | 199464 | default | 1134 | 37.06 | 25600 |
| Pokémon Red | 1048576 | default | 10437 | 57.90 | 25728 |
| Pokémon Red | 1048576 | pokered | 1186 | 606.74 | 36432 |
| QEMU AArch64 UEFI firmware | 2097152 | default | 28441 | 114.25 | 27520 |
| `test/bins/elf/ls-s390x` | 159424 | default | 883 | 37.33 | 25472 |
| `test/bins/s390/zos/prueba/prueba` | 69632 | default | 97 | 27.66 | 24448 |
| Same z/OS executable | 69632 | ebcdic37 | 997 | 28.62 | 24576 |

Counts describe candidates, not precision or recall. The firmware is the installed
`/usr/share/qemu-efi-aarch64/QEMU_EFI.fd`; the corpus's mostly zero-filled
`firmware/bios_*.bin` fixtures are not representative firmware samples.

Pokémon Red was built from
[pret/pokered](https://github.com/pret/pokered/tree/af519899719f0754965776faac0e836a3b906e6d)
with RGBDS commit `d766efe95d82f0d64dd95dece60b7681c7a14de9` and
`make -j2 DEBUG=1 RGBDS=/path/to/rgbds/ red`. The resulting SHA-1 is
`ea9bcae617fdf159b045185467ae58b2e4a48b9a`, matching the project's reference
[ROM hash](https://github.com/pret/pokered/blob/af519899719f0754965776faac0e836a3b906e6d/README.md).
The symbol file supplies independent source offsets.

Concrete examples:

- `/bin/ls` contains the real usage message at `0x19c40`, but also produces
  `@8\\t@` at `0x34`. Those bytes are ELF header size and count fields, giving a
  definite false positive without assuming that unusual language is junk.
- The firmware contains `UEFI firmware (version %s built at %a on %a)` at
  `0x53d2`. Its other candidates need labels before any precision claim.
- The s390 Linux ELF contains its usage message at `0x1aad8`. Its architecture
  does not imply EBCDIC. The z/OS executable requires `ebcdic37` to recover
  `Hola mundo` at `0x19a8`, consistent with its accompanying C source.
- In Pokémon Red, `MonsterNames` begins at source offset `0x1c21e`; after muta
  conversion it begins at decoded offset `0x6d050`. The scanner merges names
  into a large candidate starting at reported offset `0x6ce18`.
- `_OaksLabYouWantCharmanderText` begins at source offset `0x94e06`, but maps to
  decoded offset `0x242b67`. The conversion keeps only `0x100000` output bytes,
  so this dialogue disappears before scanning. The slower charset run therefore
  does not even cover all the source text.

## Surgical fixes

Each change has its own commit and validation:

- Remove the extra cursor increment after rejecting a candidate with more than
  four Unicode blocks. Previously `aéΩЖ中\0TEST\0` lost `TEST`, and replacing it
  with `HELLO` yielded `ELLO` at the wrong address.
- Share escape emission between normal and `bin.str.nofp` scanning. Previously
  nofp counted accepted tabs, newlines and backslashes but omitted their text.
- Remove the ASCII filtering loop whose body had no effect. Raw JSON output is
  byte-for-byte identical across all five binary specimens before and after
  this deletion. Optimized compilers may already eliminate the loop.
- Add `bin.charset`, environment compatibility and direct plugin-default
  selection, with command and API tests for precedence.
- Remove replacement of every decoded question mark with NUL. A genuine
  EBCDIC `HELLO?WORLD` previously became two separate strings. Replacement
  glyphs cannot identify invalid input reliably.
- Allow `bin.charset=none` so users can retain the original Unicode scan even
  when environment or plugin defaults specify a charset.

## Remaining confirmed problems

1. **Conversion loses provenance and truncates text.** The Pokémon offsets above
   demonstrate both failures. `cyrillic.win` conversion of CP1251 `Привет`, NUL
   and `HELLO` also loses the final word. Its replacement for NUL is printable,
   so changing buffer length alone would still merge strings.
2. **Charset output is not uniformly UTF-8.** `r_muta_charset_tr_decode()` and
   `r_muta_charset_tr_update()` emit table bytes directly. `ebcdic37` therefore
   works for the ASCII subset but its high bytes are not UTF-8 text for the
   following scanner. EBCDIC `café café` loses the accented characters.
3. **Game text needs control semantics.** The
   [canonical Gen 1 charmap](https://github.com/pret/pokered/blob/af519899719f0754965776faac0e836a3b906e6d/constants/charmap.asm)
   defines `0x50` as a string terminator and `0x7f` as space. The current pokered
   plugin renders them as `@` and `-`, renders NUL as `<NULL>`, maps `0xe0` to
   `é` instead of apostrophe, and escapes unsupported bytes into printable
   `\xNN` text. These representations create candidates from non-text and merge
   otherwise separate names. Dialogue also has line and end control codes.
4. **Explicit encodings remain incomplete.** Configuration accepts `utf16be`
   and `utf32be`, but `get_strings_range()` rejects them. `latin1` still goes
   through UTF-8 decoding. Even explicit UTF-16LE scans first require a valid
   UTF-8 byte sequence at the candidate start: `香港测试` is missed entirely.
5. **Unicode quality heuristics discard valid text.** The four-block cap applies
   even with nofp disabled. The UTF-16 ASCII-frequency retry can reject mixed
   text independently of the encoding selection: UTF-16LE `Hello world Привет`
   becomes `Hello world` followed by unrelated CJK text at odd source offset 25.
   Separately, the surrogate-pair bit shifts in `r_utf16_decode()` do not
   reconstruct Unicode supplementary
   characters correctly; `Hello 😀 world` is split around the emoji.
6. **Limits and output paths differ.** The candidate loop increments its length
   limit using a variable overwritten by UTF-8 encoding and escape emission,
   rather than consistently counting input bytes or characters. Minimum length
   is checked before trimming: four spaces can yield an empty result. The raw
   dump path does not run the same presentation filters as `_print_strings()`.
   `rabin2 -zzzj` also emits a trailing `{}` after the candidate array.

Performance costs beyond the ineffective ASCII loop are whole-range input
copies, whole-range decoded output, a copied muta result, and another input-sized
copy for scanning. Unicode block classification decodes candidates again and
allocates arrays sized by text length. Table-backed charset decoding linearly
searches all entries for each source position. Those costs are visible in the
Pokémon run, but a profile is needed to attribute their individual shares.

## Proposed experimental implementation

Start with an internal `bin.str.scan=legacy|experimental` selector, defaulting to
`legacy`. Keep the legacy scanner's heuristics in place. Implement the alternate
range scanner independently, sharing address calculation and result emission
where practical. Third-party scanner registration can follow a working internal
interface and the project's ABI rules.

The experimental decoder should accept bounded source bytes and return consumed
source bytes, produced UTF-8 bytes and a status: text, separator, invalid input or
incomplete input. Preserve decoder state across chunks. Treat invalid bytes and
terminators as boundaries instead of creating replacement text for detection.
Make Pokémon line breaks, end markers and runtime substitutions explicit tokens.

Track source start and end positions separately from UTF-8 length and character
count. Build `paddr`, `vaddr` and `size` from source positions. Bound input and
output sizes independently. Use chunked reads with a pending candidate and
decoder lookahead so strings crossing chunk boundaries are neither lost nor
duplicated. Compile single-byte maps into direct lookups; use indexed prefix
matching for variable-length maps.

Reuse muta's mapping data, but first define a consistent decoding contract.
Existing `.decode` callbacks allocate output, are absent from many table plugins,
and do not all mean one character: `seven` can consume an entire supplied buffer.
The update and decode interfaces also differ in their treatment of unknown bytes.
Calling either interface blindly would carry the current bugs into a new engine.

Keep candidate extraction separate from confidence scoring. Preserve decodable
candidates by default, with optional ranking and explanations for suspicious
results. Learn thresholds from labeled examples rather than a universal script
count or ASCII ratio. Chinese and Cyrillic strings, mixed scripts, filenames and
format strings need independent coverage. Add multi-charset selection only with
per-result charset provenance and an explicit overlap policy.

## Reproduction and acceptance checks

Build with `make -j2` and use this checkout's executables, libraries and plugins
as described in [Regression testing](../DEVELOPERS.md#regression-testing).
For the real samples, use:

```sh
rabin2 -zzzj /bin/ls
rabin2 -zzzj /usr/share/qemu-efi-aarch64/QEMU_EFI.fd
rabin2 -zzzj test/bins/elf/ls-s390x
RABIN2_CHARSET=ebcdic37 rabin2 -zzzj test/bins/s390/zos/prueba/prueba
RABIN2_CHARSET=pokered rabin2 -zzzj /path/to/pokered.gbc
r2 -e bin.charset=ebcdic37 -qc izzj test/bins/s390/zos/prueba/prueba
```

The targeted regression command is:

```sh
r2r -C test db/cmd/cmd_print_strings db/cmd/charset db/formats/elf/strings
```

All 27 targeted command tests and all 17 `test_bin` unit tests pass after the
patches, following root builds with `make -j2`. The unit suite checks plugin
charset fallback without core settings and an explicit override. An experimental
scanner additionally needs assertions against Pokémon symbols and text sources,
z/OS source text, the known ELF header
negative, accented EBCDIC, CP1251, both Unicode byte orders, supplementary
characters, malformed input, separators, and every possible chunk split of a
multibyte character. Measure precision and recall separately on these labels.

Sample SHA-256 values, in table order with duplicate inputs omitted:

```text
ls       fd9344759be2490eb7f1053ac1bb52924bc54695c420a973b9875bb60863d427
pokemon  5ca7ba01642a3b27b0cc0b5349b52792795b62d3ed977e98a09390659af96b7b
uefi     d2d1228a664adbaed2148c2661e30c930af9bf09f03b6d5aa2a8bbc9cb5cab43
s390elf  16da5f459c93d04d7bf36bcfec30c4606198e9a74401f09ff1625065b84813fb
zos      3c43af433c5f039b5b246bd1e8238b957f86907d73c894bd45e38e0f575d808e
```
