# ELF duplicate-symbol report — static analysis only (no build/run)

## What you see
`is` walks `bf->bo->symbols_vec` (`libr/core/cmd_info.inc.c:3246` → `libr/core/cbin.c:2929-2949`) and prints a row per element. `snprintf` appears several times with identical `paddr`, `vaddr`, `oname` (mangled) and demangled name, because that vector is assembled from several independent reads of the same ELF table and **nothing ever collapses identical entries**.

## Offending source lines

**1. The merge point — direct cause of the visible repeats** ⚠️
`libr/bin/p/bin_elf.inc.c:430-457` (`symbols_vec`):
```c
441  bf->bo->symbols_vec = eo->symbols_cache;      // transferred symbols
...
446  RVecRBinSymbol *plt_symbols = Elf_(load_plt_symbols_vec) (bf, eo);
449  R_VEC_FOREACH (plt_symbols, sym) {
450      RVecRBinSymbol_push_back (&bf->bo->symbols_vec, sym);   // <-- appended blindly
```
No check that the appended PLT/import symbol already exists in the vector.

**2. Producer of the appended copies**
`libr/bin/format/elf/elf.c:5723-5759` (`Elf_(load_plt_symbols_vec)`): emits one `RBinSymbol` for **every** entry of `eo->g_imports_vec` (line 5734 loop, 5752 push). Same names/addresses as entries already present.

**3. The import vector itself is a re-copy**
`libr/bin/format/elf/elf.c:5637-5651` (`load_imports`) → `5569-5635` (`load_symbols_from`) → `5324-5336` (`_load_additional_imported_symbols`):
```c
5324  R_VEC_FOREACH (ii->symbols_vec, symbol) { ... }
5336      RVecRBinElfSymbol_push_back (imports, symbol);   // clones already-parsed imports
```
So one import can be materialised more than once, and each copy becomes a PLT symbol in step 2.

**4. `.symtab` + `.dynsym` both processed**
`section_matters` `libr/bin/format/elf/elf.c:5259-5271` returns true for both; `load_symbols_from` loop `5592-5611` has no `break` for `R_BIN_ELF_ALL_SYMBOLS`. A name present in both tables is produced twice. (Imports get `is_sht_null = true` at `5489`/`4848` → skipped at `5671`, which is why the import re-enters through the PLT path instead.)

**5. phdr fallback re-append**
`Elf_(fix_symbols)` `libr/bin/format/elf/elf.c:5087-5093`: symbols read via `load_symbols_from_phdr` that didn't match the shdr set are pushed back in — another duplicate source.

**6. No identity check on the symbol-cache build**
`Elf_(load_symbols_vec)` `libr/bin/format/elf/elf.c:5670-5683`: one `push_back` per `g_symbols_vec` entry, verbatim.

**7. Downstream deliberately keeps duplicates**
`libr/bin/bfilter.c:155-163` detects an exact dup and returns `NULL` with the literal TODO *"symbol is dupped, so symbol can be removed!"*; `libr/bin/bobj.c:915-924` only annotates `dup_count` (and only when `bin->filter && load_unnamed`). So they survive into `is`.

## Fix (one localized pass, covers all producers)

Deduplicate at the single place where the final vector is assembled: end of `symbols_vec()` in `libr/bin/p/bin_elf.inc.c`, after the PLT append (after line 455, before `return true;`).

Identity key = **`(vaddr, paddr, is_imported, type, oname)`** — matches your own rule (*"only relevant if haddr is different"*): same pa/va/name collapse; same name at a different address, or a different `type` (IFUNC/TLS), or a versioned `oname`, stays. `ordinal` is intentionally excluded.

```c
// add near top of bin_elf.inc.c
static void dedup_symbols_vec(RVecRBinSymbol *vec) {
	if (RVecRBinSymbol_length (vec) < 2) {
		return;
	}
	HtSU *seen = ht_su_new0 ();
	RVecRBinSymbol out;
	RVecRBinSymbol_init (&out);
	RVecRBinSymbol_reserve (&out, RVecRBinSymbol_length (vec));
	RBinSymbol *sym;
	R_VEC_FOREACH (vec, sym) {
		const char *oname = r_bin_name_tostring2 (sym->name, 'o');
		char *key = r_str_newf ("%" PFMT64x ":%" PFMT64x ":%d:%s:%s",
			sym->vaddr, sym->paddr, sym->is_imported, r_str_get (sym->type), oname);
		bool found = false;
		ht_su_find (seen, key, &found);
		if (found) {
			r_bin_name_free (sym->name);      // drop the redundant element
			sym->name = NULL;
		} else {
			ht_su_insert (seen, key, 1);
			RVecRBinSymbol_push_back (&out, sym);   // shallow move, name kept
		}
		free (key);
	}
	RVecRBinSymbol_fini (vec);   // frees only the old buffer; names moved to `out`
	*vec = out;
	ht_su_free (seen);
}
```
Call it right after the PLT block in `symbols_vec()`:
```c
449  ...append PLT symbols...
455  }                               // end of plt_symbols block
     dedup_symbols_vec (&bf->bo->symbols_vec);   // <-- add
456  return true;
```

If you prefer defense-in-depth, the same key check can also be applied at `libr/bin/format/elf/elf.c:5683` before `RVecRBinSymbol_push_back (&eo->symbols_cache, &sym)` (free `sym.name` on skip) to avoid building the `.symtab`/`.dynsym` duplicates in the first place.

## Why this is safe / caveats
- Dedup is ELF-plugin-local (`symbols_vec()` only), so mach0/PE/etc. are untouched; their own dedup (`mach0.c:2965-2979`) is unaffected. Do **not** change shared `r_bin_filter_sym` (`bfilter.c:188`).
- `symbols_by_ord` is built from **clones** at `elf.c:5680-5681`, so reloc/PLT-by-ordinal resolution still works after the vector is compacted.
- Runs before `CLAMP_VEC`/`shrink_to_fit` (`bobj.c:925`, `986`) and before the address index (`bin.c:1438`), so all consumers see the unique set.
- ET_REL caveat: `paddr` is section-relative there (`elf.c:5500-5503`); if two same-named locals in different sections can collide, skip the pass when `is_bin_etrel (eo)`.

Want me to apply this patch (and the `elf.c:5683` variant) to the tree?
