/*
 *  ELF file handling for TCC
 * 
 *  Copyright (c) 2001-2004 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "tcc.h"

static int new_undef_sym = 0; /* Is there a new undefined sym since last new_undef_sym() */

ST_FUNC int put_elf_str(Section *s, const char *sym)
{
    int offset, len;
    char *ptr;

    len = strlen(sym) + 1;
    offset = s->data_offset;
    ptr = section_ptr_add(s, len);
    memcpy(ptr, sym, len);
    return offset;
}

/* elf symbol hashing function */
static unsigned long elf_hash(const unsigned char *name)
{
    unsigned long h = 0, g;
    
    while (*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        if (g)
            h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

/* rebuild hash table of section s */
/* NOTE: we do factorize the hash table code to go faster */
static void rebuild_hash(Section *s, unsigned int nb_buckets)
{
    ElfW(Sym) *sym;
    int *ptr, *hash, nb_syms, sym_index, h;
    char *strtab;

    strtab = s->link->data;
    nb_syms = s->data_offset / sizeof(ElfW(Sym));

    s->hash->data_offset = 0;
    ptr = section_ptr_add(s->hash, (2 + nb_buckets + nb_syms) * sizeof(int));
    ptr[0] = nb_buckets;
    ptr[1] = nb_syms;
    ptr += 2;
    hash = ptr;
    memset(hash, 0, (nb_buckets + 1) * sizeof(int));
    ptr += nb_buckets + 1;

    sym = (ElfW(Sym) *)s->data + 1;
    for(sym_index = 1; sym_index < nb_syms; sym_index++) {
        if (ELFW(ST_BIND)(sym->st_info) != STB_LOCAL) {
            h = elf_hash(strtab + sym->st_name) % nb_buckets;
            *ptr = hash[h];
            hash[h] = sym_index;
        } else {
            *ptr = 0;
        }
        ptr++;
        sym++;
    }
}

/* return the symbol number */
ST_FUNC int put_elf_sym(Section *s, addr_t value, unsigned long size,
    int info, int other, int shndx, const char *name)
{
    int name_offset, sym_index;
    int nbuckets, h;
    ElfW(Sym) *sym;
    Section *hs;
    
    sym = section_ptr_add(s, sizeof(ElfW(Sym)));
    if (name)
        name_offset = put_elf_str(s->link, name);
    else
        name_offset = 0;
    /* XXX: endianness */
    sym->st_name = name_offset;
    sym->st_value = value;
    sym->st_size = size;
    sym->st_info = info;
    sym->st_other = other;
    sym->st_shndx = shndx;
    sym_index = sym - (ElfW(Sym) *)s->data;
    hs = s->hash;
    if (hs) {
        int *ptr, *base;
        ptr = section_ptr_add(hs, sizeof(int));
        base = (int *)hs->data;
        /* only add global or weak symbols */
        if (ELFW(ST_BIND)(info) != STB_LOCAL) {
            /* add another hashing entry */
            nbuckets = base[0];
            h = elf_hash(name) % nbuckets;
            *ptr = base[2 + h];
            base[2 + h] = sym_index;
            base[1]++;
            /* we resize the hash table */
            hs->nb_hashed_syms++;
            if (hs->nb_hashed_syms > 2 * nbuckets) {
                rebuild_hash(s, 2 * nbuckets);
            }
        } else {
            *ptr = 0;
            base[1]++;
        }
    }
    return sym_index;
}

/* find global ELF symbol 'name' and return its index. Return 0 if not
   found. */
ST_FUNC int find_elf_sym(Section *s, const char *name)
{
    ElfW(Sym) *sym;
    Section *hs;
    int nbuckets, sym_index, h;
    const char *name1;
    
    hs = s->hash;
    if (!hs)
        return 0;
    nbuckets = ((int *)hs->data)[0];
    h = elf_hash(name) % nbuckets;
    sym_index = ((int *)hs->data)[2 + h];
    while (sym_index != 0) {
        sym = &((ElfW(Sym) *)s->data)[sym_index];
        name1 = s->link->data + sym->st_name;
        if (!strcmp(name, name1))
            return sym_index;
        sym_index = ((int *)hs->data)[2 + nbuckets + sym_index];
    }
    return 0;
}

/* return elf symbol value, signal error if 'err' is nonzero */
ST_FUNC addr_t get_elf_sym_addr(TCCState *s, const char *name, int err)
{
    int sym_index;
    ElfW(Sym) *sym;

    sym_index = find_elf_sym(s->symtab, name);
    sym = &((ElfW(Sym) *)s->symtab->data)[sym_index];
    if (!sym_index || sym->st_shndx == SHN_UNDEF) {
        if (err)
            tcc_error("%s not defined", name);
        return 0;
    }
    return sym->st_value;
}

/* return elf symbol value */
LIBTCCAPI void *tcc_get_symbol(TCCState *s, const char *name)
{
    return (void*)(uintptr_t)get_elf_sym_addr(s, name, 0);
}

#ifdef TCC_IS_NATIVE
/* return elf symbol value or error */
ST_FUNC void* tcc_get_symbol_err(TCCState *s, const char *name)
{
    return (void*)get_elf_sym_addr(s, name, 1);
}
#endif

/* add an elf symbol : check if it is already defined and patch
   it. Return symbol index. NOTE that sh_num can be SHN_UNDEF. */
ST_FUNC int add_elf_sym(Section *s, addr_t value, unsigned long size,
                       int info, int other, int sh_num, const char *name)
{
    ElfW(Sym) *esym;
    int sym_bind, sym_index, sym_type, esym_bind;
    unsigned char sym_vis, esym_vis, new_vis;

    sym_bind = ELFW(ST_BIND)(info);
    sym_type = ELFW(ST_TYPE)(info);
    sym_vis = ELFW(ST_VISIBILITY)(other);
        
    if (sym_bind != STB_LOCAL) {
        /* we search global or weak symbols */
        sym_index = find_elf_sym(s, name);
        if (!sym_index)
            goto do_def;
        esym = &((ElfW(Sym) *)s->data)[sym_index];
        if (esym->st_shndx != SHN_UNDEF) {
            esym_bind = ELFW(ST_BIND)(esym->st_info);
            /* propagate the most constraining visibility */
            /* STV_DEFAULT(0)<STV_PROTECTED(3)<STV_HIDDEN(2)<STV_INTERNAL(1) */
            esym_vis = ELFW(ST_VISIBILITY)(esym->st_other);
            if (esym_vis == STV_DEFAULT) {
                new_vis = sym_vis;
            } else if (sym_vis == STV_DEFAULT) {
                new_vis = esym_vis;
            } else {
                new_vis = (esym_vis < sym_vis) ? esym_vis : sym_vis;
            }
            esym->st_other = (esym->st_other & ~ELFW(ST_VISIBILITY)(-1))
                             | new_vis;
            other = esym->st_other; /* in case we have to patch esym */
            if (sh_num == SHN_UNDEF) {
                /* ignore adding of undefined symbol if the
                   corresponding symbol is already defined */
            } else if (sym_bind == STB_GLOBAL && esym_bind == STB_WEAK) {
                /* global overrides weak, so patch */
                goto do_patch;
            } else if (sym_bind == STB_WEAK && esym_bind == STB_GLOBAL) {
                /* weak is ignored if already global */
            } else if (sym_bind == STB_WEAK && esym_bind == STB_WEAK) {
                /* keep first-found weak definition, ignore subsequents */
            } else if (sym_vis == STV_HIDDEN || sym_vis == STV_INTERNAL) {
                /* ignore hidden symbols after */
            } else if (esym->st_shndx == SHN_COMMON
                    && (sh_num < SHN_LORESERVE || sh_num == SHN_COMMON)) {
                /* gr: Happens with 'tcc ... -static tcctest.c' on e.g. Ubuntu 6.01
                   No idea if this is the correct solution ... */
                goto do_patch;
            } else if (s == tcc_state->dynsymtab_section) {
                /* we accept that two DLL define the same symbol */
            } else {
#if 0
                printf("new_bind=%x new_shndx=%x new_vis=%x old_bind=%x old_shndx=%x old_vis=%x\n",
                       sym_bind, sh_num, new_vis, esym_bind, esym->st_shndx, esym_vis);
#endif
                tcc_error_noabort("'%s' defined twice", name);
            }
        } else {
        do_patch:
            esym->st_info = ELFW(ST_INFO)(sym_bind, sym_type);
            esym->st_shndx = sh_num;
            new_undef_sym = 1;
            esym->st_value = value;
            esym->st_size = size;
            esym->st_other = other;
        }
    } else {
    do_def:
        sym_index = put_elf_sym(s, value, size, 
                                ELFW(ST_INFO)(sym_bind, sym_type), other, 
                                sh_num, name);
    }
    return sym_index;
}

/* put relocation */
ST_FUNC void put_elf_reloc(Section *symtab, Section *s, unsigned long offset,
                          int type, int symbol)
{
    char buf[256];
    Section *sr;
    ElfW_Rel *rel;

    sr = s->reloc;
    if (!sr) {
        /* if no relocation section, create it */
        snprintf(buf, sizeof(buf), REL_SECTION_FMT, s->name);
        /* if the symtab is allocated, then we consider the relocation
           are also */
        sr = new_section(tcc_state, buf, SHT_RELX, symtab->sh_flags);
        sr->sh_entsize = sizeof(ElfW_Rel);
        sr->link = symtab;
        sr->sh_info = s->sh_num;
        s->reloc = sr;
    }
    rel = section_ptr_add(sr, sizeof(ElfW_Rel));
    rel->r_offset = offset;
    rel->r_info = ELFW(R_INFO)(symbol, type);
#ifdef TCC_TARGET_X86_64
    rel->r_addend = 0;
#endif
}

/* put stab debug information */

ST_FUNC void put_stabs(const char *str, int type, int other, int desc,
                      unsigned long value)
{
    Stab_Sym *sym;

    sym = section_ptr_add(stab_section, sizeof(Stab_Sym));
    if (str) {
        sym->n_strx = put_elf_str(stabstr_section, str);
    } else {
        sym->n_strx = 0;
    }
    sym->n_type = type;
    sym->n_other = other;
    sym->n_desc = desc;
    sym->n_value = value;
}

ST_FUNC void put_stabs_r(const char *str, int type, int other, int desc, 
                        unsigned long value, Section *sec, int sym_index)
{
    put_stabs(str, type, other, desc, value);
    put_elf_reloc(symtab_section, stab_section, 
                  stab_section->data_offset - sizeof(unsigned int),
                  R_DATA_32, sym_index);
}

ST_FUNC void put_stabn(int type, int other, int desc, int value)
{
    put_stabs(NULL, type, other, desc, value);
}

ST_FUNC void put_stabd(int type, int other, int desc)
{
    put_stabs(NULL, type, other, desc, 0);
}

/* In an ELF file symbol table, the local symbols must appear below
   the global and weak ones. Since TCC cannot sort it while generating
   the code, we must do it after. All the relocation tables are also
   modified to take into account the symbol table sorting */
static void sort_syms(TCCState *s1, Section *s)
{
    int *old_to_new_syms;
    ElfW(Sym) *new_syms;
    int nb_syms, i;
    ElfW(Sym) *p, *q;
    ElfW_Rel *rel, *rel_end;
    Section *sr;
    int type, sym_index;

    nb_syms = s->data_offset / sizeof(ElfW(Sym));
    new_syms = malloc(nb_syms * sizeof(ElfW(Sym)));
    old_to_new_syms = malloc(nb_syms * sizeof(int));

    /* first pass for local symbols */
    p = (ElfW(Sym) *)s->data;
    q = new_syms;
    for(i = 0; i < nb_syms; i++) {
        if (ELFW(ST_BIND)(p->st_info) == STB_LOCAL) {
            old_to_new_syms[i] = q - new_syms;
            *q++ = *p;
        }
        p++;
    }
    /* save the number of local symbols in section header */
    s->sh_info = q - new_syms;

    /* then second pass for non local symbols */
    p = (ElfW(Sym) *)s->data;
    for(i = 0; i < nb_syms; i++) {
        if (ELFW(ST_BIND)(p->st_info) != STB_LOCAL) {
            old_to_new_syms[i] = q - new_syms;
            *q++ = *p;
        }
        p++;
    }
    
    /* we copy the new symbols to the old */
    memcpy(s->data, new_syms, nb_syms * sizeof(ElfW(Sym)));
    free(new_syms);

    /* now we modify all the relocations */
    for(i = 1; i < s1->nb_sections; i++) {
        sr = s1->sections[i];
        if (sr->sh_type == SHT_RELX && sr->link == s) {
            rel_end = (ElfW_Rel *)(sr->data + sr->data_offset);
            for(rel = (ElfW_Rel *)sr->data;
                rel < rel_end;
                rel++) {
                sym_index = ELFW(R_SYM)(rel->r_info);
                type = ELFW(R_TYPE)(rel->r_info);
                sym_index = old_to_new_syms[sym_index];
                rel->r_info = ELFW(R_INFO)(sym_index, type);
            }
        }
    }
    
    free(old_to_new_syms);
}

/* relocate common symbols in the .bss section */
ST_FUNC void relocate_common_syms(void)
{
    ElfW(Sym) *sym, *sym_end;
    unsigned long offset, align;
    
    sym_end = (ElfW(Sym) *)(symtab_section->data + symtab_section->data_offset);
    for(sym = (ElfW(Sym) *)symtab_section->data + 1; 
        sym < sym_end;
        sym++) {
        if (sym->st_shndx == SHN_COMMON) {
            /* align symbol */
            align = sym->st_value;
            offset = bss_section->data_offset;
            offset = (offset + align - 1) & -align;
            sym->st_value = offset;
            sym->st_shndx = bss_section->sh_num;
            offset += sym->st_size;
            bss_section->data_offset = offset;
        }
    }
}

/* relocate symbol table, resolve undefined symbols if do_resolve is
   true and output error if undefined symbol. */
ST_FUNC void relocate_syms(TCCState *s1, int do_resolve)
{
    ElfW(Sym) *sym, *esym, *sym_end;
    int sym_bind, sh_num, sym_index;
    const char *name;

    sym_end = (ElfW(Sym) *)(symtab_section->data + symtab_section->data_offset);
    for(sym = (ElfW(Sym) *)symtab_section->data + 1; 
        sym < sym_end;
        sym++) {
        sh_num = sym->st_shndx;
        if (sh_num == SHN_UNDEF) {
            name = strtab_section->data + sym->st_name;
            if (do_resolve) {
#if defined TCC_IS_NATIVE && !defined _WIN32
                void *addr;
                name = symtab_section->link->data + sym->st_name;
                addr = resolve_sym(s1, name);
                if (addr) {
                    sym->st_value = (addr_t)addr;
                    goto found;
                }
#endif
            } else if (s1->dynsym) {
                /* if dynamic symbol exist, then use it */
                sym_index = find_elf_sym(s1->dynsym, name);
                if (sym_index) {
                    esym = &((ElfW(Sym) *)s1->dynsym->data)[sym_index];
                    sym->st_value = esym->st_value;
                    goto found;
                }
            }
            /* XXX: _fp_hw seems to be part of the ABI, so we ignore
               it */
            if (!strcmp(name, "_fp_hw"))
                goto found;
            /* only weak symbols are accepted to be undefined. Their
               value is zero */
            sym_bind = ELFW(ST_BIND)(sym->st_info);
            if (sym_bind == STB_WEAK) {
                sym->st_value = 0;
            } else {
                tcc_error_noabort("undefined symbol '%s'", name);
            }
        } else if (sh_num < SHN_LORESERVE) {
            /* add section base */
            sym->st_value += s1->sections[sym->st_shndx]->sh_addr;
        }
    found: ;
    }
}

#ifdef TCC_HAS_RUNTIME_PLTGOT
#ifdef TCC_TARGET_X86_64
#define JMP_TABLE_ENTRY_SIZE 14
static addr_t add_jmp_table(TCCState *s1, addr_t val)
{
    char *p = s1->runtime_plt_and_got + s1->runtime_plt_and_got_offset;
    s1->runtime_plt_and_got_offset += JMP_TABLE_ENTRY_SIZE;
    /* jmp *0x0(%rip) */
    p[0] = 0xff;
    p[1] = 0x25;
    *(int *)(p + 2) = 0;
    *(addr_t *)(p + 6) = val;
    return (addr_t)p;
}

static addr_t add_got_table(TCCState *s1, addr_t val)
{
    addr_t *p = (addr_t *)(s1->runtime_plt_and_got + s1->runtime_plt_and_got_offset);
    s1->runtime_plt_and_got_offset += sizeof(addr_t);
    *p = val;
    return (addr_t)p;
}
#elif defined TCC_TARGET_ARM
#define JMP_TABLE_ENTRY_SIZE 8
static addr_t add_jmp_table(TCCState *s1, int val)
{
    uint32_t *p = (uint32_t *)(s1->runtime_plt_and_got + s1->runtime_plt_and_got_offset);
    s1->runtime_plt_and_got_offset += JMP_TABLE_ENTRY_SIZE;
    /* ldr pc, [pc, #-4] */
    p[0] = 0xE51FF004;
    p[1] = val;
    return (addr_t)p;
}
#endif
#endif /* def TCC_HAS_RUNTIME_PLTGOT */

/* relocate a given section (CPU dependent) */
ST_FUNC void relocate_section(TCCState *s1, Section *s)
{
    Section *sr;
    ElfW_Rel *rel, *rel_end, *qrel;
    ElfW(Sym) *sym;
    int type, sym_index;
    unsigned char *ptr;
    addr_t val, addr;
#if defined TCC_TARGET_I386 || defined TCC_TARGET_X86_64
    int esym_index;
#endif

    sr = s->reloc;
    rel_end = (ElfW_Rel *)(sr->data + sr->data_offset);
    qrel = (ElfW_Rel *)sr->data;
    for(rel = qrel;
        rel < rel_end;
        rel++) {
        ptr = s->data + rel->r_offset;

        sym_index = ELFW(R_SYM)(rel->r_info);
        sym = &((ElfW(Sym) *)symtab_section->data)[sym_index];
        val = sym->st_value;
#ifdef TCC_TARGET_X86_64
        val += rel->r_addend;
#endif
        type = ELFW(R_TYPE)(rel->r_info);
        addr = s->sh_addr + rel->r_offset;

        /* CPU specific */
        switch(type) {
#if defined(TCC_TARGET_I386)
        case R_386_32:
            if (s1->output_type == TCC_OUTPUT_DLL) {
                esym_index = s1->symtab_to_dynsym[sym_index];
                qrel->r_offset = rel->r_offset;
                if (esym_index) {
                    qrel->r_info = ELFW(R_INFO)(esym_index, R_386_32);
                    qrel++;
                    break;
                } else {
                    qrel->r_info = ELFW(R_INFO)(0, R_386_RELATIVE);
                    qrel++;
                }
            }
            *(int *)ptr += val;
            break;
        case R_386_PC32:
            if (s1->output_type == TCC_OUTPUT_DLL) {
                /* DLL relocation */
                esym_index = s1->symtab_to_dynsym[sym_index];
                if (esym_index) {
                    qrel->r_offset = rel->r_offset;
                    qrel->r_info = ELFW(R_INFO)(esym_index, R_386_PC32);
                    qrel++;
                    break;
                }
            }
            *(int *)ptr += val - addr;
            break;
        case R_386_PLT32:
            *(int *)ptr += val - addr;
            break;
        case R_386_GLOB_DAT:
        case R_386_JMP_SLOT:
            *(int *)ptr = val;
            break;
        case R_386_GOTPC:
            *(int *)ptr += s1->got->sh_addr - addr;
            break;
        case R_386_GOTOFF:
            *(int *)ptr += val - s1->got->sh_addr;
            break;
        case R_386_GOT32:
            /* we load the got offset */
            *(int *)ptr += s1->sym_attrs[sym_index].got_offset;
            break;
        case R_386_16:
            if (s1->output_format != TCC_OUTPUT_FORMAT_BINARY) {
            output_file:
		tcc_error("can only produce 16-bit binary files");
            }
            *(short *)ptr += val;
            break;
        case R_386_PC16:
            if (s1->output_format != TCC_OUTPUT_FORMAT_BINARY)
		goto output_file;
            *(short *)ptr += val - addr;
            break;
#elif defined(TCC_TARGET_ARM)
        case R_ARM_PC24:
        case R_ARM_CALL:
        case R_ARM_JUMP24:
        case R_ARM_PLT32:
            {
                int x, is_thumb, is_call, h, blx_avail;
                x = (*(int *)ptr)&0xffffff;
                (*(int *)ptr) &= 0xff000000;
                if (x & 0x800000)
                    x -= 0x1000000;
                x <<= 2;
                blx_avail = (TCC_ARM_VERSION >= 5);
                is_thumb = val & 1;
                is_call = (type == R_ARM_CALL);
                x += val - addr;
                h = x & 2;
#ifdef TCC_HAS_RUNTIME_PLTGOT
                if (s1->output_type == TCC_OUTPUT_MEMORY) {
                    if ((x & 3) || x >= 0x2000000 || x < -0x2000000)
                        if (!(x & 3) || !blx_avail || !is_call) {
                            x += add_jmp_table(s1, val) - val; /* add veneer */
                            is_thumb = 0; /* Veneer uses ARM instructions */
                        }
                }
#endif
                if ((x & 3) || x >= 0x2000000 || x < -0x2000000)
                    if (!(x & 3) || !blx_avail || !is_call)
                        tcc_error("can't relocate value at %x",addr);
                x >>= 2;
                x &= 0xffffff;
                /* Only reached if blx is avail and it is a call */
                if (is_thumb) {
                    x |= h << 24;
                    (*(int *)ptr) = 0xfa << 24; /* bl -> blx */
                }
                (*(int *)ptr) |= x;
            }
            break;
        /* Since these relocations only concern Thumb-2 and blx instruction was
           introduced before Thumb-2, we can assume blx is available and not
           guard its use */
        case R_ARM_THM_CALL:
        case R_ARM_THM_JUMP24:
	    {
                int x, hi, lo, s, j1, j2, i1, i2, imm10, imm11;
                int to_thumb, is_call, to_plt, blx_bit = 1 << 12;
                Section *plt;

                /* weak reference */
                if (sym->st_shndx == SHN_UNDEF &&
                    ELFW(ST_BIND)(sym->st_info) == STB_WEAK)
                    break;

                /* Get initial offset */
                hi = (*(uint16_t *)ptr);
                lo = (*(uint16_t *)(ptr+2));
                s = (hi >> 10) & 1;
                j1 = (lo >> 13) & 1;
                j2 = (lo >> 11) & 1;
                i1 = (j1 ^ s) ^ 1;
                i2 = (j2 ^ s) ^ 1;
                imm10 = hi & 0x3ff;
                imm11 = lo & 0x7ff;
                x = (s << 24) | (i1 << 23) | (i2 << 22) |
                    (imm10 << 12) | (imm11 << 1);
                if (x & 0x01000000)
                    x -= 0x02000000;

                /* Relocation infos */
                to_thumb = val & 1;
                plt = s1->plt;
                to_plt = (val >= plt->sh_addr) &&
                         (val < plt->sh_addr + plt->data_offset);
                is_call = (type == R_ARM_THM_CALL);

                /* Compute final offset */
                if (to_plt && !is_call) /* Point to 1st instr of Thumb stub */
                    x -= 4;
                x += val - addr;
                if (!to_thumb && is_call) {
                    blx_bit = 0; /* bl -> blx */
                    x = (x + 3) & -4; /* Compute offset from aligned PC */
                }

                /* Check that relocation is possible
                   * offset must not be out of range
                   * if target is to be entered in arm mode:
                     - bit 1 must not set
                     - instruction must be a call (bl) or a jump to PLT */
                if (!to_thumb || x >= 0x1000000 || x < -0x1000000)
                    if (to_thumb || (val & 2) || (!is_call && !to_plt))
                        tcc_error("can't relocate value at %x",addr);

                /* Compute and store final offset */
                s = (x >> 24) & 1;
                i1 = (x >> 23) & 1;
                i2 = (x >> 22) & 1;
                j1 = s ^ (i1 ^ 1);
                j2 = s ^ (i2 ^ 1);
                imm10 = (x >> 12) & 0x3ff;
                imm11 = (x >> 1) & 0x7ff;
                (*(uint16_t *)ptr) = (uint16_t) ((hi & 0xf800) |
                                     (s << 10) | imm10);
                (*(uint16_t *)(ptr+2)) = (uint16_t) ((lo & 0xc000) |
                                (j1 << 13) | blx_bit | (j2 << 11) |
                                imm11);
            }
            break;
        case R_ARM_MOVT_ABS:
        case R_ARM_MOVW_ABS_NC:
            {
                int x, imm4, imm12;
                if (type == R_ARM_MOVT_ABS)
                    val >>= 16;
                imm12 = val & 0xfff;
                imm4 = (val >> 12) & 0xf;
                x = (imm4 << 16) | imm12;
                if (type == R_ARM_THM_MOVT_ABS)
                    *(int *)ptr |= x;
                else
                    *(int *)ptr += x;
	    }
            break;
        case R_ARM_THM_MOVT_ABS:
        case R_ARM_THM_MOVW_ABS_NC:
            {
                int x, i, imm4, imm3, imm8;
                if (type == R_ARM_THM_MOVT_ABS)
                    val >>= 16;
                imm8 = val & 0xff;
                imm3 = (val >> 8) & 0x7;
                i = (val >> 11) & 1;
                imm4 = (val >> 12) & 0xf;
                x = (imm3 << 28) | (imm8 << 16) | (i << 10) | imm4;
                if (type == R_ARM_THM_MOVT_ABS)
                    *(int *)ptr |= x;
                else
                    *(int *)ptr += x;
	    }
            break;
        case R_ARM_PREL31:
            {
                int x;
                x = (*(int *)ptr) & 0x7fffffff;
                (*(int *)ptr) &= 0x80000000;
                x = (x * 2) / 2;
                x += val - addr;
                if((x^(x>>1))&0x40000000)
                    tcc_error("can't relocate value at %x",addr);
                (*(int *)ptr) |= x & 0x7fffffff;
            }
        case R_ARM_ABS32:
            *(int *)ptr += val;
            break;
        case R_ARM_REL32:
            *(int *)ptr += val - addr;
            break;
        case R_ARM_BASE_PREL:
            *(int *)ptr += s1->got->sh_addr - addr;
            break;
        case R_ARM_GOTOFF32:
            *(int *)ptr += val - s1->got->sh_addr;
            break;
        case R_ARM_GOT_BREL:
            /* we load the got offset */
            *(int *)ptr += s1->sym_attrs[sym_index].got_offset;
            break;
        case R_ARM_COPY:
            break;
        case R_ARM_V4BX:
            /* trade Thumb support for ARMv4 support */
            if ((0x0ffffff0 & *(int*)ptr) == 0x012FFF10)
                *(int*)ptr ^= 0xE12FFF10 ^ 0xE1A0F000; /* BX Rm -> MOV PC, Rm */
            break;
        default:
            fprintf(stderr,"FIXME: handle reloc type %x at %x [%p] to %x\n",
                type, (unsigned)addr, ptr, (unsigned)val);
            break;
#elif defined(TCC_TARGET_C67)
        case R_C60_32:
            *(int *)ptr += val;
            break;
        case R_C60LO16:
            {
                uint32_t orig;
                
                /* put the low 16 bits of the absolute address */
                // add to what is already there
                
                orig  =   ((*(int *)(ptr  )) >> 7) & 0xffff;
                orig |=  (((*(int *)(ptr+4)) >> 7) & 0xffff) << 16;
                
                //patch both at once - assumes always in pairs Low - High
                
                *(int *) ptr    = (*(int *) ptr    & (~(0xffff << 7)) ) |  (((val+orig)      & 0xffff) << 7);
                *(int *)(ptr+4) = (*(int *)(ptr+4) & (~(0xffff << 7)) ) | ((((val+orig)>>16) & 0xffff) << 7);
            }
            break;
        case R_C60HI16:
            break;
        default:
            fprintf(stderr,"FIXME: handle reloc type %x at %x [%p] to %x\n",
                type, (unsigned)addr, ptr, (unsigned)val);
            break;
#elif defined(TCC_TARGET_X86_64)
        case R_X86_64_64:
            if (s1->output_type == TCC_OUTPUT_DLL) {
                qrel->r_info = ELFW(R_INFO)(0, R_X86_64_RELATIVE);
                qrel->r_addend = *(long long *)ptr + val;
                qrel++;
            }
            *(long long *)ptr += val;
            break;
        case R_X86_64_32:
        case R_X86_64_32S:
            if (s1->output_type == TCC_OUTPUT_DLL) {
                /* XXX: this logic may depend on TCC's codegen
                   now TCC uses R_X86_64_32 even for a 64bit pointer */
                qrel->r_info = ELFW(R_INFO)(0, R_X86_64_RELATIVE);
                qrel->r_addend = *(int *)ptr + val;
                qrel++;
            }
            *(int *)ptr += val;
            break;

        case R_X86_64_PC32:
            if (s1->output_type == TCC_OUTPUT_DLL) {
                /* DLL relocation */
                esym_index = s1->symtab_to_dynsym[sym_index];
                if (esym_index) {
                    qrel->r_offset = rel->r_offset;
                    qrel->r_info = ELFW(R_INFO)(esym_index, R_X86_64_PC32);
                    qrel->r_addend = *(int *)ptr;
                    qrel++;
                    break;
                }
            }
            /* fall through */
        case R_X86_64_PLT32: {
            long long diff;
            diff = (long long)val - addr;
            if (diff <= -2147483647 || diff > 2147483647) {
#ifdef TCC_HAS_RUNTIME_PLTGOT
                /* XXX: naive support for over 32bit jump */
                if (s1->output_type == TCC_OUTPUT_MEMORY) {
                    val = (add_jmp_table(s1, val - rel->r_addend) +
                           rel->r_addend);
                    diff = val - addr;
                }
#endif
                if (diff <= -2147483647 || diff > 2147483647) {
                    tcc_error("internal error: relocation failed");
                }
            }
            *(int *)ptr += diff;
        }
            break;
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
            /* They don't need addend */
            *(int *)ptr = val - rel->r_addend;
            break;
        case R_X86_64_GOTPCREL:
#ifdef TCC_HAS_RUNTIME_PLTGOT
            if (s1->output_type == TCC_OUTPUT_MEMORY) {
                val = add_got_table(s1, val - rel->r_addend) + rel->r_addend;
                *(int *)ptr += val - addr;
                break;
            }
#endif
            *(int *)ptr += (s1->got->sh_addr - addr +
                            s1->sym_attrs[sym_index].got_offset - 4);
            break;
        case R_X86_64_GOTTPOFF:
            *(int *)ptr += val - s1->got->sh_addr;
            break;
        case R_X86_64_GOT32:
            /* we load the got offset */
            *(int *)ptr += s1->sym_attrs[sym_index].got_offset;
            break;
#else
#error unsupported processor
#endif
        }
    }
    /* if the relocation is allocated, we change its symbol table */
    if (sr->sh_flags & SHF_ALLOC)
        sr->link = s1->dynsym;
}

/* relocate relocation table in 'sr' */
static void relocate_rel(TCCState *s1, Section *sr)
{
    Section *s;
    ElfW_Rel *rel, *rel_end;
    
    s = s1->sections[sr->sh_info];
    rel_end = (ElfW_Rel *)(sr->data + sr->data_offset);
    for(rel = (ElfW_Rel *)sr->data;
        rel < rel_end;
        rel++) {
        rel->r_offset += s->sh_addr;
    }
}

/* count the number of dynamic relocations so that we can reserve
   their space */
static int prepare_dynamic_rel(TCCState *s1, Section *sr)
{
    ElfW_Rel *rel, *rel_end;
    int sym_index, esym_index, type, count;

    count = 0;
    rel_end = (ElfW_Rel *)(sr->data + sr->data_offset);
    for(rel = (ElfW_Rel *)sr->data; rel < rel_end; rel++) {
        sym_index = ELFW(R_SYM)(rel->r_info);
        type = ELFW(R_TYPE)(rel->r_info);
        switch(type) {
#if defined(TCC_TARGET_I386)
        case R_386_32:
#elif defined(TCC_TARGET_X86_64)
        case R_X86_64_32:
        case R_X86_64_32S:
        case R_X86_64_64:
#endif
            count++;
            break;
#if defined(TCC_TARGET_I386)
        case R_386_PC32:
#elif defined(TCC_TARGET_X86_64)
        case R_X86_64_PC32:
#endif
            esym_index = s1->symtab_to_dynsym[sym_index];
            if (esym_index)
                count++;
            break;
        default:
            break;
        }
    }
    if (count) {
        /* allocate the section */
        sr->sh_flags |= SHF_ALLOC;
        sr->sh_size = count * sizeof(ElfW_Rel);
    }
    return count;
}

static struct sym_attr *alloc_sym_attr(TCCState *s1, int index)
{
    int n;
    struct sym_attr *tab;

    if (index >= s1->nb_sym_attrs) {
        /* find immediately bigger power of 2 and reallocate array */
        n = 1;
        while (index >= n)
            n *= 2;
        tab = realloc(s1->sym_attrs, n * sizeof(*s1->sym_attrs));
        s1->sym_attrs = tab;
        memset(s1->sym_attrs + s1->nb_sym_attrs, 0,
               (n - s1->nb_sym_attrs) * sizeof(*s1->sym_attrs));
        s1->nb_sym_attrs = n;
    }
    return &s1->sym_attrs[index];
}

/* XXX: suppress that */
static void put32(unsigned char *p, uint32_t val)
{
    p[0] = val;
    p[1] = val >> 8;
    p[2] = val >> 16;
    p[3] = val >> 24;
}

#if defined(TCC_TARGET_I386) || defined(TCC_TARGET_ARM) || \
    defined(TCC_TARGET_X86_64)
static uint32_t get32(unsigned char *p)
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}
#endif

static void build_got(TCCState *s1)
{
    unsigned char *ptr;

    /* if no got, then create it */
    s1->got = new_section(s1, ".got", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);
    s1->got->sh_entsize = 4;
    add_elf_sym(symtab_section, 0, 4, ELFW(ST_INFO)(STB_GLOBAL, STT_OBJECT), 
                0, s1->got->sh_num, "_GLOBAL_OFFSET_TABLE_");
    ptr = section_ptr_add(s1->got, 3 * PTR_SIZE);
#if PTR_SIZE == 4
    /* keep space for _DYNAMIC pointer, if present */
    put32(ptr, 0);
    /* two dummy got entries */
    put32(ptr + 4, 0);
    put32(ptr + 8, 0);
#else
    /* keep space for _DYNAMIC pointer, if present */
    put32(ptr, 0);
    put32(ptr + 4, 0);
    /* two dummy got entries */
    put32(ptr + 8, 0);
    put32(ptr + 12, 0);
    put32(ptr + 16, 0);
    put32(ptr + 20, 0);
#endif
}

/* put a got entry corresponding to a symbol in symtab_section. 'size'
   and 'info' can be modifed if more precise info comes from the DLL */
static void put_got_entry(TCCState *s1,
                          int reloc_type, unsigned long size, int info, 
                          int sym_index)
{
    int index;
    const char *name;
    ElfW(Sym) *sym;
    unsigned long offset;
    int *ptr;

    if (!s1->got)
        build_got(s1);

    /* if a got entry already exists for that symbol, no need to add one */
    if (sym_index < s1->nb_sym_attrs &&
        s1->sym_attrs[sym_index].got_offset)
        return;

    alloc_sym_attr(s1, sym_index)->got_offset = s1->got->data_offset;

    if (s1->dynsym) {
        sym = &((ElfW(Sym) *)symtab_section->data)[sym_index];
        name = symtab_section->link->data + sym->st_name;
        offset = sym->st_value;
#if defined(TCC_TARGET_I386) || defined(TCC_TARGET_X86_64)
        if (reloc_type ==
#ifdef TCC_TARGET_X86_64
            R_X86_64_JUMP_SLOT
#else
            R_386_JMP_SLOT
#endif
            ) {
            Section *plt;
            uint8_t *p;
            int modrm;

#if defined(TCC_OUTPUT_DLL_WITH_PLT)
            modrm = 0x25;
#else
            /* if we build a DLL, we add a %ebx offset */
            if (s1->output_type == TCC_OUTPUT_DLL)
                modrm = 0xa3;
            else
                modrm = 0x25;
#endif

            /* add a PLT entry */
            plt = s1->plt;
            if (plt->data_offset == 0) {
                /* first plt entry */
                p = section_ptr_add(plt, 16);
                p[0] = 0xff; /* pushl got + PTR_SIZE */
                p[1] = modrm + 0x10;
                put32(p + 2, PTR_SIZE);
                p[6] = 0xff; /* jmp *(got + PTR_SIZE * 2) */
                p[7] = modrm;
                put32(p + 8, PTR_SIZE * 2);
            }

            p = section_ptr_add(plt, 16);
            p[0] = 0xff; /* jmp *(got + x) */
            p[1] = modrm;
            put32(p + 2, s1->got->data_offset);
            p[6] = 0x68; /* push $xxx */
            put32(p + 7, (plt->data_offset - 32) >> 1);
            p[11] = 0xe9; /* jmp plt_start */
            put32(p + 12, -(plt->data_offset));

            /* the symbol is modified so that it will be relocated to
               the PLT */
#if !defined(TCC_OUTPUT_DLL_WITH_PLT)
            if (s1->output_type == TCC_OUTPUT_EXE)
#endif
                offset = plt->data_offset - 16;
        }
#elif defined(TCC_TARGET_ARM)
        if (reloc_type == R_ARM_JUMP_SLOT) {
            Section *plt;
            uint8_t *p;
            
            /* if we build a DLL, we add a %ebx offset */
            if (s1->output_type == TCC_OUTPUT_DLL)
                tcc_error("DLLs unimplemented!");

            /* add a PLT entry */
            plt = s1->plt;
            if (plt->data_offset == 0) {
                /* first plt entry */
                p = section_ptr_add(plt, 16);
                put32(p     , 0xe52de004);
                put32(p +  4, 0xe59fe010);
                put32(p +  8, 0xe08fe00e);
                put32(p + 12, 0xe5bef008);
            }

            if (s1->sym_attrs[sym_index].plt_thumb_stub) {
                p = section_ptr_add(plt, 20);
                put32(p  , 0x4778); // bx pc
                put32(p+2, 0x46c0); // nop
                p += 4;
            } else
                p = section_ptr_add(plt, 16);
            put32(p  , 0xe59fc004); // ldr ip, [pc, #4] // offset in GOT
            put32(p+4, 0xe08fc00c); // add ip, pc, ip // absolute address or offset
            put32(p+8, 0xe59cf000); // ldr pc, [ip] // load absolute address or load offset
            put32(p+12, s1->got->data_offset);

            /* the symbol is modified so that it will be relocated to
               the PLT */
            if (s1->output_type == TCC_OUTPUT_EXE)
                offset = plt->data_offset - 16;
        }
#elif defined(TCC_TARGET_C67)
        tcc_error("C67 got not implemented");
#else
#error unsupported CPU
#endif
        index = put_elf_sym(s1->dynsym, offset, 
                            size, info, 0, sym->st_shndx, name);
        /* put a got entry */
        put_elf_reloc(s1->dynsym, s1->got, 
                      s1->got->data_offset, 
                      reloc_type, index);
    }
    ptr = section_ptr_add(s1->got, PTR_SIZE);
    *ptr = 0;
}

/* build GOT and PLT entries */
ST_FUNC void build_got_entries(TCCState *s1)
{
    Section *s;
    ElfW_Rel *rel, *rel_end;
    ElfW(Sym) *sym;
    int i, type, reloc_type, sym_index;

    for(i = 1; i < s1->nb_sections; i++) {
        s = s1->sections[i];
        if (s->sh_type != SHT_RELX)
            continue;
        /* no need to handle got relocations */
        if (s->link != symtab_section)
            continue;
        rel_end = (ElfW_Rel *)(s->data + s->data_offset);
        for(rel = (ElfW_Rel *)s->data;
            rel < rel_end;
            rel++) {
            type = ELFW(R_TYPE)(rel->r_info);
            switch(type) {
#if defined(TCC_TARGET_I386)
            case R_386_GOT32:
            case R_386_GOTOFF:
            case R_386_GOTPC:
            case R_386_PLT32:
                if (!s1->got)
                    build_got(s1);
                if (type == R_386_GOT32 || type == R_386_PLT32) {
                    sym_index = ELFW(R_SYM)(rel->r_info);
                    sym = &((ElfW(Sym) *)symtab_section->data)[sym_index];
                    /* look at the symbol got offset. If none, then add one */
                    if (type == R_386_GOT32)
                        reloc_type = R_386_GLOB_DAT;
                    else
                        reloc_type = R_386_JMP_SLOT;
                    put_got_entry(s1, reloc_type, sym->st_size, sym->st_info, 
                                  sym_index);
                }
                break;
#elif defined(TCC_TARGET_ARM)
            case R_ARM_GOT_BREL:
            case R_ARM_GOTOFF32:
            case R_ARM_BASE_PREL:
            case R_ARM_PLT32:
                if (!s1->got)
                    build_got(s1);
                if (type == R_ARM_GOT_BREL || type == R_ARM_PLT32) {
                    sym_index = ELFW(R_SYM)(rel->r_info);
                    sym = &((ElfW(Sym) *)symtab_section->data)[sym_index];
                    /* look at the symbol got offset. If none, then add one */
                    if (type == R_ARM_GOT_BREL)
                        reloc_type = R_ARM_GLOB_DAT;
                    else
                        reloc_type = R_ARM_JUMP_SLOT;
                    put_got_entry(s1, reloc_type, sym->st_size, sym->st_info, 
                                  sym_index);
                }
                break;
#elif defined(TCC_TARGET_C67)
            case R_C60_GOT32:
            case R_C60_GOTOFF:
            case R_C60_GOTPC:
            case R_C60_PLT32:
                if (!s1->got)
                    build_got(s1);
                if (type == R_C60_GOT32 || type == R_C60_PLT32) {
                    sym_index = ELFW(R_SYM)(rel->r_info);
                    sym = &((ElfW(Sym) *)symtab_section->data)[sym_index];
                    /* look at the symbol got offset. If none, then add one */
                    if (type == R_C60_GOT32)
                        reloc_type = R_C60_GLOB_DAT;
                    else
                        reloc_type = R_C60_JMP_SLOT;
                    put_got_entry(s1, reloc_type, sym->st_size, sym->st_info, 
                                  sym_index);
                }
                break;
#elif defined(TCC_TARGET_X86_64)
            case R_X86_64_GOT32:
            case R_X86_64_GOTTPOFF:
            case R_X86_64_GOTPCREL:
            case R_X86_64_PLT32:
                if (!s1->got)
                    build_got(s1);
                if (type == R_X86_64_GOT32 || type == R_X86_64_GOTPCREL ||
                    type == R_X86_64_PLT32) {
                    sym_index = ELFW(R_SYM)(rel->r_info);
                    sym = &((ElfW(Sym) *)symtab_section->data)[sym_index];
                    /* look at the symbol got offset. If none, then add one */
                    if (type == R_X86_64_GOT32 || type == R_X86_64_GOTPCREL)
                        reloc_type = R_X86_64_GLOB_DAT;
                    else
                        reloc_type = R_X86_64_JUMP_SLOT;
                    put_got_entry(s1, reloc_type, sym->st_size, sym->st_info, 
                                  sym_index);
                }
                break;
#else
#error unsupported CPU
#endif
            default:
                break;
            }
        }
    }
}

ST_FUNC Section *new_symtab(TCCState *s1,
                           const char *symtab_name, int sh_type, int sh_flags,
                           const char *strtab_name, 
                           const char *hash_name, int hash_sh_flags)
{
    Section *symtab, *strtab, *hash;
    int *ptr, nb_buckets;

    symtab = new_section(s1, symtab_name, sh_type, sh_flags);
    symtab->sh_entsize = sizeof(ElfW(Sym));
    strtab = new_section(s1, strtab_name, SHT_STRTAB, sh_flags);
    put_elf_str(strtab, "");
    symtab->link = strtab;
    put_elf_sym(symtab, 0, 0, 0, 0, 0, NULL);
    
    nb_buckets = 1;

    hash = new_section(s1, hash_name, SHT_HASH, hash_sh_flags);
    hash->sh_entsize = sizeof(int);
    symtab->hash = hash;
    hash->link = symtab;

    ptr = section_ptr_add(hash, (2 + nb_buckets + 1) * sizeof(int));
    ptr[0] = nb_buckets;
    ptr[1] = 1;
    memset(ptr + 2, 0, (nb_buckets + 1) * sizeof(int));
    return symtab;
}

/* put dynamic tag */
static void put_dt(Section *dynamic, int dt, addr_t val)
{
    ElfW(Dyn) *dyn;
    dyn = section_ptr_add(dynamic, sizeof(ElfW(Dyn)));
    dyn->d_tag = dt;
    dyn->d_un.d_val = val;
}

static void add_init_array_defines(TCCState *s1, const char *section_name)
{
    Section *s;
    long end_offset;
    char sym_start[1024];
    char sym_end[1024];
    
    snprintf(sym_start, sizeof(sym_start), "__%s_start", section_name + 1);
    snprintf(sym_end, sizeof(sym_end), "__%s_end", section_name + 1);

    s = find_section(s1, section_name);
    if (!s) {
        end_offset = 0;
        s = data_section;
    } else {
        end_offset = s->data_offset;
    }

    add_elf_sym(symtab_section, 
                0, 0,
                ELFW(ST_INFO)(STB_GLOBAL, STT_NOTYPE), 0,
                s->sh_num, sym_start);
    add_elf_sym(symtab_section, 
                end_offset, 0,
                ELFW(ST_INFO)(STB_GLOBAL, STT_NOTYPE), 0,
                s->sh_num, sym_end);
}

ST_FUNC void tcc_add_bcheck(TCCState *s1)
{
#ifdef CONFIG_TCC_BCHECK
    unsigned long *ptr;
    Section *init_section;
    unsigned char *pinit;
    int sym_index;

    if (0 == s1->do_bounds_check)
        return;

    /* XXX: add an object file to do that */
    ptr = section_ptr_add(bounds_section, sizeof(unsigned long));
    *ptr = 0;
    add_elf_sym(symtab_section, 0, 0,
                ELFW(ST_INFO)(STB_GLOBAL, STT_NOTYPE), 0,
                bounds_section->sh_num, "__bounds_start");
#ifdef TCC_TARGET_I386
    if (s1->output_type != TCC_OUTPUT_MEMORY) {
        /* add 'call __bound_init()' in .init section */
        init_section = find_section(s1, ".init");
        pinit = section_ptr_add(init_section, 5);
        pinit[0] = 0xe8;
        put32(pinit + 1, -4);
        sym_index = find_elf_sym(symtab_section, "__bound_init");
        put_elf_reloc(symtab_section, init_section,
                      init_section->data_offset - 4, R_386_PC32, sym_index);
    }
#endif
#endif
}

static inline int tcc_add_support(TCCState *s1, const char *filename)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s/%s", s1->tcc_lib_path, filename);
    return tcc_add_file(s1, buf);
}

/* add tcc runtime libraries */
ST_FUNC void tcc_add_runtime(TCCState *s1)
{
    tcc_add_bcheck(s1);

    /* add libc */
    if (!s1->nostdlib) {
        tcc_add_library(s1, "c");
#if 0
#ifdef CONFIG_USE_LIBGCC
        tcc_add_file(s1, TCC_LIBGCC);
#elif !defined WITHOUT_LIBTCC
        tcc_add_support(s1, "libtcc1.a");
#endif
#endif
        /* add crt end if not memory output */
        if (s1->output_type != TCC_OUTPUT_MEMORY)
            tcc_add_crt(s1, "crtn.o");
    }
}

/* add various standard linker symbols (must be done after the
   sections are filled (for example after allocating common
   symbols)) */
ST_FUNC void tcc_add_linker_symbols(TCCState *s1)
{
    char buf[1024];
    int i;
    Section *s;

    add_elf_sym(symtab_section, 
                text_section->data_offset, 0,
                ELFW(ST_INFO)(STB_GLOBAL, STT_NOTYPE), 0,
                text_section->sh_num, "_etext");
    add_elf_sym(symtab_section, 
                data_section->data_offset, 0,
                ELFW(ST_INFO)(STB_GLOBAL, STT_NOTYPE), 0,
                data_section->sh_num, "_edata");
    add_elf_sym(symtab_section, 
                bss_section->data_offset, 0,
                ELFW(ST_INFO)(STB_GLOBAL, STT_NOTYPE), 0,
                bss_section->sh_num, "_end");
    /* horrible new standard ldscript defines */
    add_init_array_defines(s1, ".preinit_array");
    add_init_array_defines(s1, ".init_array");
    add_init_array_defines(s1, ".fini_array");
    
    /* add start and stop symbols for sections whose name can be
       expressed in C */
    for(i = 1; i < s1->nb_sections; i++) {
        s = s1->sections[i];
        if (s->sh_type == SHT_PROGBITS &&
            (s->sh_flags & SHF_ALLOC)) {
            const char *p;
            int ch;

            /* check if section name can be expressed in C */
            p = s->name;
            for(;;) {
                ch = *p;
                if (!ch)
                    break;
                if (!isid(ch) && !isnum(ch))
                    goto next_sec;
                p++;
            }
            snprintf(buf, sizeof(buf), "__start_%s", s->name);
            add_elf_sym(symtab_section, 
                        0, 0,
                        ELFW(ST_INFO)(STB_GLOBAL, STT_NOTYPE), 0,
                        s->sh_num, buf);
            snprintf(buf, sizeof(buf), "__stop_%s", s->name);
            add_elf_sym(symtab_section,
                        s->data_offset, 0,
                        ELFW(ST_INFO)(STB_GLOBAL, STT_NOTYPE), 0,
                        s->sh_num, buf);
        }
    next_sec: ;
    }
}

static void tcc_output_binary(TCCState *s1, FILE *f,
                              const int *section_order)
{
    Section *s;
    int i, offset, size;

    offset = 0;
    for(i=1;i<s1->nb_sections;i++) {
        s = s1->sections[section_order[i]];
        if (s->sh_type != SHT_NOBITS &&
            (s->sh_flags & SHF_ALLOC)) {
            while (offset < s->sh_offset) {
                fputc(0, f);
                offset++;
            }
            size = s->sh_size;
            fwrite(s->data, 1, size, f);
            offset += size;
        }
    }
}

#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
#define	HAVE_PHDR	1
#define	EXTRA_RELITEMS	14

/* move the relocation value from .dynsym to .got */
void patch_dynsym_undef(TCCState *s1, Section *s)
{
    uint32_t *gotd = (void *)s1->got->data;
    ElfW(Sym) *sym, *sym_end;

    gotd += 3;	// dummy entries in .got
    /* relocate symbols in .dynsym */
    sym_end = (ElfW(Sym) *)(s->data + s->data_offset);
    for (sym = (ElfW(Sym) *)s->data + 1; sym < sym_end; sym++) {
	if (sym->st_shndx == SHN_UNDEF) {
	    *gotd++ = sym->st_value + 6; // XXX 6 is magic ?
	    sym->st_value = 0;
	}
    }
}
#else
#define	HAVE_PHDR	0
#define	EXTRA_RELITEMS	9

/* zero plt offsets of weak symbols in .dynsym */
void patch_dynsym_undef(TCCState *s1, Section *s)
{
    ElfW(Sym) *sym, *sym_end;

    sym_end = (ElfW(Sym) *)(s->data + s->data_offset);
    for (sym = (ElfW(Sym) *)s->data + 1; sym < sym_end; sym++)
        if (sym->st_shndx == SHN_UNDEF && ELFW(ST_BIND)(sym->st_info) == STB_WEAK)
            sym->st_value = 0;
}
#endif

ST_FUNC void fill_got_entry(TCCState *s1, ElfW_Rel *rel)
{
	int sym_index = ELFW(R_SYM) (rel->r_info);
	ElfW(Sym) *sym = &((ElfW(Sym) *) symtab_section->data)[sym_index];
	unsigned long offset;

	if (sym_index >= s1->nb_sym_attrs)
		return;
	offset = s1->sym_attrs[sym_index].got_offset;
	section_reserve(s1->got, offset + PTR_SIZE);
#ifdef TCC_TARGET_X86_64
	/* only works for x86-64 */
	put32(s1->got->data + offset + 4, sym->st_value >> 32);
#endif
	put32(s1->got->data + offset, sym->st_value & 0xffffffff);
}

ST_FUNC void fill_got(TCCState *s1)
{
	Section *s;
	ElfW_Rel *rel, *rel_end;
	int i;

	for(i = 1; i < s1->nb_sections; i++) {
		s = s1->sections[i];
		if (s->sh_type != SHT_RELX)
			continue;
		/* no need to handle got relocations */
		if (s->link != symtab_section)
			continue;
		rel_end = (ElfW_Rel *) (s->data + s->data_offset);
		for(rel = (ElfW_Rel *) s->data; rel < rel_end; rel++) {
			switch (ELFW(R_TYPE) (rel->r_info)) {
			case R_X86_64_GOT32:
			case R_X86_64_GOTPCREL:
			case R_X86_64_PLT32:
				fill_got_entry(s1, rel);
				break;
			}
		}
	}
}


/* output an ELF file */
/* XXX: suppress unneeded sections */
static int elf_output_file(TCCState *s1, const char *filename)
{
printf ("elf_output_file (%s)\n", filename);
return 0;
#if 0
    ElfW(Ehdr) ehdr;
    FILE *f;
    int fd, mode, ret;
    int *section_order;
    int shnum, i, phnum, file_offset, offset, size, j, sh_order_index, k;
    long long tmp;
    addr_t addr;
    Section *strsec, *s;
    ElfW(Shdr) shdr, *sh;
    ElfW(Phdr) *phdr, *ph;
    Section *interp, *dynamic, *dynstr;
    unsigned long saved_dynamic_data_offset;
    ElfW(Sym) *sym;
    int type, file_type;
    addr_t rel_addr, rel_size;
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
    addr_t bss_addr, bss_size;
#endif

    file_type = s1->output_type;
    s1->nb_errors = 0;

    if (file_type != TCC_OUTPUT_OBJ) {
        tcc_add_runtime(s1);
    }

    phdr = NULL;
    section_order = NULL;
    interp = NULL;
    dynamic = NULL;
    dynstr = NULL; /* avoid warning */
    saved_dynamic_data_offset = 0; /* avoid warning */
    
    if (file_type != TCC_OUTPUT_OBJ) {
        relocate_common_syms();

        tcc_add_linker_symbols(s1);

        if (!s1->static_link) {
            const char *name;
            int sym_index, index;
            ElfW(Sym) *esym, *sym_end;

            if (file_type == TCC_OUTPUT_EXE) {
                char *ptr;
		/* allow override the dynamic loader */
		const char *elfint = getenv("LD_SO");
		if (elfint == NULL)
		    elfint = CONFIG_TCC_ELFINTERP;
                /* add interpreter section only if executable */
                interp = new_section(s1, ".interp", SHT_PROGBITS, SHF_ALLOC);
                interp->sh_addralign = 1;
                ptr = section_ptr_add(interp, 1+strlen(elfint));
                strcpy(ptr, elfint);
            }

            /* add dynamic symbol table */
            s1->dynsym = new_symtab(s1, ".dynsym", SHT_DYNSYM, SHF_ALLOC,
                                    ".dynstr", 
                                    ".hash", SHF_ALLOC);
            dynstr = s1->dynsym->link;
            
            /* add dynamic section */
            dynamic = new_section(s1, ".dynamic", SHT_DYNAMIC, 
                                  SHF_ALLOC | SHF_WRITE);
            dynamic->link = dynstr;
            dynamic->sh_entsize = sizeof(ElfW(Dyn));
        
            /* add PLT */
            s1->plt = new_section(s1, ".plt", SHT_PROGBITS, 
                                  SHF_ALLOC | SHF_EXECINSTR);
            s1->plt->sh_entsize = 4;

            build_got(s1);

            /* scan for undefined symbols and see if they are in the
               dynamic symbols. If a symbol STT_FUNC or STT_GNU_IFUNC
               is found, then we add it in the PLT. If a symbol
               STT_OBJECT is found, we add it in the .bss section with
               a suitable relocation */
            sym_end = (ElfW(Sym) *)(symtab_section->data + 
                                    symtab_section->data_offset);
            if (file_type == TCC_OUTPUT_EXE) {
                for(sym = (ElfW(Sym) *)symtab_section->data + 1; 
                    sym < sym_end;
                    sym++) {
                    if (sym->st_shndx == SHN_UNDEF) {
                        name = symtab_section->link->data + sym->st_name;
                        sym_index = find_elf_sym(s1->dynsymtab_section, name);
                        if (sym_index) {
                            esym = &((ElfW(Sym) *)s1->dynsymtab_section->data)[sym_index];
                            type = ELFW(ST_TYPE)(esym->st_info);
                            if ((type == STT_FUNC) || (type == STT_GNU_IFUNC)) {
                                /* Indirect functions shall have STT_FUNC type
                                 * in executable dynsym section. Indeed, a dlsym
                                 * call following a lazy resolution would pick
                                 * the symbol value from the executable dynsym
                                 * entry which would contain the address of the
                                 * function wanted by the caller of dlsym
                                 * instead of the address of the function that
                                 * would return that address */
                                put_got_entry(s1, R_JMP_SLOT, esym->st_size, 
                                              ELFW(ST_INFO)(STB_GLOBAL,STT_FUNC),
                                              sym - (ElfW(Sym) *)symtab_section->data);
                            } else if (type == STT_OBJECT) {
                                unsigned long offset;
                                ElfW(Sym) *dynsym, *dynsym_end;
                                offset = bss_section->data_offset;
                                /* XXX: which alignment ? */
                                offset = (offset + 16 - 1) & -16;
                                index = put_elf_sym(s1->dynsym, offset, esym->st_size, 
                                                    esym->st_info, 0, 
                                                    bss_section->sh_num, name);
                                // Ensure R_COPY works for weak symbol aliases
                                if (ELFW(ST_BIND)(esym->st_info) == STB_WEAK) {
                                    dynsym_end = (ElfW(Sym) *)
                                                 (s1->dynsymtab_section->data +
                                                  s1->dynsymtab_section->data_offset);
                                    for(dynsym = (ElfW(Sym) *)s1->dynsymtab_section->data + 1;
                                        dynsym < dynsym_end; dynsym++) {
                                        if ((dynsym->st_value == esym->st_value)
                                           && (ELFW(ST_BIND)(dynsym->st_info) == STB_GLOBAL)) {
                                            char *dynname;
                                            dynname = s1->dynsymtab_section->link->data
                                                      + dynsym->st_name;
                                            put_elf_sym(s1->dynsym, offset,
                                                        dynsym->st_size,
                                                        dynsym->st_info, 0,
                                                        bss_section->sh_num,
                                                        dynname);
                                            break;
                                        }
                                    }
                                }
                                put_elf_reloc(s1->dynsym, bss_section, 
                                              offset, R_COPY, index);
                                offset += esym->st_size;
                                bss_section->data_offset = offset;
                            }
                        } else {
                                /* STB_WEAK undefined symbols are accepted */
                                /* XXX: _fp_hw seems to be part of the ABI, so we ignore
                                   it */
                            if (ELFW(ST_BIND)(sym->st_info) == STB_WEAK ||
                                !strcmp(name, "_fp_hw")) {
                            } else {
                                tcc_error_noabort("undefined symbol '%s'", name);
                            }
                        }
                    } else if (s1->rdynamic && 
                               ELFW(ST_BIND)(sym->st_info) != STB_LOCAL) {
                        /* if -rdynamic option, then export all non
                           local symbols */
                        name = symtab_section->link->data + sym->st_name;
                        put_elf_sym(s1->dynsym, sym->st_value, sym->st_size, 
                                    sym->st_info, 0, 
                                    sym->st_shndx, name);
                    }
                }
            
                if (s1->nb_errors)
                    goto fail;

                /* now look at unresolved dynamic symbols and export
                   corresponding symbol */
                sym_end = (ElfW(Sym) *)(s1->dynsymtab_section->data + 
                                        s1->dynsymtab_section->data_offset);
                for(esym = (ElfW(Sym) *)s1->dynsymtab_section->data + 1; 
                    esym < sym_end;
                    esym++) {
                    if (esym->st_shndx == SHN_UNDEF) {
                        name = s1->dynsymtab_section->link->data + esym->st_name;
                        sym_index = find_elf_sym(symtab_section, name);
                        if (sym_index) {
                            /* XXX: avoid adding a symbol if already
                               present because of -rdynamic ? */
                            sym = &((ElfW(Sym) *)symtab_section->data)[sym_index];
                            put_elf_sym(s1->dynsym, sym->st_value, sym->st_size, 
                                        sym->st_info, 0, 
                                        sym->st_shndx, name);
                        } else {
                            if (ELFW(ST_BIND)(esym->st_info) == STB_WEAK) {
                                /* weak symbols can stay undefined */
                            } else {
                                tcc_warning("undefined dynamic symbol '%s'", name);
                            }
                        }
                    }
                }
            } else {
                int nb_syms;
                /* shared library case : we simply export all the global symbols */
                nb_syms = symtab_section->data_offset / sizeof(ElfW(Sym));
                s1->symtab_to_dynsym = tcc_mallocz(sizeof(int) * nb_syms);
                for(sym = (ElfW(Sym) *)symtab_section->data + 1; 
                    sym < sym_end;
                    sym++) {
                    if (ELFW(ST_BIND)(sym->st_info) != STB_LOCAL) {
#if defined(TCC_OUTPUT_DLL_WITH_PLT)
                        if ((ELFW(ST_TYPE)(sym->st_info) == STT_FUNC ||
                            ELFW(ST_TYPE)(sym->st_info) == STT_GNU_IFUNC)
                            && sym->st_shndx == SHN_UNDEF) {
                            int visibility = ELFW(ST_BIND)(sym->st_info);
                            put_got_entry(s1, R_JMP_SLOT, sym->st_size, 
                                          ELFW(ST_INFO)(visibility,STT_FUNC),
                                          sym - (ElfW(Sym) *)symtab_section->data);
                        }
                        else if (ELFW(ST_TYPE)(sym->st_info) == STT_OBJECT) {
                            put_got_entry(s1, R_X86_64_GLOB_DAT, sym->st_size, 
                                          sym->st_info, 
                                          sym - (ElfW(Sym) *)symtab_section->data);
                        }
                        else
#endif
                        {
                            name = symtab_section->link->data + sym->st_name;
                            index = put_elf_sym(s1->dynsym, sym->st_value, sym->st_size, 
                                                sym->st_info, 0, 
                                                sym->st_shndx, name);
                            s1->symtab_to_dynsym[sym - 
                                                 (ElfW(Sym) *)symtab_section->data] = 
                                index;
                        }
                    }
                }
            }

            build_got_entries(s1);
        
            /* add a list of needed dlls */
            for(i = 0; i < s1->nb_loaded_dlls; i++) {
                DLLReference *dllref = s1->loaded_dlls[i];
                if (dllref->level == 0)
                    put_dt(dynamic, DT_NEEDED, put_elf_str(dynstr, dllref->name));
            }

            if (s1->rpath)
                put_dt(dynamic, DT_RPATH, put_elf_str(dynstr, s1->rpath));

            /* XXX: currently, since we do not handle PIC code, we
               must relocate the readonly segments */
            if (file_type == TCC_OUTPUT_DLL) {
                if (s1->soname)
                    put_dt(dynamic, DT_SONAME, put_elf_str(dynstr, s1->soname));
                put_dt(dynamic, DT_TEXTREL, 0);
            }

            if (s1->symbolic)
                put_dt(dynamic, DT_SYMBOLIC, 0);

            /* add necessary space for other entries */
            saved_dynamic_data_offset = dynamic->data_offset;
            dynamic->data_offset += sizeof(ElfW(Dyn)) * EXTRA_RELITEMS;
        } else {
            /* still need to build got entries in case of static link */
            build_got_entries(s1);
        }
    }

    memset(&ehdr, 0, sizeof(ehdr));

    /* we add a section for symbols */
    strsec = new_section(s1, ".shstrtab", SHT_STRTAB, 0);
    put_elf_str(strsec, "");
    
    /* compute number of sections */
    shnum = s1->nb_sections;

    /* this array is used to reorder sections in the output file */
    section_order = malloc(sizeof(int) * shnum);
    section_order[0] = 0;
    sh_order_index = 1;
    
    /* compute number of program headers */
    switch(file_type) {
    default:
    case TCC_OUTPUT_OBJ:
        phnum = 0;
        break;
    case TCC_OUTPUT_EXE:
        if (!s1->static_link)
            phnum = 4 + HAVE_PHDR;
        else
            phnum = 2;
        break;
    case TCC_OUTPUT_DLL:
        phnum = 3;
        break;
    }

    /* allocate strings for section names and decide if an unallocated
       section should be output */
    /* NOTE: the strsec section comes last, so its size is also
       correct ! */
    for(i = 1; i < s1->nb_sections; i++) {
        s = s1->sections[i];
        s->sh_name = put_elf_str(strsec, s->name);
#if 0 /* gr */
        printf("section: f=%08x t=%08x i=%08x %s %s\n", 
               s->sh_flags, 
               s->sh_type, 
               s->sh_info, 
               s->name, 
               s->reloc ? s->reloc->name : "n"
               ); 
#endif
        /* when generating a DLL, we include relocations but we may
           patch them */
        if (file_type == TCC_OUTPUT_DLL && 
            s->sh_type == SHT_RELX && 
            !(s->sh_flags & SHF_ALLOC)) {
            /* //gr: avoid bogus relocs for empty (debug) sections */
            if (s1->sections[s->sh_info]->sh_flags & SHF_ALLOC)
                prepare_dynamic_rel(s1, s);
            else if (s1->do_debug)
                s->sh_size = s->data_offset;
        } else if (s1->do_debug ||
            file_type == TCC_OUTPUT_OBJ || 
            (s->sh_flags & SHF_ALLOC) ||
            i == (s1->nb_sections - 1)) {
            /* we output all sections if debug or object file */
            s->sh_size = s->data_offset;
        }
    }

    /* allocate program segment headers */
    phdr = tcc_mallocz(phnum * sizeof(ElfW(Phdr)));
        
    if (s1->output_format == TCC_OUTPUT_FORMAT_ELF) {
        file_offset = sizeof(ElfW(Ehdr)) + phnum * sizeof(ElfW(Phdr));
    } else {
        file_offset = 0;
    }
    if (phnum > 0) {
        /* compute section to program header mapping */
        if (s1->has_text_addr) { 
            int a_offset, p_offset;
            addr = s1->text_addr;
            /* we ensure that (addr % ELF_PAGE_SIZE) == file_offset %
               ELF_PAGE_SIZE */
            a_offset = (int) (addr & (s1->section_align - 1));
            p_offset = file_offset & (s1->section_align - 1);
            if (a_offset < p_offset) 
                a_offset += s1->section_align;
            file_offset += (a_offset - p_offset);
        } else {
            if (file_type == TCC_OUTPUT_DLL)
                addr = 0;
            else
                addr = ELF_START_ADDR;
            /* compute address after headers */
            addr += (file_offset & (s1->section_align - 1));
        }
        
        /* dynamic relocation table information, for .dynamic section */
        rel_size = 0;
        rel_addr = 0;

#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
        bss_addr = bss_size = 0;
#endif
        /* leave one program header for the program interpreter */
        ph = &phdr[0];
        if (interp)
            ph += 1 + HAVE_PHDR;

        for(j = 0; j < 2; j++) {
            ph->p_type = PT_LOAD;
            if (j == 0)
                ph->p_flags = PF_R | PF_X;
            else
                ph->p_flags = PF_R | PF_W;
            ph->p_align = s1->section_align;
            
            /* we do the following ordering: interp, symbol tables,
               relocations, progbits, nobits */
            /* XXX: do faster and simpler sorting */
            for(k = 0; k < 5; k++) {
                for(i = 1; i < s1->nb_sections; i++) {
                    s = s1->sections[i];
                    /* compute if section should be included */
                    if (j == 0) {
                        if ((s->sh_flags & (SHF_ALLOC | SHF_WRITE)) != 
                            SHF_ALLOC)
                            continue;
                    } else {
                        if ((s->sh_flags & (SHF_ALLOC | SHF_WRITE)) != 
                            (SHF_ALLOC | SHF_WRITE))
                            continue;
                    }
                    if (s == interp) {
                        if (k != 0)
                            continue;
                    } else if (s->sh_type == SHT_DYNSYM ||
                               s->sh_type == SHT_STRTAB ||
                               s->sh_type == SHT_HASH) {
                        if (k != 1)
                            continue;
                    } else if (s->sh_type == SHT_RELX) {
                        if (k != 2)
                            continue;
                    } else if (s->sh_type == SHT_NOBITS) {
                        if (k != 4)
                            continue;
                    } else {
                        if (k != 3)
                            continue;
                    }
                    section_order[sh_order_index++] = i;

                    /* section matches: we align it and add its size */
                    tmp = addr;
                    addr = (addr + s->sh_addralign - 1) & 
                        ~(s->sh_addralign - 1);
                    file_offset += (int) ( addr - tmp );
                    s->sh_offset = file_offset;
                    s->sh_addr = addr;
                    
                    /* update program header infos */
                    if (ph->p_offset == 0) {
                        ph->p_offset = file_offset;
                        ph->p_vaddr = addr;
                        ph->p_paddr = ph->p_vaddr;
                    }
                    /* update dynamic relocation infos */
                    if (s->sh_type == SHT_RELX) {
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
                        if (!strcmp(strsec->data + s->sh_name, ".rel.got")) { // rel_size == 0) {
                            rel_addr = addr;
			    rel_size += s->sh_size;	// XXX only first rel.
			}
                        if (!strcmp(strsec->data + s->sh_name, ".rel.bss")) { // rel_size == 0) {
                            bss_addr = addr;
			    bss_size = s->sh_size;	// XXX only first rel.
			}
#else
                        if (rel_size == 0)
                            rel_addr = addr;
                        rel_size += s->sh_size;
#endif
                    }
                    addr += s->sh_size;
                    if (s->sh_type != SHT_NOBITS)
                        file_offset += s->sh_size;
                }
            }
            ph->p_filesz = file_offset - ph->p_offset;
            ph->p_memsz = addr - ph->p_vaddr;
            ph++;
            if (j == 0) {
                if (s1->output_format == TCC_OUTPUT_FORMAT_ELF) {
                    /* if in the middle of a page, we duplicate the page in
                       memory so that one copy is RX and the other is RW */
                    if ((addr & (s1->section_align - 1)) != 0)
                        addr += s1->section_align;
                } else {
                    addr = (addr + s1->section_align - 1) & ~(s1->section_align - 1);
                    file_offset = (file_offset + s1->section_align - 1) &
                        ~(s1->section_align - 1);
                }
            }
        }

        /* if interpreter, then add corresponing program header */
        if (interp) {
            ph = &phdr[0];

#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
	    {
		int len = phnum * sizeof(ElfW(Phdr));

		ph->p_type = PT_PHDR;
		ph->p_offset = sizeof(ElfW(Ehdr));
		ph->p_vaddr = interp->sh_addr - len;
		ph->p_paddr = ph->p_vaddr;
		ph->p_filesz = ph->p_memsz = len;
		ph->p_flags = PF_R | PF_X;
		ph->p_align = 4; // interp->sh_addralign;
		ph++;
	    }
#endif

            ph->p_type = PT_INTERP;
            ph->p_offset = interp->sh_offset;
            ph->p_vaddr = interp->sh_addr;
            ph->p_paddr = ph->p_vaddr;
            ph->p_filesz = interp->sh_size;
            ph->p_memsz = interp->sh_size;
            ph->p_flags = PF_R;
            ph->p_align = interp->sh_addralign;
        }
        
        /* if dynamic section, then add corresponing program header */
        if (dynamic) {
            ElfW(Sym) *sym_end;

            ph = &phdr[phnum - 1];
            
            ph->p_type = PT_DYNAMIC;
            ph->p_offset = dynamic->sh_offset;
            ph->p_vaddr = dynamic->sh_addr;
            ph->p_paddr = ph->p_vaddr;
            ph->p_filesz = dynamic->sh_size;
            ph->p_memsz = dynamic->sh_size;
            ph->p_flags = PF_R | PF_W;
            ph->p_align = dynamic->sh_addralign;

            /* put GOT dynamic section address */
            put32(s1->got->data, dynamic->sh_addr);

            /* relocate the PLT */
            if (file_type == TCC_OUTPUT_EXE
#if defined(TCC_OUTPUT_DLL_WITH_PLT)
                || file_type == TCC_OUTPUT_DLL
#endif
                ) {
                uint8_t *p, *p_end;

                p = s1->plt->data;
                p_end = p + s1->plt->data_offset;
                if (p < p_end) {
#if defined(TCC_TARGET_I386)
                    put32(p + 2, get32(p + 2) + s1->got->sh_addr);
                    put32(p + 8, get32(p + 8) + s1->got->sh_addr);
                    p += 16;
                    while (p < p_end) {
                        put32(p + 2, get32(p + 2) + s1->got->sh_addr);
                        p += 16;
                    }
#elif defined(TCC_TARGET_X86_64)
                    int x = s1->got->sh_addr - s1->plt->sh_addr - 6;
                    put32(p + 2, get32(p + 2) + x);
                    put32(p + 8, get32(p + 8) + x - 6);
                    p += 16;
                    while (p < p_end) {
                        put32(p + 2, get32(p + 2) + x + s1->plt->data - p);
                        p += 16;
                    }
#elif defined(TCC_TARGET_ARM)
                    int x;
                    x=s1->got->sh_addr - s1->plt->sh_addr - 12;
                    p += 16;
                    while (p < p_end) {
                        if (get32(p) == 0x46c04778) /* PLT Thumb stub present */
                            p += 4;
                        put32(p + 12, x + get32(p + 12) + s1->plt->data - p);
                        p += 16;
                    }
#elif defined(TCC_TARGET_C67)
                    /* XXX: TODO */
#else
#error unsupported CPU
#endif
                }
            }

            /* relocate symbols in .dynsym */
            sym_end = (ElfW(Sym) *)(s1->dynsym->data + s1->dynsym->data_offset);
            for(sym = (ElfW(Sym) *)s1->dynsym->data + 1; 
                sym < sym_end;
                sym++) {
                if (sym->st_shndx == SHN_UNDEF) {
                    /* relocate to the PLT if the symbol corresponds
                       to a PLT entry */
                    if (sym->st_value)
                        sym->st_value += s1->plt->sh_addr;
                } else if (sym->st_shndx < SHN_LORESERVE) {
                    /* do symbol relocation */
                    sym->st_value += s1->sections[sym->st_shndx]->sh_addr;
                }
            }

            /* put dynamic section entries */
            dynamic->data_offset = saved_dynamic_data_offset;
            put_dt(dynamic, DT_HASH, s1->dynsym->hash->sh_addr);
            put_dt(dynamic, DT_STRTAB, dynstr->sh_addr);
            put_dt(dynamic, DT_SYMTAB, s1->dynsym->sh_addr);
            put_dt(dynamic, DT_STRSZ, dynstr->data_offset);
            put_dt(dynamic, DT_SYMENT, sizeof(ElfW(Sym)));
#ifdef TCC_TARGET_X86_64
            put_dt(dynamic, DT_RELA, rel_addr);
            put_dt(dynamic, DT_RELASZ, rel_size);
            put_dt(dynamic, DT_RELAENT, sizeof(ElfW_Rel));
#else
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
            put_dt(dynamic, DT_PLTGOT, s1->got->sh_addr);
            put_dt(dynamic, DT_PLTRELSZ, rel_size);
            put_dt(dynamic, DT_JMPREL, rel_addr);
            put_dt(dynamic, DT_PLTREL, DT_REL);
            put_dt(dynamic, DT_REL, bss_addr);
            put_dt(dynamic, DT_RELSZ, bss_size);
#else
            put_dt(dynamic, DT_REL, rel_addr);
            put_dt(dynamic, DT_RELSZ, rel_size);
            put_dt(dynamic, DT_RELENT, sizeof(ElfW_Rel));
#endif
#endif
            if (s1->do_debug)
                put_dt(dynamic, DT_DEBUG, 0);
            put_dt(dynamic, DT_NULL, 0);
        }

        ehdr.e_phentsize = sizeof(ElfW(Phdr));
        ehdr.e_phnum = phnum;
        ehdr.e_phoff = sizeof(ElfW(Ehdr));
    }

    /* all other sections come after */
    for(i = 1; i < s1->nb_sections; i++) {
        s = s1->sections[i];
        if (phnum > 0 && (s->sh_flags & SHF_ALLOC))
            continue;
        section_order[sh_order_index++] = i;
        
        file_offset = (file_offset + s->sh_addralign - 1) & 
            ~(s->sh_addralign - 1);
        s->sh_offset = file_offset;
        if (s->sh_type != SHT_NOBITS)
            file_offset += s->sh_size;
    }
    
    /* if building executable or DLL, then relocate each section
       except the GOT which is already relocated */
    if (file_type != TCC_OUTPUT_OBJ) {
        relocate_syms(s1, 0);

        if (s1->nb_errors != 0) {
        fail:
            ret = -1;
            goto the_end;
        }

        /* relocate sections */
        /* XXX: ignore sections with allocated relocations ? */
        for(i = 1; i < s1->nb_sections; i++) {
            s = s1->sections[i];
            if (s->reloc && s != s1->got)
                relocate_section(s1, s);
        }

        /* relocate relocation entries if the relocation tables are
           allocated in the executable */
        for(i = 1; i < s1->nb_sections; i++) {
            s = s1->sections[i];
            if ((s->sh_flags & SHF_ALLOC) &&
                s->sh_type == SHT_RELX) {
                relocate_rel(s1, s);
            }
        }

        /* get entry point address */
        if (file_type == TCC_OUTPUT_EXE)
            ehdr.e_entry = get_elf_sym_addr(s1, "_start", 1);
        else
            ehdr.e_entry = text_section->sh_addr; /* XXX: is it correct ? */
    }
    if (file_type == TCC_OUTPUT_EXE && s1->static_link)
        fill_got(s1);

    /* write elf file */
    if (file_type == TCC_OUTPUT_OBJ)
        mode = 0666;
    else
        mode = 0777;
    unlink(filename);
    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, mode); 
    if (fd < 0) {
        tcc_error_noabort("could not write '%s'", filename);
        goto fail;
    }
    f = fdopen(fd, "wb");
    if (s1->verbose)
        printf("<- %s\n", filename);

#ifdef TCC_TARGET_COFF
    if (s1->output_format == TCC_OUTPUT_FORMAT_COFF) {
        tcc_output_coff(s1, f);
    } else
#endif
    if (s1->output_format == TCC_OUTPUT_FORMAT_ELF) {
        sort_syms(s1, symtab_section);
        
        /* align to 4 */
        file_offset = (file_offset + 3) & -4;
    
        /* fill header */
        ehdr.e_ident[0] = ELFMAG0;
        ehdr.e_ident[1] = ELFMAG1;
        ehdr.e_ident[2] = ELFMAG2;
        ehdr.e_ident[3] = ELFMAG3;
        ehdr.e_ident[4] = ELFCLASSW;
        ehdr.e_ident[5] = ELFDATA2LSB;
        ehdr.e_ident[6] = EV_CURRENT;
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
        ehdr.e_ident[EI_OSABI] = ELFOSABI_FREEBSD;
#endif
#ifdef TCC_TARGET_ARM
#ifdef TCC_ARM_EABI
        ehdr.e_ident[EI_OSABI] = 0;
        ehdr.e_flags = 4 << 24;
#else
        ehdr.e_ident[EI_OSABI] = ELFOSABI_ARM;
#endif
#endif
        switch(file_type) {
        default:
        case TCC_OUTPUT_EXE:
            ehdr.e_type = ET_EXEC;
            break;
        case TCC_OUTPUT_DLL:
            ehdr.e_type = ET_DYN;
            break;
        case TCC_OUTPUT_OBJ:
            ehdr.e_type = ET_REL;
            break;
        }
        ehdr.e_machine = EM_TCC_TARGET;
        ehdr.e_version = EV_CURRENT;
        ehdr.e_shoff = file_offset;
        ehdr.e_ehsize = sizeof(ElfW(Ehdr));
        ehdr.e_shentsize = sizeof(ElfW(Shdr));
        ehdr.e_shnum = shnum;
        ehdr.e_shstrndx = shnum - 1;
        
        fwrite(&ehdr, 1, sizeof(ElfW(Ehdr)), f);
        fwrite(phdr, 1, phnum * sizeof(ElfW(Phdr)), f);
        offset = sizeof(ElfW(Ehdr)) + phnum * sizeof(ElfW(Phdr));

        for(i=1;i<s1->nb_sections;i++) {
            s = s1->sections[section_order[i]];
            if (s->sh_type != SHT_NOBITS) {
		if (s->sh_type == SHT_DYNSYM)
		    patch_dynsym_undef(s1, s);
                while (offset < s->sh_offset) {
                    fputc(0, f);
                    offset++;
                }
                size = s->sh_size;
                fwrite(s->data, 1, size, f);
                offset += size;
            }
        }

        /* output section headers */
        while (offset < ehdr.e_shoff) {
            fputc(0, f);
            offset++;
        }
    
        for(i=0;i<s1->nb_sections;i++) {
            sh = &shdr;
            memset(sh, 0, sizeof(ElfW(Shdr)));
            s = s1->sections[i];
            if (s) {
                sh->sh_name = s->sh_name;
                sh->sh_type = s->sh_type;
                sh->sh_flags = s->sh_flags;
                sh->sh_entsize = s->sh_entsize;
                sh->sh_info = s->sh_info;
                if (s->link)
                    sh->sh_link = s->link->sh_num;
                sh->sh_addralign = s->sh_addralign;
                sh->sh_addr = s->sh_addr;
                sh->sh_offset = s->sh_offset;
                sh->sh_size = s->sh_size;
            }
            fwrite(sh, 1, sizeof(ElfW(Shdr)), f);
        }
    } else {
        tcc_output_binary(s1, f, section_order);
    }
    fclose(f);

    ret = 0;
 the_end:
    free(s1->symtab_to_dynsym);
    free(section_order);
    free(phdr);
    free(s1->sym_attrs);
    return ret;
#endif
}

LIBTCCAPI int tcc_output_file(TCCState *s, const char *filename)
{
    int ret;
#ifdef TCC_TARGET_PE
    if (s->output_type != TCC_OUTPUT_OBJ) {
        ret = pe_output_file(s, filename);
    } else
#endif
    {
        ret = elf_output_file(s, filename);
    }
    return ret;
}

static void *load_data(int fd, unsigned long file_offset, unsigned long size)
{
    void *data;

    data = malloc(size);
    lseek(fd, file_offset, SEEK_SET);
    read(fd, data, size);
    return data;
}

typedef struct SectionMergeInfo {
    Section *s;            /* corresponding existing section */
    unsigned long offset;  /* offset of the new section in the existing section */
    uint8_t new_section;       /* true if section 's' was added */
    uint8_t link_once;         /* true if link once section */
} SectionMergeInfo;

/* load an object file and merge it with current files */
/* XXX: handle correctly stab (debug) info */
ST_FUNC int tcc_load_object_file(TCCState *s1, 
                                int fd, unsigned long file_offset)
{ 
    ElfW(Ehdr) ehdr;
    ElfW(Shdr) *shdr, *sh;
    int size, i, j, offset, offseti, nb_syms, sym_index, ret;
    unsigned char *strsec, *strtab;
    int *old_to_new_syms;
    char *sh_name, *name;
    SectionMergeInfo *sm_table, *sm;
    ElfW(Sym) *sym, *symtab;
    ElfW_Rel *rel, *rel_end;
    Section *s;

    int stab_index;
    int stabstr_index;

    stab_index = stabstr_index = 0;

    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr))
        goto fail1;
    if (ehdr.e_ident[0] != ELFMAG0 ||
        ehdr.e_ident[1] != ELFMAG1 ||
        ehdr.e_ident[2] != ELFMAG2 ||
        ehdr.e_ident[3] != ELFMAG3)
        goto fail1;
    /* test if object file */
    if (ehdr.e_type != ET_REL)
        goto fail1;
    /* test CPU specific stuff */
    if (ehdr.e_ident[5] != ELFDATA2LSB ||
        ehdr.e_machine != EM_TCC_TARGET) {
    fail1:
        tcc_error_noabort("invalid object file");
        return -1;
    }
    /* read sections */
    shdr = load_data(fd, file_offset + ehdr.e_shoff, 
                     sizeof(ElfW(Shdr)) * ehdr.e_shnum);
    sm_table = tcc_mallocz(sizeof(SectionMergeInfo) * ehdr.e_shnum);
    
    /* load section names */
    sh = &shdr[ehdr.e_shstrndx];
    strsec = load_data(fd, file_offset + sh->sh_offset, sh->sh_size);

    /* load symtab and strtab */
    old_to_new_syms = NULL;
    symtab = NULL;
    strtab = NULL;
    nb_syms = 0;
    for(i = 1; i < ehdr.e_shnum; i++) {
        sh = &shdr[i];
        if (sh->sh_type == SHT_SYMTAB) {
            if (symtab) {
                tcc_error_noabort("object must contain only one symtab");
            fail:
                ret = -1;
                goto the_end;
            }
            nb_syms = sh->sh_size / sizeof(ElfW(Sym));
            symtab = load_data(fd, file_offset + sh->sh_offset, sh->sh_size);
            sm_table[i].s = symtab_section;

            /* now load strtab */
            sh = &shdr[sh->sh_link];
            strtab = load_data(fd, file_offset + sh->sh_offset, sh->sh_size);
        }
    }
        
    /* now examine each section and try to merge its content with the
       ones in memory */
    for(i = 1; i < ehdr.e_shnum; i++) {
        /* no need to examine section name strtab */
        if (i == ehdr.e_shstrndx)
            continue;
        sh = &shdr[i];
        sh_name = strsec + sh->sh_name;
        /* ignore sections types we do not handle */
        if (sh->sh_type != SHT_PROGBITS &&
            sh->sh_type != SHT_RELX && 
#ifdef TCC_ARM_EABI
            sh->sh_type != SHT_ARM_EXIDX &&
#endif
            sh->sh_type != SHT_NOBITS && 
            sh->sh_type != SHT_PREINIT_ARRAY &&
            sh->sh_type != SHT_INIT_ARRAY &&
            sh->sh_type != SHT_FINI_ARRAY &&
            strcmp(sh_name, ".stabstr")
            )
            continue;
        if (sh->sh_addralign < 1)
            sh->sh_addralign = 1;
        /* find corresponding section, if any */
        for(j = 1; j < s1->nb_sections;j++) {
            s = s1->sections[j];
            if (!strcmp(s->name, sh_name)) {
                if (!strncmp(sh_name, ".gnu.linkonce", 
                             sizeof(".gnu.linkonce") - 1)) {
                    /* if a 'linkonce' section is already present, we
                       do not add it again. It is a little tricky as
                       symbols can still be defined in
                       it. */
                    sm_table[i].link_once = 1;
                    goto next;
                } else {
                    goto found;
                }
            }
        }
        /* not found: create new section */
        s = new_section(s1, sh_name, sh->sh_type, sh->sh_flags);
        /* take as much info as possible from the section. sh_link and
           sh_info will be updated later */
        s->sh_addralign = sh->sh_addralign;
        s->sh_entsize = sh->sh_entsize;
        sm_table[i].new_section = 1;
    found:
        if (sh->sh_type != s->sh_type) {
            tcc_error_noabort("invalid section type");
            goto fail;
        }

        /* align start of section */
        offset = s->data_offset;

        if (0 == strcmp(sh_name, ".stab")) {
            stab_index = i;
            goto no_align;
        }
        if (0 == strcmp(sh_name, ".stabstr")) {
            stabstr_index = i;
            goto no_align;
        }

        size = sh->sh_addralign - 1;
        offset = (offset + size) & ~size;
        if (sh->sh_addralign > s->sh_addralign)
            s->sh_addralign = sh->sh_addralign;
        s->data_offset = offset;
    no_align:
        sm_table[i].offset = offset;
        sm_table[i].s = s;
        /* concatenate sections */
        size = sh->sh_size;
        if (sh->sh_type != SHT_NOBITS) {
            unsigned char *ptr;
            lseek(fd, file_offset + sh->sh_offset, SEEK_SET);
            ptr = section_ptr_add(s, size);
            read(fd, ptr, size);
        } else {
            s->data_offset += size;
        }
    next: ;
    }

    /* //gr relocate stab strings */
    if (stab_index && stabstr_index) {
        Stab_Sym *a, *b;
        unsigned o;
        s = sm_table[stab_index].s;
        a = (Stab_Sym *)(s->data + sm_table[stab_index].offset);
        b = (Stab_Sym *)(s->data + s->data_offset);
        o = sm_table[stabstr_index].offset;
        while (a < b) 
            a->n_strx += o, a++;
    }

    /* second short pass to update sh_link and sh_info fields of new
       sections */
    for(i = 1; i < ehdr.e_shnum; i++) {
        s = sm_table[i].s;
        if (!s || !sm_table[i].new_section)
            continue;
        sh = &shdr[i];
        if (sh->sh_link > 0)
            s->link = sm_table[sh->sh_link].s;
        if (sh->sh_type == SHT_RELX) {
            s->sh_info = sm_table[sh->sh_info].s->sh_num;
            /* update backward link */
            s1->sections[s->sh_info]->reloc = s;
        }
    }
    sm = sm_table;

    /* resolve symbols */
    old_to_new_syms = tcc_mallocz(nb_syms * sizeof(int));

    sym = symtab + 1;
    for(i = 1; i < nb_syms; i++, sym++) {
        if (sym->st_shndx != SHN_UNDEF &&
            sym->st_shndx < SHN_LORESERVE) {
            sm = &sm_table[sym->st_shndx];
            if (sm->link_once) {
                /* if a symbol is in a link once section, we use the
                   already defined symbol. It is very important to get
                   correct relocations */
                if (ELFW(ST_BIND)(sym->st_info) != STB_LOCAL) {
                    name = strtab + sym->st_name;
                    sym_index = find_elf_sym(symtab_section, name);
                    if (sym_index)
                        old_to_new_syms[i] = sym_index;
                }
                continue;
            }
            /* if no corresponding section added, no need to add symbol */
            if (!sm->s)
                continue;
            /* convert section number */
            sym->st_shndx = sm->s->sh_num;
            /* offset value */
            sym->st_value += sm->offset;
        }
        /* add symbol */
        name = strtab + sym->st_name;
        sym_index = add_elf_sym(symtab_section, sym->st_value, sym->st_size, 
                                sym->st_info, sym->st_other, 
                                sym->st_shndx, name);
        old_to_new_syms[i] = sym_index;
    }

    /* third pass to patch relocation entries */
    for(i = 1; i < ehdr.e_shnum; i++) {
        s = sm_table[i].s;
        if (!s)
            continue;
        sh = &shdr[i];
        offset = sm_table[i].offset;
        switch(s->sh_type) {
        case SHT_RELX:
            /* take relocation offset information */
            offseti = sm_table[sh->sh_info].offset;
            rel_end = (ElfW_Rel *)(s->data + s->data_offset);
            for(rel = (ElfW_Rel *)(s->data + offset);
                rel < rel_end;
                rel++) {
                int type;
                unsigned sym_index;
                /* convert symbol index */
                type = ELFW(R_TYPE)(rel->r_info);
                sym_index = ELFW(R_SYM)(rel->r_info);
                /* NOTE: only one symtab assumed */
                if (sym_index >= nb_syms)
                    goto invalid_reloc;
                sym_index = old_to_new_syms[sym_index];
                /* ignore link_once in rel section. */
                if (!sym_index && !sm->link_once
#ifdef TCC_TARGET_ARM
                    && type != R_ARM_V4BX
#endif
                   ) {
                invalid_reloc:
                    tcc_error_noabort("Invalid relocation entry [%2d] '%s' @ %.8x",
                        i, strsec + sh->sh_name, rel->r_offset);
                    goto fail;
                }
                rel->r_info = ELFW(R_INFO)(sym_index, type);
                /* offset the relocation offset */
                rel->r_offset += offseti;
#ifdef TCC_TARGET_ARM
                /* Jumps and branches from a Thumb code to a PLT entry need
                   special handling since PLT entries are ARM code.
                   Unconditional bl instructions referencing PLT entries are
                   handled by converting these instructions into blx
                   instructions. Other case of instructions referencing a PLT
                   entry require to add a Thumb stub before the PLT entry to
                   switch to ARM mode. We set bit 0 of the got offset of a
                   symbol to indicate such a case. */
                if (type == R_ARM_THM_JUMP24)
                    alloc_sym_attr(s1, sym_index)->plt_thumb_stub = 1;
#endif
            }
            break;
        default:
            break;
        }
    }
    
    ret = 0;
 the_end:
    free(symtab);
    free(strtab);
    free(old_to_new_syms);
    free(sm_table);
    free(strsec);
    free(shdr);
    return ret;
}

typedef struct ArchiveHeader {
    char ar_name[16];           /* name of this member */
    char ar_date[12];           /* file mtime */
    char ar_uid[6];             /* owner uid; printed as decimal */
    char ar_gid[6];             /* owner gid; printed as decimal */
    char ar_mode[8];            /* file mode, printed as octal   */
    char ar_size[10];           /* file size, printed as decimal */
    char ar_fmag[2];            /* should contain ARFMAG */
} ArchiveHeader;

static int get_be32(const uint8_t *b)
{
    return b[3] | (b[2] << 8) | (b[1] << 16) | (b[0] << 24);
}

/* load only the objects which resolve undefined symbols */
static int tcc_load_alacarte(TCCState *s1, int fd, int size)
{
    int i, bound, nsyms, sym_index, off, ret;
    uint8_t *data;
    const char *ar_names, *p;
    const uint8_t *ar_index;
    ElfW(Sym) *sym;

    data = malloc(size);
    if (read(fd, data, size) != size)
        goto fail;
    nsyms = get_be32(data);
    ar_index = data + 4;
    ar_names = ar_index + nsyms * 4;

    do {
        bound = 0;
        for(p = ar_names, i = 0; i < nsyms; i++, p += strlen(p)+1) {
            sym_index = find_elf_sym(symtab_section, p);
            if(sym_index) {
                sym = &((ElfW(Sym) *)symtab_section->data)[sym_index];
                if(sym->st_shndx == SHN_UNDEF) {
                    off = get_be32(ar_index + i * 4) + sizeof(ArchiveHeader);
#if 0
                    printf("%5d\t%s\t%08x\n", i, p, sym->st_shndx);
#endif
                    ++bound;
                    lseek(fd, off, SEEK_SET);
                    if(tcc_load_object_file(s1, fd, off) < 0) {
                    fail:
                        ret = -1;
                        goto the_end;
                    }
                }
            }
        }
    } while(bound);
    ret = 0;
 the_end:
    free(data);
    return ret;
}

/* load a '.a' file */
ST_FUNC int tcc_load_archive(TCCState *s1, int fd)
{
    ArchiveHeader hdr;
    char ar_size[11];
    char ar_name[17];
    char magic[8];
    int size, len, i;
    unsigned long file_offset;

    /* skip magic which was already checked */
    read(fd, magic, sizeof(magic));
    
    for(;;) {
        len = read(fd, &hdr, sizeof(hdr));
        if (len == 0)
            break;
        if (len != sizeof(hdr)) {
            tcc_error_noabort("invalid archive");
            return -1;
        }
        memcpy(ar_size, hdr.ar_size, sizeof(hdr.ar_size));
        ar_size[sizeof(hdr.ar_size)] = '\0';
        size = strtol(ar_size, NULL, 0);
        memcpy(ar_name, hdr.ar_name, sizeof(hdr.ar_name));
        for(i = sizeof(hdr.ar_name) - 1; i >= 0; i--) {
            if (ar_name[i] != ' ')
                break;
        }
        ar_name[i + 1] = '\0';
        //        printf("name='%s' size=%d %s\n", ar_name, size, ar_size);
        file_offset = lseek(fd, 0, SEEK_CUR);
        /* align to even */
        size = (size + 1) & ~1;
        if (!strcmp(ar_name, "/")) {
            /* coff symbol table : we handle it */
            if(s1->alacarte_link)
                return tcc_load_alacarte(s1, fd, size);
        } else if (!strcmp(ar_name, "//") ||
                   !strcmp(ar_name, "__.SYMDEF") ||
                   !strcmp(ar_name, "__.SYMDEF/") ||
                   !strcmp(ar_name, "ARFILENAMES/")) {
            /* skip symbol table or archive names */
        } else {
            if (tcc_load_object_file(s1, fd, file_offset) < 0)
                return -1;
        }
        lseek(fd, file_offset + size, SEEK_SET);
    }
    return 0;
}

#ifndef TCC_TARGET_PE
/* load a DLL and all referenced DLLs. 'level = 0' means that the DLL
   is referenced by the user (so it should be added as DT_NEEDED in
   the generated ELF file) */
ST_FUNC int tcc_load_dll(TCCState *s1, int fd, const char *filename, int level)
{ 
    ElfW(Ehdr) ehdr;
    ElfW(Shdr) *shdr, *sh, *sh1;
    int i, j, nb_syms, nb_dts, sym_bind, ret;
    ElfW(Sym) *sym, *dynsym;
    ElfW(Dyn) *dt, *dynamic;
    unsigned char *dynstr;
    const char *name, *soname;
    DLLReference *dllref;
    
    read(fd, &ehdr, sizeof(ehdr));

    /* test CPU specific stuff */
    if (ehdr.e_ident[5] != ELFDATA2LSB ||
        ehdr.e_machine != EM_TCC_TARGET) {
        tcc_error_noabort("bad architecture");
        return -1;
    }

    /* read sections */
    shdr = load_data(fd, ehdr.e_shoff, sizeof(ElfW(Shdr)) * ehdr.e_shnum);

    /* load dynamic section and dynamic symbols */
    nb_syms = 0;
    nb_dts = 0;
    dynamic = NULL;
    dynsym = NULL; /* avoid warning */
    dynstr = NULL; /* avoid warning */
    for(i = 0, sh = shdr; i < ehdr.e_shnum; i++, sh++) {
        switch(sh->sh_type) {
        case SHT_DYNAMIC:
            nb_dts = sh->sh_size / sizeof(ElfW(Dyn));
            dynamic = load_data(fd, sh->sh_offset, sh->sh_size);
            break;
        case SHT_DYNSYM:
            nb_syms = sh->sh_size / sizeof(ElfW(Sym));
            dynsym = load_data(fd, sh->sh_offset, sh->sh_size);
            sh1 = &shdr[sh->sh_link];
            dynstr = load_data(fd, sh1->sh_offset, sh1->sh_size);
            break;
        default:
            break;
        }
    }
    
    /* compute the real library name */
    soname = tcc_basename(filename);
        
    for(i = 0, dt = dynamic; i < nb_dts; i++, dt++) {
        if (dt->d_tag == DT_SONAME) {
            soname = dynstr + dt->d_un.d_val;
        }
    }

    /* if the dll is already loaded, do not load it */
    for(i = 0; i < s1->nb_loaded_dlls; i++) {
        dllref = s1->loaded_dlls[i];
        if (!strcmp(soname, dllref->name)) {
            /* but update level if needed */
            if (level < dllref->level)
                dllref->level = level;
            ret = 0;
            goto the_end;
        }
    }
    
    //    printf("loading dll '%s'\n", soname);

    /* add the dll and its level */
    dllref = tcc_mallocz(sizeof(DLLReference) + strlen(soname));
    dllref->level = level;
    strcpy(dllref->name, soname);
    dynarray_add((void ***)&s1->loaded_dlls, &s1->nb_loaded_dlls, dllref);

    /* add dynamic symbols in dynsym_section */
    for(i = 1, sym = dynsym + 1; i < nb_syms; i++, sym++) {
        sym_bind = ELFW(ST_BIND)(sym->st_info);
        if (sym_bind == STB_LOCAL)
            continue;
        name = dynstr + sym->st_name;
        add_elf_sym(s1->dynsymtab_section, sym->st_value, sym->st_size,
                    sym->st_info, sym->st_other, sym->st_shndx, name);
    }

    /* load all referenced DLLs */
    for(i = 0, dt = dynamic; i < nb_dts; i++, dt++) {
        switch(dt->d_tag) {
        case DT_NEEDED:
            name = dynstr + dt->d_un.d_val;
            for(j = 0; j < s1->nb_loaded_dlls; j++) {
                dllref = s1->loaded_dlls[j];
                if (!strcmp(name, dllref->name))
                    goto already_loaded;
            }
            if (tcc_add_dll(s1, name, AFF_REFERENCED_DLL) < 0) {
                tcc_error_noabort("referenced dll '%s' not found", name);
                ret = -1;
                goto the_end;
            }
        already_loaded:
            break;
        }
    }
    ret = 0;
 the_end:
    free(dynstr);
    free(dynsym);
    free(dynamic);
    free(shdr);
    return ret;
}

#define LD_TOK_NAME 256
#define LD_TOK_EOF  (-1)

/* return next ld script token */
static int ld_next(TCCState *s1, char *name, int name_size)
{
    int c;
    char *q;

 redo:
    switch(ch) {
    case ' ':
    case '\t':
    case '\f':
    case '\v':
    case '\r':
    case '\n':
        inp();
        goto redo;
    case '/':
        minp();
        if (ch == '*') {
            file->buf_ptr = parse_comment(file->buf_ptr);
            ch = file->buf_ptr[0];
            goto redo;
        } else {
            q = name;
            *q++ = '/';
            goto parse_name;
        }
        break;
    /* case 'a' ... 'z': */
    case 'a':
       case 'b':
       case 'c':
       case 'd':
       case 'e':
       case 'f':
       case 'g':
       case 'h':
       case 'i':
       case 'j':
       case 'k':
       case 'l':
       case 'm':
       case 'n':
       case 'o':
       case 'p':
       case 'q':
       case 'r':
       case 's':
       case 't':
       case 'u':
       case 'v':
       case 'w':
       case 'x':
       case 'y':
       case 'z':
    /* case 'A' ... 'z': */
    case 'A':
       case 'B':
       case 'C':
       case 'D':
       case 'E':
       case 'F':
       case 'G':
       case 'H':
       case 'I':
       case 'J':
       case 'K':
       case 'L':
       case 'M':
       case 'N':
       case 'O':
       case 'P':
       case 'Q':
       case 'R':
       case 'S':
       case 'T':
       case 'U':
       case 'V':
       case 'W':
       case 'X':
       case 'Y':
       case 'Z':
    case '_':
    case '\\':
    case '.':
    case '$':
    case '~':
        q = name;
    parse_name:
        for(;;) {
            if (!((ch >= 'a' && ch <= 'z') ||
                  (ch >= 'A' && ch <= 'Z') ||
                  (ch >= '0' && ch <= '9') ||
                  strchr("/.-_+=$:\\,~", ch)))
                break;
            if ((q - name) < name_size - 1) {
                *q++ = ch;
            }
            minp();
        }
        *q = '\0';
        c = LD_TOK_NAME;
        break;
    case CH_EOF:
        c = LD_TOK_EOF;
        break;
    default:
        c = ch;
        inp();
        break;
    }
#if 0
    printf("tok=%c %d\n", c, c);
    if (c == LD_TOK_NAME)
        printf("  name=%s\n", name);
#endif
    return c;
}

static int ld_add_file(TCCState *s1, const char filename[])
{
    int ret;

    ret = tcc_add_file_internal(s1, filename, 0);
    if (ret)
        ret = tcc_add_dll(s1, filename, 0);
    return ret;
}

static inline int new_undef_syms(void)
{
    int ret = 0;
    ret = new_undef_sym;
    new_undef_sym = 0;
    return ret;
}

static int ld_add_file_list(TCCState *s1, const char *cmd, int as_needed)
{
    char filename[1024], libname[1024];
    int t, group, nblibs = 0, ret = 0;
    char **libs = NULL;

    group = !strcmp(cmd, "GROUP");
    if (!as_needed)
        new_undef_syms();
    t = ld_next(s1, filename, sizeof(filename));
    if (t != '(')
        expect("(");
    t = ld_next(s1, filename, sizeof(filename));
    for(;;) {
        libname[0] = '\0';
        if (t == LD_TOK_EOF) {
            tcc_error_noabort("unexpected end of file");
            ret = -1;
            goto lib_parse_error;
        } else if (t == ')') {
            break;
        } else if (t == '-') {
            t = ld_next(s1, filename, sizeof(filename));
            if ((t != LD_TOK_NAME) || (filename[0] != 'l')) {
                tcc_error_noabort("library name expected");
                ret = -1;
                goto lib_parse_error;
            }
            pstrcpy(libname, sizeof libname, &filename[1]);
            if (s1->static_link) {
                snprintf(filename, sizeof filename, "lib%s.a", libname);
            } else {
                snprintf(filename, sizeof filename, "lib%s.so", libname);
            }
        } else if (t != LD_TOK_NAME) {
            tcc_error_noabort("filename expected");
            ret = -1;
            goto lib_parse_error;
        }
        if (!strcmp(filename, "AS_NEEDED")) {
            ret = ld_add_file_list(s1, cmd, 1);
            if (ret)
                goto lib_parse_error;
        } else {
            /* TODO: Implement AS_NEEDED support. Ignore it for now */
            if (!as_needed) {
                ret = ld_add_file(s1, filename);
                if (ret)
                    goto lib_parse_error;
                if (group) {
                    /* Add the filename *and* the libname to avoid future conversions */
                    dynarray_add((void ***) &libs, &nblibs, strdup(filename));
                    if (libname[0] != '\0')
                        dynarray_add((void ***) &libs, &nblibs, strdup(libname));
                }
            }
        }
        t = ld_next(s1, filename, sizeof(filename));
        if (t == ',') {
            t = ld_next(s1, filename, sizeof(filename));
        }
    }
    if (group && !as_needed) {
        while (new_undef_syms()) {
            int i;

            for (i = 0; i < nblibs; i ++)
                ld_add_file(s1, libs[i]);
        }
    }
lib_parse_error:
    dynarray_reset(&libs, &nblibs);
    return ret;
}

/* interpret a subset of GNU ldscripts to handle the dummy libc.so
   files */
ST_FUNC int tcc_load_ldscript(TCCState *s1)
{
    char cmd[64];
    char filename[1024];
    int t, ret;
    
    ch = file->buf_ptr[0];
    ch = handle_eob();
    for(;;) {
        t = ld_next(s1, cmd, sizeof(cmd));
        if (t == LD_TOK_EOF)
            return 0;
        else if (t != LD_TOK_NAME)
            return -1;
        if (!strcmp(cmd, "INPUT") ||
            !strcmp(cmd, "GROUP")) {
            ret = ld_add_file_list(s1, cmd, 0);
            if (ret)
                return ret;
        } else if (!strcmp(cmd, "OUTPUT_FORMAT") ||
                   !strcmp(cmd, "TARGET")) {
            /* ignore some commands */
            t = ld_next(s1, cmd, sizeof(cmd));
            if (t != '(')
                expect("(");
            for(;;) {
                t = ld_next(s1, filename, sizeof(filename));
                if (t == LD_TOK_EOF) {
                    tcc_error_noabort("unexpected end of file");
                    return -1;
                } else if (t == ')') {
                    break;
                }
            }
        } else {
            return -1;
        }
    }
    return 0;
}
#endif /* ndef TCC_TARGET_PE */
