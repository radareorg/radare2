/* radare - LGPL - Copyright 2010-2016 - pancake, alvaro_fe */

static void r_mach_swap_header(struct MACH0_(mach_header) *mh, bool endian) {
	mh->magic      = r_read_ble32 (&mh->magic, endian);
	mh->cputype    = r_read_ble32 (&mh->cputype, endian);
	mh->cpusubtype = r_read_ble32 (&mh->cpusubtype, endian);
	mh->filetype   = r_read_ble32 (&mh->filetype, endian);
	mh->ncmds      = r_read_ble32 (&mh->ncmds, endian);
	mh->sizeofcmds = r_read_ble32 (&mh->sizeofcmds, endian);
	mh->flags      = r_read_ble32 (&mh->flags, endian);
}

static void r_mach_swap_load_command(struct load_command *lc, bool endian) {
	lc->cmd     = r_read_ble32 (&lc->cmd, endian);
	lc->cmdsize = r_read_ble32 (&lc->cmdsize, endian);
}


static void r_mach_swap_segment32(struct segment_command *sg, bool endian) {
	/* segname[16] */
	sg->cmd      = r_read_ble32 (&sg->cmd, endian);
	sg->cmdsize  = r_read_ble32 (&sg->cmdsize, endian);
	sg->vmaddr   = r_read_ble32 (&sg->vmaddr, endian);
	sg->vmsize   = r_read_ble32 (&sg->vmsize, endian);
	sg->fileoff  = r_read_ble32 (&sg->fileoff, endian);
	sg->filesize = r_read_ble32 (&sg->filesize, endian);
	sg->maxprot  = r_read_ble32 (&sg->maxprot, endian);
	sg->initprot = r_read_ble32 (&sg->initprot, endian);
	sg->nsects   = r_read_ble32 (&sg->nsects, endian);
	sg->flags    = r_read_ble32 (&sg->flags, endian);
}


static void r_mach_swap_segment64(struct segment_command_64 *sg, bool endian) {
	/* segname[16] */
	sg->cmd      = r_read_ble32 (&sg->cmd, endian);
	sg->cmdsize  = r_read_ble32 (&sg->cmdsize, endian);
	sg->vmaddr   = r_read_ble64 (&sg->vmaddr, endian);
	sg->vmsize   = r_read_ble64 (&sg->vmsize, endian);
	sg->fileoff  = r_read_ble64 (&sg->fileoff, endian);
	sg->filesize = r_read_ble64 (&sg->filesize, endian);
	sg->maxprot  = r_read_ble32 (&sg->maxprot, endian);
	sg->initprot = r_read_ble32 (&sg->initprot, endian);
	sg->nsects   = r_read_ble32 (&sg->nsects, endian);
	sg->flags    = r_read_ble32 (&sg->flags, endian);
}


static void r_mach_swap_segment(struct MACH0_(segment_command) *seg, bool is_64, bool endian) {
    	if (is_64) r_mach_swap_segment64 ((struct segment_command_64 *)seg, endian);
	else r_mach_swap_segment32 ((struct segment_command *)seg, endian);
}


static void r_mach_swap_section32(struct section *s, ut32 nsects, bool endian) {
	ut32 i;
	for (i = 0; i < nsects; i++) {
		/* sectname[16] */
		/* segname[16] */
		s[i].addr      = r_read_ble32 (&s[i].addr, endian);
		s[i].size      = r_read_ble32 (&s[i].size, endian);
		s[i].offset    = r_read_ble32 (&s[i].offset, endian);
		s[i].align     = r_read_ble32 (&s[i].align, endian);
		s[i].reloff    = r_read_ble32 (&s[i].reloff, endian);
		s[i].nreloc    = r_read_ble32 (&s[i].nreloc, endian);
		s[i].flags     = r_read_ble32 (&s[i].flags, endian);
		s[i].reserved1 = r_read_ble32 (&s[i].reserved1, endian);
		s[i].reserved2 = r_read_ble32 (&s[i].reserved2, endian);
	}
}


static void r_mach_swap_section64(struct section_64 *s, ut32 nsects, bool endian) {
	ut32 i;
	for (i = 0; i < nsects; i++) {
		/* sectname[16] */
		/* segname[16] */
		s[i].addr      = r_read_ble64 (&s[i].addr, endian);
		s[i].size      = r_read_ble64 (&s[i].size, endian);
		s[i].offset    = r_read_ble32 (&s[i].offset, endian);
		s[i].align     = r_read_ble32 (&s[i].align, endian);
		s[i].reloff    = r_read_ble32 (&s[i].reloff, endian);
		s[i].nreloc    = r_read_ble32 (&s[i].nreloc, endian);
		s[i].flags     = r_read_ble32 (&s[i].flags, endian);
		s[i].reserved1 = r_read_ble32 (&s[i].reserved1, endian);
		s[i].reserved2 = r_read_ble32 (&s[i].reserved2, endian);
	}
}


static void r_mach_swap_sections(struct MACH0_(section) *s, ut32 nsects, bool is_64, bool endian) {
    	if (is_64) r_mach_swap_section64 ((struct section_64 *)s, nsects, endian);
	else r_mach_swap_section32 ((struct section *)s, nsects, endian);
}

static void r_mach_swap_symtab(struct symtab_command *st, bool endian) {
	st->cmd     = r_read_ble32 (&st->cmd, endian);
	st->cmdsize = r_read_ble32 (&st->cmdsize, endian);
	st->symoff  = r_read_ble32 (&st->symoff, endian);
	st->nsyms   = r_read_ble32 (&st->nsyms, endian);
	st->stroff  = r_read_ble32 (&st->stroff, endian);
	st->strsize = r_read_ble32 (&st->strsize, endian);
}


static void r_mach_swap_nlist_32(struct nlist *symbols, ut32 nsymbols, bool endian) {
	ut32 i;
	for (i = 0; i < nsymbols; i++) {
		symbols[i].n_un.n_strx = r_read_ble32 (&symbols[i].n_un.n_strx, endian);
		/* n_type */
		/* n_sect */
		symbols[i].n_desc  = r_read_ble16 (&symbols[i].n_desc, endian);
		symbols[i].n_value = r_read_ble32 (&symbols[i].n_value, endian);
	}
}

static void r_mach_swap_nlist_64(struct nlist_64 *symbols, ut32 nsymbols, bool endian) {
	ut32 i;
	for (i = 0; i < nsymbols; i++) {
		symbols[i].n_un.n_strx = r_read_ble32 (&symbols[i].n_un.n_strx, endian);
		/* n_type */
		/* n_sect */
		symbols[i].n_desc  = r_read_ble16 (&symbols[i].n_desc, endian);
		symbols[i].n_value = r_read_ble64 (&symbols[i].n_value, endian);
	}
}

static void r_mach_swap_nlist(struct MACH0_(nlist) *sym,  ut32 nsym, bool is_64, bool endian) {
    	if (is_64) r_mach_swap_nlist_64 ((struct nlist_64 *)sym, nsym, endian);
	else r_mach_swap_nlist_32 ((struct nlist *)sym, nsym, endian);
}

static void r_mach_swap_dysymtab(struct dysymtab_command *dyst, bool endian) {
	dyst->cmd	     = r_read_ble32 (&dyst->cmd, endian);
	dyst->cmdsize	     = r_read_ble32 (&dyst->cmdsize, endian);
	dyst->ilocalsym      = r_read_ble32 (&dyst->ilocalsym, endian);
	dyst->nlocalsym      = r_read_ble32 (&dyst->nlocalsym, endian);
	dyst->iextdefsym     = r_read_ble32 (&dyst->iextdefsym, endian);
	dyst->nextdefsym     = r_read_ble32 (&dyst->nextdefsym, endian);
	dyst->iundefsym      = r_read_ble32 (&dyst->iundefsym, endian);
	dyst->nundefsym      = r_read_ble32 (&dyst->nundefsym, endian);
	dyst->tocoff	     = r_read_ble32 (&dyst->tocoff, endian);
	dyst->ntoc	     = r_read_ble32 (&dyst->ntoc, endian);
	dyst->modtaboff      = r_read_ble32 (&dyst->modtaboff, endian);
	dyst->nmodtab	     = r_read_ble32 (&dyst->nmodtab, endian);
	dyst->extrefsymoff   = r_read_ble32 (&dyst->extrefsymoff, endian);
	dyst->nextrefsyms    = r_read_ble32 (&dyst->nextrefsyms, endian);
	dyst->indirectsymoff = r_read_ble32 (&dyst->indirectsymoff, endian);
	dyst->nindirectsyms  = r_read_ble32 (&dyst->nindirectsyms, endian);
	dyst->extreloff      = r_read_ble32 (&dyst->extreloff, endian);
	dyst->nextrel 	     = r_read_ble32 (&dyst->nextrel, endian);
	dyst->locreloff      = r_read_ble32 (&dyst->locreloff, endian);
	dyst->nlocrel 	     = r_read_ble32 (&dyst->nlocrel, endian);
}

static void r_mach_swap_dylib_toc(struct dylib_table_of_contents *tocs, ut32 ntocs, bool endian) {

	ut32 i;
	for (i = 0; i < ntocs; i++) {
		tocs[i].symbol_index = r_read_ble32 (&tocs[i].symbol_index, endian);
		tocs[i].module_index = r_read_ble32 (&tocs[i].module_index, endian);
	}
}

static void r_mach_swap_dylib_module_32(struct dylib_module *mods, ut32 nmods, bool endian) {
	ut32 i;
	for (i = 0; i < nmods; i++) {
		mods[i].module_name = r_read_ble32 (&mods[i].module_name, endian);
		mods[i].iextdefsym  = r_read_ble32 (&mods[i].iextdefsym, endian);
		mods[i].nextdefsym  = r_read_ble32 (&mods[i].nextdefsym, endian);
		mods[i].irefsym     = r_read_ble32 (&mods[i].irefsym, endian);
		mods[i].nrefsym     = r_read_ble32 (&mods[i].nrefsym, endian);
		mods[i].ilocalsym   = r_read_ble32 (&mods[i].ilocalsym, endian);
		mods[i].nlocalsym   = r_read_ble32 (&mods[i].nlocalsym, endian);
		mods[i].iextrel     = r_read_ble32 (&mods[i].iextrel, endian);
		mods[i].nextrel     = r_read_ble32 (&mods[i].nextrel, endian);
		mods[i].iinit_iterm = r_read_ble32 (&mods[i].iinit_iterm, endian);
		mods[i].ninit_nterm = r_read_ble32 (&mods[i].ninit_nterm, endian);
		mods[i].objc_module_info_size = r_read_ble32 (&mods[i].objc_module_info_size, endian);
		mods[i].objc_module_info_addr = r_read_ble32 (&mods[i].objc_module_info_addr, endian);
	}
}

static void r_mach_swap_dylib_module_64(struct dylib_module_64 *mods, ut32 nmods, bool endian) {
	ut32 i;
	for (i = 0; i < nmods; i++) {
		mods[i].module_name = r_read_ble32 (&mods[i].module_name, endian);
		mods[i].iextdefsym  = r_read_ble32 (&mods[i].iextdefsym, endian);
		mods[i].nextdefsym  = r_read_ble32 (&mods[i].nextdefsym, endian);
		mods[i].irefsym     = r_read_ble32 (&mods[i].irefsym, endian);
		mods[i].nrefsym     = r_read_ble32 (&mods[i].nrefsym, endian);
		mods[i].ilocalsym   = r_read_ble32 (&mods[i].ilocalsym, endian);
		mods[i].nlocalsym   = r_read_ble32 (&mods[i].nlocalsym, endian);
		mods[i].iextrel     = r_read_ble32 (&mods[i].iextrel, endian);
		mods[i].nextrel     = r_read_ble32 (&mods[i].nextrel, endian);
		mods[i].iinit_iterm = r_read_ble32 (&mods[i].iinit_iterm, endian);
		mods[i].ninit_nterm = r_read_ble32 (&mods[i].ninit_nterm, endian);
		mods[i].objc_module_info_size = r_read_ble32 (&mods[i].objc_module_info_size, endian);
		mods[i].objc_module_info_addr = r_read_ble64 (&mods[i].objc_module_info_addr, endian);
	}
}

static void r_mach_swap_dylib_module(struct MACH0_(dylib_module) *dylib, ut32 nmods, bool is_64, bool endian) {
    	if (is_64) r_mach_swap_dylib_module_64 ((struct dylib_module_64 *)dylib, nmods, endian);
	else r_mach_swap_dylib_module_32 ((struct dylib_module *)dylib, nmods, endian);
}

static void r_mach_swap_indirect_symbols(uint32_t *indirect_symbols, ut32 nindirect_symbols, bool endian) {
	ut32 i;
	for (i = 0; i < nindirect_symbols; i++)
		indirect_symbols[i] = r_read_ble32 (&indirect_symbols[i], endian);
}

static void r_mach_swap_linkedit_data_command(struct linkedit_data_command *ld, bool endian) {
	ld->cmd      = r_read_ble32 (&ld->cmd, endian);
	ld->cmdsize  = r_read_ble32 (&ld->cmdsize, endian);
	ld->dataoff  = r_read_ble32 (&ld->dataoff, endian);
	ld->datasize = r_read_ble32 (&ld->datasize, endian);
}

static void r_mach_swap_thread_command(struct thread_command *ut, bool endian) {
	ut->cmd     = r_read_ble32 (&ut->cmd, endian);
	ut->cmdsize = r_read_ble32 (&ut->cmdsize, endian);
}

static void r_mach_swap_dylib_command(struct dylib_command *dl, bool endian) {
	dl->cmd			  = r_read_ble32 (&dl->cmd, endian);
	dl->cmdsize		  = r_read_ble32 (&dl->cmdsize, endian);
	dl->dylib.name.offset     = r_read_ble32 (&dl->dylib.name.offset, endian);
	dl->dylib.timestamp       = r_read_ble32 (&dl->dylib.timestamp, endian);
	dl->dylib.current_version = r_read_ble32 (&dl->dylib.current_version, endian);
	dl->dylib.compatibility_version = r_read_ble32 (&dl->dylib.compatibility_version, endian);
}

static void r_mach_swap_uuid_command(struct uuid_command *uuid_cmd, bool endian) {
	uuid_cmd->cmd     = r_read_ble32 (&uuid_cmd->cmd, endian);
	uuid_cmd->cmdsize = r_read_ble32 (&uuid_cmd->cmdsize, endian);
}

static void r_mach_swap_encryption_command_32(struct encryption_info_command *ec, bool endian) {
	ec->cmd       = r_read_ble32 (&ec->cmd, endian);
	ec->cmdsize   = r_read_ble32 (&ec->cmdsize, endian);
	ec->cryptoff  = r_read_ble32 (&ec->cryptoff, endian);
	ec->cryptsize = r_read_ble32 (&ec->cryptsize, endian);
	ec->cryptid   = r_read_ble32 (&ec->cryptid, endian);
}

static void r_mach_swap_encryption_command_64(struct encryption_info_command_64 *ec, bool endian) {
	ec->cmd       = r_read_ble32 (&ec->cmd, endian);
	ec->cmdsize   = r_read_ble32 (&ec->cmdsize, endian);
	ec->cryptoff  = r_read_ble32 (&ec->cryptoff, endian);
	ec->cryptsize = r_read_ble32 (&ec->cryptsize, endian);
	ec->cryptid   = r_read_ble32 (&ec->cryptid, endian);
	ec->cryptid   = r_read_ble32 (&ec->pad, endian);
}

static void r_mach_swap_dylinker_command(struct dylinker_command *dyld, bool endian) {
	dyld->cmd	 = r_read_ble32 (&dyld->cmd, endian);
	dyld->cmdsize     = r_read_ble32 (&dyld->cmdsize, endian);
	dyld->name.offset = r_read_ble32 (&dyld->name.offset, endian);
}

static void r_mach_swap_dyld_info_command(struct dyld_info_command *ed, bool endian) {
	ed->cmd		   = r_read_ble32 (&ed->cmd, endian);
	ed->cmdsize	   = r_read_ble32 (&ed->cmdsize, endian);
	ed->rebase_off     = r_read_ble32 (&ed->rebase_off, endian);
	ed->rebase_size    = r_read_ble32 (&ed->rebase_size, endian);
	ed->bind_off       = r_read_ble32 (&ed->bind_off, endian);
	ed->bind_size      = r_read_ble32 (&ed->bind_size, endian);
	ed->weak_bind_off  = r_read_ble32 (&ed->weak_bind_off, endian);
	ed->weak_bind_size = r_read_ble32 (&ed->weak_bind_size, endian);
	ed->lazy_bind_off  = r_read_ble32 (&ed->lazy_bind_off, endian);
	ed->lazy_bind_size = r_read_ble32 (&ed->lazy_bind_size, endian);
	ed->export_off     = r_read_ble32 (&ed->export_off, endian);
	ed->export_size    = r_read_ble32 (&ed->export_size, endian);
}
