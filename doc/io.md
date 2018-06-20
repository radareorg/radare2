How IO should work
==================

* Maps

    Used to select fd. Mapaddr..size

* Sections

    Used to specify vaddr<->paddr

Manually selecting fd is still valid and it should override maps fdselection. This is.. We need a way to tell r2 to view one fd or all of them. In case of having two files mapped on the same address space we will select the last opened.

The base address is used to reallocate all vaddr offsets.

Reading/writing ops should be done in a loop checking for the section boundaries.

The sections must be asociated to a file, but we should be able to display/use them all in case of having non forced fd. This is, when not having overlapped files in memory.

The write ops should only obey to the global io configuration and ignore the section permissions (maybe just throw a warning?)

Atm sections are dupped in io and bin. We should merge them. Maybe using sdb, so we just reuse it
