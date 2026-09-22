# How IO should work

* Maps: Used to select fd. Mapaddr..size
* Sections: Used to specify vaddr <-> paddr

Manually selecting fd is still valid and it should override maps fdselection. This is.. We need a way to tell r2 to view one fd or all of them. In case of having two files mapped on the same address space we will select the last opened.

The base address is used to reallocate all vaddr offsets.

Reading/writing ops should be done in a loop checking for the section boundaries.

The sections must be associated to a file, but we should be able to display/use them all in case of having non forced fd. This is, when not having overlapped files in memory.

The write ops should only obey to the global io configuration and ignore the section permissions (maybe just throw a warning?)

Atm sections are dupped in io and bin. We should merge them. Maybe using sdb, so we just reuse it

## Descriptor information

`r_io_desc_info(desc)` returns the `blkdev`, `chrdev` and `isdbg` flags in an
`RIODescInfo`. A null descriptor or a descriptor without a plugin returns zeroed flags.
Plugins can provide `getinfo` to report per-descriptor flags; the plugin's static
`isdbg` flag is ORed with the callback result. Without a callback, only the static
debugger flag is used. Keep this callback cheap and free of side effects: it runs
during reads, writes and debugger queries.

This replaces the `is_blockdevice` and `is_chardevice` plugin callbacks and their
`r_io_desc_*` / `r_io_fd_*` helpers. For an fd, use
`r_io_desc_info(r_io_desc_get(io, fd))`. The `r_io_desc_is_dbg` and `r_io_fd_is_dbg`
helpers are also replaced by the `isdbg` field. `RIOBind.desc_info` exposes the same
query to bound consumers, replacing `fd_is_dbg`. The PID, TID and base callbacks are unchanged.
External IO plugins must migrate their device callbacks and rebuild for the new ABI.
