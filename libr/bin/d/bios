# BIOS parameter block
pf.bpb .b.[8]zwbwbwwbwwwxx jmp oem_id bytes_per_sector sectors_per_cluster reserved_sectors num_fat num_dir_ent num_sectors type sectors_per_fat sectors_per_track num_heads num_hidden large_sectors
pf.ebpb16 bbbx[11]z[8]z[448].w drive_num ntflags_or_reserved signature volume_id volume_label system_id bootable_signature
pf.ebpb32 xwbbxww[12]bbbbx[11]z[8]z[420].w sectors_per_fat flags version.major version.minor root_cluster fsinfo_cluster backup_boot_cluster reserved drive_num ntflags_or_reserved signature volume_id volume_label system_id bootable_signature
pf.bpb16 ?? (bpb)bios_parameter_block (ebpb16)extended_boot_record
pf.bpb32 ?? (bpb)bios_parameter_block (ebpb32)extended_boot_record

# Data access packet (for INT 13h)
pf.dap bbwwwq size reserved sector offset segment start