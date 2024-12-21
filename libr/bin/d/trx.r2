# TRX v1
# offset[0] = lzma-loader
# offset[1] = Linx-Kernel
# offset[2] = rootfs
pf.TRXv1 [4]zxxwwxxx magic length crc flags version part_loader part_kernel part_rootfs

# TRX v2
# offset[0] = lzma-loader
# offset[1] = Linx-Kernel
# offset[2] = rootfs
# offset[3] = bin-Header
pf.TRXv2 [4]zxxwwxxx*? magic length crc flags version part_loader part_kernel part_rootfs (TRXv2BinHeader)part_binheader

# BinHeader
# magic: firmware magic depends on board etc. s.th. like '3G2V' or 'W54U'
# res1: reserved for extra magic??
# char fwdate[3]: fwdate[0]: Year, fwdate[1]: Month, fwdate[2]: Day
# fwvern: version information a.b.c.
# ID: fix "U2ND"
# hw_ver: depends on board
# s/n: depends on board
# flags:
# stable: Marks the firmware stable, this is 0xFF in the image and will be written to 0x73 by the running system once it completed booting.
# try1-3: 0xFF in firmware image. CFE will set try1 to 0x74 on first boot and continue with try2 and try3 unless "stable" was written by the running image. After writing try3 and the stable flag was not written yet, the CFE assumes that the image is broken and starts a TFTP server
# res3: unused?
pf.TRXv2BinHeader [4]zxxwwwwwwwwww magic res1 fwdate fwvern id0 id1 hwver flags stable try1 try2 try3 res3
# XXX td enum BinHeaderMAGIC { "3G2V", "W54U" }
