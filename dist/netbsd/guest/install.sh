#!/bin/sh
# Runs inside the NetBSD guest as root, with the transfer cd mounted on /mnt.
# Installs radare2 and tunes the image for the v86 browser console.
set -x

echo "[r2] installing radare2 into /usr/local"
tar -xzpf /mnt/r2.tgz -C /
# let ld.elf_so find the radare2 shared libraries
echo /usr/local/lib > /etc/ld.so.conf

# the stock GENERIC kernel cannot boot under v86 (see ../README.md); install
# the custom one as the default and keep GENERIC around as a fallback
echo "[r2] installing the v86 kernel"
cp /netbsd /netbsd.generic
cp /mnt/netbsd.v86 /netbsd

# boot on the VGA console (anita installs with the serial console) and
# skip the boot menu delay
grep -v -e '^consdev' -e '^timeout' /boot.cfg > /tmp/boot.cfg
echo 'consdev=pc' >> /tmp/boot.cfg
echo 'timeout=1' >> /tmp/boot.cfg
cp /tmp/boot.cfg /boot.cfg

# auto-login root on the VGA console; typing passwords on a phone keyboard
# is no fun. sysinst (driven over the serial console) leaves a getty on
# "console", so put that one to sleep and autologin on the wscons terminal.
printf '\n# autologin for the browser console\nAl|Autologin console:al=root:tc=Pc\n' >> /etc/gettytab
# rewrite the console entries wholesale; the field separators are tabs and
# sysinst enables gettys on both console and constty for serial installs
grep -v -e '^console[ 	]' -e '^constty[ 	]' -e '^ttyE0[ 	]' /etc/ttys > /tmp/ttys
printf 'console\t"/usr/libexec/getty Pc"\twsvt25\toff\tsecure\n' >> /tmp/ttys
printf 'constty\t"/usr/libexec/getty Pc"\twsvt25\toff\tsecure\n' >> /tmp/ttys
printf 'ttyE0\t"/usr/libexec/getty Al"\twsvt25\ton\tsecure\n' >> /tmp/ttys
cp /tmp/ttys /etc/ttys

# keep the boot quick and quiet: no network daemons, and a hostname so
# postfix does not error out at startup
{
	echo 'hostname=r2netbsd'
	echo 'wscons=YES'
	echo 'dhcpcd=NO'
	echo 'ntpd=NO'
	echo 'sshd=NO'
	echo 'postfix=NO'
} >> /etc/rc.conf

# `mount /mnt` picks up cds built by the browser upload button
echo '/dev/cd0a /mnt cd9660 ro,noauto 0 0' >> /etc/fstab

printf 'export PATH=$PATH:/usr/local/bin:/usr/local/sbin\n' >> /root/.profile

# the wscons console emulates vt100: it understands the 8/16 basic ansi
# colors but not the 256-color or truecolor escapes, which r2 picks by
# default on many terminals -- those just come out uncoloured
printf 'e scr.color=1\n' > /root/.radare2rc

# v86 derives its timers from the browser clock, which is not monotonic, so
# NetBSD complains "timecounter went backwards". pin the timecounter:
# clockinterrupt (10ms) just counts ticks and cannot go backwards, i8254 is
# finer grained but samples the jittery clock. see ../Makefile
printf 'kern.timecounter.hardware=@TIMECOUNTER@\n' >> /etc/sysctl.conf

# one-shot: the build pipeline boots the freshly injected image once so that
# fsck repairs the superblocks and marks the file system clean *on disk*.
# without it every browser boot redoes the repair (its writes are volatile)
cat >> /etc/rc.local <<'EOF'
if [ -f /.settle ]; then
	rm -f /.settle
	sync
	/sbin/shutdown -p now
fi
EOF
touch /.settle

# leave a hint; rc.d/motd rewrites the first two lines on boot, keeps the rest
{
	echo 'NetBSD'
	echo ''
	echo 'Welcome to the radare2 NetBSD playground.'
	echo '  r2 /bin/ls     inspect a binary (radare2 lives in /usr/local)'
	echo '  mount /mnt     access files uploaded from the browser'
} > /etc/motd

sync
