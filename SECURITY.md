Security Policies and Procedures
================================

We take security seriously, and encourage everyone to use the last version of
radare2 from git if possible. We do not backport security fixes to old releases.

Security bugs are max priority and they all must be fixed in less than a day.

Reporting a vulnerability
-------------------------

If you discover a security issue in radare2 (or any related project under the
radareorg umbrella), please submit a public issue in the [GitHub](https://github.com/radareorg/radare2/issues) repository for that project.

If you are able to do so, we would appreciate a pull request with your suggested
fix instead of the reproducer, which is usually faster than reporting and
explaining it.

See `DEVELOPERS.md` for technical details, but in short you may want to try
`sys/sanitize.sh` (ASAN) builds and set `R2_DEBUG_ASSERT=1` to get to the point
of failure.

Disclosure policy
-----------------

We don't believe in secrecy when security matters, keeping the bugs for
yourself or for a limited amount of people results in a false sense of
security for the community.

We encourage full disclosure of any and all security bugs in radare2's codebase.

Please see the "Reporting a Bug" section for information on how to report a bug.
If you do not or can not create a GitHub account, you may email the bug details
to `pancake@nopcode.org` and we will create the issue / fix on your behalf.

Privacy
-------

While we are able to publicly acknowledge you for your contribution to radare2
for helping us keep our software secure for users, if you so choose we will
keep your contribution anonymous.

To cover those situations we recommend you to create a GitHub, Telegram or IRC
accounts and report it in the public channel, DMs to the author are also fine.

Bounties
--------

No bounty programs are available right now.
