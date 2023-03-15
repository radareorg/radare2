# How to report issues

Before reporting an issue on GitHub, please check that:
* You are using the most recent git version of radare2
* You are using a clean installation of radare2
* The issue has not already been reported (search
  [here](https://github.com/radareorg/radare2/issues))

When the above conditions are satisfied, feel free to submit an issue. Please
provide a precise description, and as many of the following as possible:

* Your operating system and architecture; e.g. "Windows 10 32-bit", "Debian 11
  64-bit".
* The file in use when the issue was encountered (we may add the file or a
  section of it to our test suite to avoid regressions).
* A backtrace, if the issue is a segmentation fault. You can compile with ASan
  on Linux using `sys/sanitize.sh` to allow easier diagnosis of such issues.
* Detailed steps to reproduce the issue, including a list of commands and
  expected and/or actual output.

# How to contribute

There are a few guidelines that we ask contributors to follow to ensure that
the codebase is clean and consistent.

## Getting Started

* Make sure you have a GitHub account and a basic understanding of `git`. If
  you don't know how to use `git`, there is a useful guide
  [here](https://learnxinyminutes.com/docs/git).
* Fork the repository on GitHub (there should be a "Fork" button on the top
  right of the repository home page).
* Create a branch on your fork based off of `master`. Please avoid working
  directly on the `master` branch. This will make it easier to prepare your
  changes for merging when it's ready.

```sh
git checkout master
git checkout -b mybranch
```

* Make commits of logical units. Try not to make several unrelated changes in
  the same commit, but don't feel obligated to split them up too much either.
  Ideally, r2 should successfully compile at each commit. This simplifies the
  debugging process, as it allows easier use of tools such as `git bisect`
  alongside the `r2r` testing suite to identify when a bug is introduced.
* Check for coding style issues with:

```sh
git diff master..mybranch | sys/clang-format-diff.py -p1
```

  For more on the coding style, see [DEVELOPERS.md](DEVELOPERS.md).
* Open a [pull request](https://github.com/radareorg/radare2/pulls) (PR) on
  Github.
* Prefix the PR title with `WIP:` and mark it as a draft if you aren't ready to
  merge.
* When relevant, add or modify tests in [test/](test).

## Rebasing onto updated master

New changes are frequently pushed to the `master` branch. Before your branch
can be merged, you must resolve any conflicts with new commits made to
`master`.

To prepare your branch for merging onto `master`, you must first `rebase` it
onto the most recent commit on `radareorg/master`, then, if you already pushed
to your remote, force-`push` it to overwrite the previous commits after any
conflict resolution.

#### Step 0: Configuring git

You may wish to change default git settings to ensure you don't need to always
provide specific options. These do not need to be set again after initial
configuration unless your git settings are lost, e.g. if you delete the
repository folder and then clone it again.

If you cloned from your fork, you can add a new remote for upstream. The
commands here will assume that `origin` is your fork and `radareorg` is
upstream, but you can name them as you choose.

```sh
# Use SSH
git remote add radareorg git@github.com:radareorg/radare2.git

# Use HTTPS
git remote add radareorg https://github.com/radareorg/radare2
```

radare2 uses the `squash` merging style to summarize changes. When your changes
are merged, the merging collaborator can customize the commit message that will
be used in `master`. Typically, the pull request title is used as the commit
message. Specific or smaller changes may be included in the body.

Default settings may create "merge commits" when pulling from upstream, which
can cause issues. Set `merge` and `pull` to fast-forward only to avoid this.

```sh
git config merge.ff only
git config pull.ff only
```

#### Step 1: Pull new commits to `master` from upstream

```sh
git checkout master
git pull radareorg master
```

You may need to add the `-f` flag to force the pull if it is rejected. If you
have made commits to your local `master` branch (not recommended!), this may
overwrite them.

If there are new commits to master, you will see the list of changed files. If
there are no updates, you will see `Already up to date.`.

#### Step 2: Rebase `mybranch` onto master

```sh
git checkout mybranch
git rebase master
```

You may optionally use the interactive mode. This allows you to reorder,
`reword`, `edit`, or `squash` your commits into fewer individual commits.

```sh
git rebase -i master
```

Again, you must resolve any conflicts that occur before you can merge.

If you are concerned about potential loss of work, you can back up your code by
creating a new branch using your feature branch as a base before rebasing.

```sh
git checkout mybranch
git branch backup
git rebase master
```

#### Step 3: Publish your updated local branch

If you have not pushed this branch before:

```sh
git push -u origin mybranch
```

If you are updating an existing branch:

```sh
git push -f
```

The `-f` flag may be needed to `force` the push onto the remote if you are
replacing existing commits on the remote because git commits are immutable -
this discards the old commits on your remote, and git won't take potentially
destructive actions without confirmation.

## Commit message guidelines

When committing changes, we ask that you follow some guidelines to keep the
history readable and consistent:

* Start the message capitalized (only the first character must be in uppercase)
* Be concise. A descriptive message under 100 characters is preferred, but may
  not be possible in all situations. For large commits, it is acceptable to use
  a summary line, followed by an empty line, then an asterisk item list of
  changes.
* If a command is inlined, use backticks, e.g.:

```sh
git commit -m 'Modify output of `ls`'
```

* Add a tag if the change falls into a relevant category (see below)
* If the commit fixes an issue, you may optionally start the message with
  `Fix #number - `
* Use present simple tense and avoid past tense. Use "add", "fix", or "change"
  instead of "added", "fixed", or "changed".

### Commit message tag list

| Tag              | Relevant changes |
|------------------|------------------|
| `##analysis`     | Analysis |
| `##arch`         | Architecture |
| `##asm`          | Assembly (not disassembly) |
| `##bin`          | Binary parsing |
| `##build`        | Build system |
| `##config`       | Configuration variables |
| `##cons`         | Console/terminal |
| `##crypto`       | Cryptography |
| `##debug`        | Debugger |
| `##diff`         | Diffing code, strings, basic blocks, etc. |
| `##disasm`       | Disassembler |
| `##doc`          | Documentation |
| `##egg`          | The `r_lang` compiler |
| `##emu`          | Emulation, including esil |
| `##graph`        | Basic block graph, callgraph, etc. |
| `##io`           | The `r_io` library |
| `##json`         | JSON |
| `##lang`         | Language bindings |
| `##meta`         | Metadata handling, excluding printing |
| `##optimization` | Space/time optimizations |
| `##platform`     | Platform-specific code |
| `##port`         | Portability - new OS or architectures |
| `##print`        | Printing data, structures, strings, tables, types, etc. |
| `##projects`     | Saving and loading state |
| `##refactor`     | Code quality improvements |
| `##remote`       | Usage over a remote connection (TCP, HTTP, RAP, etc.), collaboration |
| `##search`       | `rafind2`, `/` command, etc. |
| `##shell`        | Command-line, argument parsing, new commands, etc. |
| `##signatures`   | Searching for or generating signatures |
| `##test`         | Testing infrastructure, including `r2r` |
| `##tools`        | `r2pm`, `rarun2`, `rax2` changes that don't fit in another category |
| `##util`         | Core APIs |
| `##visual`       | Visual UI, including panels |

# Additional resources

 * [README.md](README.md)
 * [DEVELOPERS.md](DEVELOPERS.md)
 * [USAGE.md](USAGE.md)
