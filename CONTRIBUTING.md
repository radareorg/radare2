# How to report issues

Before reporting an issue with GitHub, be sure that:
* you are using the git version of radare2
* you are using a clean installation
* the issue was not already reported

When the above conditions are satisfied, feel free to submit an issue
while trying to be as precise as possible. If you can, provide the problematic
binary, the steps to reproduce the error and a backtrace in case of SEGFAULTs.
Any information will help to fix the problem.

# How to contribute

There are a few guidelines that we need contributors to follow so that we can
try to keep the codebase consistent and clean.

## Getting Started

* Make sure you have a GitHub account and solid ability to use `git`.
* Fork the repository on GitHub.
* Create a topic branch from master. Please avoid working directly on the `master` branch.
* Make commits of logical units.
* Check for coding style issues with:

      git diff master..mybranch | ./sys/clang-format-diff.py -p1

  and be sure to follow the CODINGSTYLE (more on this in [DEVELOPERS.md][]).
* Submit the Pull Request(PR) on Github.
* When relevant, write a test in [test/](test).

## Rebasing onto updated master

Every so often, your PR will lag behind `master` and get conflicts.

To "update" your branch `my-awesome-feature`, you *rebase* it onto
the latest `radareorg/master`, and *force-push* the result into your fork.

#### Step 1: Switch to `master` branch.

    $ git checkout master

#### Step 2: Pull new commits published to radareorg repo.

    $ git pull https://github.com/radareorg/radare2

#### Step 3: Switch back to `my-awesome-feature` branch.

    $ git checkout my-awesome-feature

#### Step 4: Rebase the `my-awesome-feature` branch.

    $ git rebase master

Optionally, use the alternative mode "interactive rebase". It allows
to `squash` your commits all into one, reorder, reword them, etc.

    $ git rebase -i master

Follow git instructions when conflicts arise.

#### Step 5: publish your updated local branch.

    $ git push -f

This `-f` *force-flag* is needed because git commits are immutable: rebasing
creates newer versions of them. git needs to confirm the destruction of
previous incarnations.

When afraid to touch force and risk losing your work (do backups!..),
try *merging master into your branch* instead of rebasing onto it.
This is discouraged, as it produces ugly hard-to-maintain commit history.


# Additional resources

 * [README.md][]
 * [DEVELOPERS.md][]

[README.md]: https://github.com/radareorg/radare2/blob/master/README.md
[DEVELOPERS.md]: https://github.com/radareorg/radare2/blob/master/DEVELOPERS.md

If you need more confidence in your git skills, check out this quick guide:
<https://learnxinyminutes.com/docs/git/>
