# Basic block contents

`cmd.bbgraph` selects the command used to fill graph blocks. An empty value
keeps the normal disassembly and graph display modes. `e cmd.bbgraph=?` lists
suggested renderers; other commands are supported too.

| Content | Setting |
| --- | --- |
| Disassembly | `e cmd.bbgraph=` |
| Decompiler | `e cmd.bbgraph=pdcb` |
| Comments | `e cmd.bbgraph=CCb` |
| Source lines | `e cmd.bbgraph=CLLb` |
| Block summary | `e cmd.bbgraph=pdsb` |
| ESIL | `"e cmd.bbgraph=pdb @e:asm.esil=true"` |
| No body | `e graph.body=false` |

Use `e graph.body=true` to show bodies again. The visual graph's `W` key
switches between normal disassembly and `pdcb`. Right-click a graph panel and
choose Graph options > Contents to select a renderer directly. The active
choice is marked with `*`. Empty hides bodies; selecting another renderer shows
them again.

In `VV`, `p` and `P` cycle forward and backward through normal disassembly,
offsets, mini, tiny, summary, comments, and `pdcb`. The decompiler cycle entry
uses `cmd.pdc` without changing the configured `cmd.bbgraph` renderer.

`pdcb` prints only the current block's decompiled lines. It selects the backend
through `cmd.pdc`: for example, `e cmd.pdc=pdg` selects Ghidra and
`e cmd.pdc=pdd` selects r2dec. The whole function is decompiled and its address
annotations select each block's lines. Comments and source metadata are not
imported or replaced. Blocks optimized away by the decompiler have empty bodies.

Graph commands decompile once per function per render when `cmd.bbgraph=pdcb`.
The results are discarded after the render, so edits and backend changes take
effect on the next request. Hidden bodies skip rendering. `graph.bb.maxsize`
limits the default disassembly; custom commands control their own input ranges.

For frontends, `agfj` and `agfJ` include a `body` string in each block when a
custom renderer is selected. Existing instruction metadata stays in `ops`.
Fetch the whole graph once to obtain every block's contents, including
decompilation, without invoking `pdcb` separately for every block. `agf*` and
`agfd` also use the selected renderer.
