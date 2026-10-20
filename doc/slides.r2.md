# r2slides
--font=block
--markdown
--label:title
--gotokey:x:contents
--gotokey:i:insert
--notes:From the radare2 repository: r2 -i doc/slides.r2.md -. This showcase uses the current r2slides renderer. Suggested terminal: 100x32 or larger. All automatic commands are bounded, repeatable display commands. Commands in fenced blocks are literal.

## Present inside your reverse engineering session

```text
      Markdown + Unicode + live radare2
                     │
                     ▼
            a terminal presentation
```

`?E Welcome to r2land`

**n** next · **p** previous · **R** theme · **?** help

Press **x** for contents; **i** for the shell exercise.

# Contents
--font=block
--markdown
--label:contents
--gotokey:i:insert
--gotokey:f:fonts
--gotokey:t:themes
--gotokey:c:commands

This introductory course also demonstrates the viewer.

- [x] What is radare2?
- [x] How to install it
- [ ] Basic shell usage
- [ ] Scripting examples

**Feature tour:** Markdown, code, fonts, palettes, live output,
labels, two-page layout, scrolling, editing, and reload.

Jump: **f** fonts · **t** themes · **c** commands · **i** exercise

# Author a deck
--font=block
--markdown

Save a text file ending in **.r2.md**.

```markdown
# My first slide
--font=block
--markdown

## A subtitle
**Readable prose**, lists, and `inline code`.

# My second slide
--markdown
Another page starts at a level-one heading.
```

Fenced headings stay on this slide. They create no extra pages.

# Markdown
--font=block
--markdown

## Hierarchy, emphasis, and readable prose

**Bold** · *italic* · ~~struck out~~ · `inline code`

- Ordinary lists wrap within the pane
* [x] Completed checklist item
* [ ] An item still to do
* [X] Uppercase X is checked too

> A quote stands apart from ordinary body text.

[Read the format guide](r2slides.md)

---

Prose wraps to the available width when the terminal resizes.

# Tables
--font=block
--markdown

| Input | Meaning | Output |
| :--- | :--- | ---: |
| `# Heading` | New slide | Title band |
| `--markdown` | Formatted body | Wrapped prose |
| Fenced block | Literal code | Preserved indentation |
| Single-backtick line | Live r2 command | Captured output |

Table cells wrap with the pane width.

Make the terminal narrower, or press **2**, to see the layout adapt.

# Literal code
--font=block
--markdown

```c
int answer(bool ready) {
    if (ready) {
        return 42;
    }
    return 0;
}
```

```text
# This is not a new slide
--color=red
`?e This is displayed, not executed`
```

Backtick and tilde fences protect code and directives alike.

# Block titles
--font=block
--markdown
--label:fonts
--gotokey:t:themes

## Three terminal rows, real Unicode blocks

```text
   # Block titles
   --font=block
   --markdown
```

The wider block alphabet packs six pixel rows into three text rows.

Titles that cannot fit fall back to a readable single-line font.
With `scr.utf8=false`, the viewer uses an ASCII title instead.

# ASCII title spacing
--font=ascii
--markdown

## The original seven-segment title style

```text
   # ASCII title spacing
   --font=ascii
```

The existing radare2 ASCII-art font remains available.

Choose `--font=plain` for an ordinary title with a background band.

# utfmt fonts
--font=sansserifbold
--markdown

## Use the built-in r_font_render API

```text
   --font=sansserifbold
   --font=doublestruck
   --font=monospace
   --font=smallcaps
   --font=fraktur
   --font=bolditalic
```

The following slides are live title-font specimens.
Font availability also depends on your terminal's Unicode font.

# Double struck title words
--font=doublestruck
--markdown

```text
   # Double struck title words
   --font=doublestruck
```

Mathematical Unicode characters give the title a different face.

Punctuation and ordinary body text remain readable.

# Monospace title words
--font=monospace
--markdown

```text
   # Monospace title words
   --font=monospace
```

The title is formatted with utfmt's monospace alphabet.

The body keeps the terminal's ordinary monospace characters.

# Small caps preserve spaces
--font=smallcaps
--markdown

```text
   # Small caps preserve spaces
   --font=smallcaps
```

Compact Unicode typography is useful for longer titles.

Fonts are selected per slide, so navigation is predictable.

# Fraktur titles with spaces
--font=fraktur
--markdown

```text
   # Fraktur titles with spaces
   --font=fraktur
```

The same title band, a different utfmt family.

Use `bold`, `script`, `boldfraktur`, `openface`, or other utfmt
families when they fit the tone of your talk.

# Long multiword titles should wrap without losing spaces or font styling between lines
--font=monospace,ansibold
--markdown

This title intentionally exceeds one line in a normal terminal.

```text
   --font=monospace,ansibold
```

Press **2** to make the pane narrower. Every title row keeps
its font, its word spacing, and the theme's background band.

Press **1** to restore a full-width slide.

# Themes
--font=block
--markdown
--label:themes
--gotokey:c:commands

## Press R to rotate the active radare2 theme

The title and page-index backgrounds, title foreground, links,
code backgrounds, and syntax colors follow palette roles.

```c
// Watch the palette change while this text stays put.
const char *message = "hello, r2";
return 42;
```

`R` selects the next theme (`ecn`); `r` selects the previous (`ecp`).
Use **Ctrl-R** to reload the deck.
Theme changes stay active in your r2 session after the talk.

# Backgrounds
--font=block
--bgcolor=@linehl
--markdown

## This title uses the theme's linehl background

```text
   --bgcolor=theme       title band uses widget.bg
   --bgcolor=@linehl     use another theme palette role
   --bgcolor=rgb:183040  choose an explicit background
   --bgcolor=blue        named background color
   --bgcolor=none        no title background
```

Place title settings immediately after the slide heading.

Theme roles adapt when you press **R**; explicit colors stay fixed.

# Text colors
--font=block
--markdown

Use the active palette for themed accents.

--markdown=false
--color=@comment
This raw line uses the theme's comment color.
--color=@fname
This raw line uses the theme's function-name color.
--color=
--markdown

```text
   --color=@comment
   A themed accent in a raw body section.
   --color=
```

Named colors and `rgb:` values remain available for explicit overrides.

# Live CMDS
--font=block
--markdown
--label:commands
--gotokey:i:insert
--notes:These commands display output and do not modify the loaded binary. A slide command runs again on redraw, including theme rotation and resize. Keep analysis and writes manual via the colon prompt.

This result is produced by the current r2 session:

`?e Hello from a live slide`
`?v 6*7`

The source uses one backtick at each end of a whole line:

```text
`?e Hello from a live slide`
`?v 6*7`
```

Commands run on every redraw. Use bounded, repeatable output.

# Label jumps
--font=block
--markdown
--gotokey:x:title
--gotokey:i:insert

```text
   --label:title
   --gotokey:x:title
   --gotokey:i:insert
```

Press **x** to jump to the title, or **i** for the shell exercise.

Bindings belong to the displayed slide and are case-sensitive.
Built-in navigation keys take precedence.

In two-page mode, bindings from both pages are available.

# Two pages
--font=block
--markdown
--notes:Press 2 while this page is current. It pairs naturally with the following page. Each pane has its own clipping width; long left-hand content cannot overwrite the right-hand page.

## Press 2 now

```text
   ┌─────────┬─────────┐
   │ current │  next   │
   │  page   │  page   │
   └─────────┴─────────┘
```

**n / p** move by two pages.

Press **1** to return to one page.

# Alongside
--font=block
--markdown

## The following page

- Both panes wrap Markdown
- Each pane crops its content
- Scrolling offsets are shared
- Resize redraws both pages

This is handy for a diagram
and its explanation.

Live commands on this page
run before the left-hand page.

# Scrolling
--font=block
--markdown

## Move around a large slide

| Key | Action |
| --- | --- |
| `h` / `l` | Scroll left / right |
| `j` / `k` | Scroll down / up |
| `J` / `K` | Move one screen down / up |
| Arrow keys | Corresponding scrolling direction |
| Page Down / Up | Screenful scrolling |

Next slide deliberately exceeds a normal terminal's height.
Next/previous page navigation resets scrolling.

# Tall slide
--font=block
--markdown
--gotokey:x:insert

Use **J**, Page Down, or the mouse wheel to reach the bottom.

```text
   01 │ source
   02 │ source
   03 │ source
   04 │ source
   05 │ source
   06 │ source
   07 │ source
   08 │ source
   09 │ source
   10 │ source
   11 │ source
   12 │ source
   13 │ source
   14 │ source
   15 │ source
   16 │ source
   17 │ source
   18 │ source
   19 │ source
   20 │ source
   21 │ source
   22 │ source
   23 │ source
   24 │ source
   25 │ source
   26 │ source
   27 │ source
   28 │ source
   29 │ source
   30 │ source
   31 │ source
   32 │ source
```

**You reached the bottom.** Press **K** to go up, or **n** to continue.

# Raw body
--font=plain
--notes:Legacy body rendering stays available without --markdown. This wide line deliberately extends beyond a normal pane; l and h expose the rest. The indentation inside a fenced block is preserved even in raw mode.

**These stars remain literal.** So does `inline code`.

The default body is raw; --markdown opts a slide in.
Use --markdown=false to return to raw text inside a slide.

LEFT ────────────────────────────────────────────────────────────────────────────────────────────── RIGHT: scroll with l to find me

```
    raw fenced code
        preserves its indentation
```

# Insertion
--font=block
--markdown
--label:insert
--gotokey:x:title

## Drop into the live r2 command prompt

Press **:**, then enter a command; an empty line resumes slides.

```text
?e hello world
```

To try the original writing exercise in a scratch session:

```text
o malloc://64
w hello world
px 16
```

This is manual: slide redraws do not repeat the write.

# Edit and reload
--font=block
--markdown

```text
   e / !       edit at the current slide's source line
   Ctrl-R      reload the deck from disk
   R / r       next / previous color theme
   ?           show navigation help
   q           leave slides and return to radare2
```

Editing uses **cfg.editor**. Saving and returning reloads the file.

Plain reload preserves your current page and scroll offsets,
subject to the new page count. Resize also redraws immediately.

# Questions
--font=block
--markdown
--gotokey:x:title
--gotokey:f:fonts
--gotokey:t:themes

## The presentation is still a radare2 session

```text
   r2 -i doc/slides.r2.md -

   . doc/slides.r2.md

   v. doc/slides.r2.md
```

Full syntax and implementation notes: **doc/r2slides.md**

**x** title · **f** fonts · **t** themes · **:** experiment · **q** exit
