Tiled r2 webui
==============

widgets required
----------------

notes: notepad with textarea to put your notes there
disasm: proper disasm widget
hexdump: proper hexdump widget
assemble: assemble instructions
console:
scrips:
floating/modal frame. invalidating the rest.

features
--------
follow in ->

Frames must have the following properties:
 - update() -> refresh the contents (run r2 command again, generate html, etc.)
 - seek(off) -> used by follow in...
 - selected
 - name -> we need a method to rename frames
