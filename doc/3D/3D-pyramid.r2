#!/usr/bin/r2 --
o malloc://2048
b 28
# []
wow 27 @ 25+(80*3)
wow 27 @ 25+(80*4)
wow 27 @ 25+(80*5)
wow 27 @ 25+(80*6)
wow 27 @ 25+(80*7)
wow 27 @ 25+(80*8)
wow 27 @ 25+(80*9)
wow 27 @ 25+(80*10)
wow 27 @ 25+(80*11)
wow 27 @ 25+(80*12)
wow 27 @ 25+(80*13)
wow 27 @ 25+(80*14)
# []
f delta=4
b 24-delta
wow 40 @ 25+delta+(80*5)
wow 40 @ 25+delta+(80*6)
wow 40 @ 25+delta+(80*7)
wow 40 @ 25+delta+(80*8)
wow 40 @ 25+delta+(80*9)
wow 40 @ 25+delta+(80*10)
wow 40 @ 25+delta+(80*11)
wow 40 @ 25+delta+(80*12)
# []
f delta=8
b 24-delta-4
wow 52 @ 25+delta+(80*7)
wow 52 @ 25+delta+(80*8)
wow 52 @ 25+delta+(80*9)
wow 52 @ 25+delta+(80*10)
b 18*80
e hex.cols=80
# px
p3
