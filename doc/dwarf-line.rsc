# seek to section..debug_line
# (getdline,?e `f~debug_line`~section.[0])
(getdline,?e `S=~debug_line[1]`)
(getdline_end,?e `S=~debug_line[3]`)
f dline_begin 1 `.(getdline)`
f dline_end @ `.(getdline_end)`
f dline_size 1 dline_end-dline_begin
#
s dline_begin
b dline_size
?e dump of section debug_line:
x
#
# show header information
?e Header:
pf xwxccccc length version prolog min init linebase linerange opbase
#
s+15
b-15
# TODO. implement b+ and b-
pf 12b
s+12
b-12
x
