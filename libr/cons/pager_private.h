#ifndef PAGER_PRIVATE_H
#define PAGER_PRIVATE_H

R_IPI void pager_color_line(const char *line, RStrpool *p, RList *ml);
R_IPI void pager_printpage(const char *line, int *index, RList **mla, int from, int to, int w);
R_IPI int pager_next_match(int from, RList **mla, int lcount);
R_IPI int pager_prev_match(int from, RList **mla);
R_IPI bool pager_all_matches(const char *s, RRegex *rx, RList **mla, int *lines, int lcount);
R_IPI int *pager_splitlines(char *s, int *lines_count);

#endif
