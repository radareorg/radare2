#ifndef _INCLUDE_R_LINE_H_
#define _INCLUDE_R_LINE_H_

#include "r_types.h"
#include "r_cons.h"

#include <stdio.h>

#define R_LINE_BUFSIZE 1024
#define R_LINE_HISTSIZE 256

extern int r_line_echo;
extern const char *r_line_prompt;
extern const char *r_line_clipboard;
extern void r_line_label_show();

extern char **r_line_history;
extern int r_line_histsize;
extern int r_line_histidx;
extern int r_line_autosave;
extern int r_line_disable;

/* history */
extern char **r_line_history;
extern int r_line_histsize;
extern int r_line_histidx;
extern int r_line_autosave;
extern int r_line_disable;

int r_line_init();
int r_line_hist_load(const char *file);
char *r_line_readline(int argc, const char **argv);
extern int r_line_readchar();
extern int r_line_hist_add(const char *line);
int r_line_hist_save(const char *file);
int r_line_hist_label(const char *label, void (*cb)(const char*));
void r_line_label_show();

extern char **(*r_line_callback)(const char *text, int start, int end);

#if 0
extern char *hist_get_i(int p);
extern void hist_add(char *str, int log);
extern void hist_clean();
extern int hist_show();
#endif

#endif
