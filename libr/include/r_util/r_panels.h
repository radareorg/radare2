#ifndef R_PANELS_H
#define R_PANELS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	PANEL_TYPE_DEFAULT = 0,
	PANEL_TYPE_MENU = 1
} RPanelType;

typedef struct r_panel_pos_t {
	int x;
	int y;
	int w;
	int h;
} RPanelPos;

typedef struct r_panel_t {
	RPanelPos pos;
	RPanelPos prevPos;
	int depth;
	int sx; // scroll-x
	int sy; // scroll-y
	int curpos;
	char *cmd;
	char *title;
	bool refresh;
	RPanelType type;
	ut64 baseAddr;
	ut64 addr;
	char *cmdStrCache;
} RPanel;

#ifdef __cplusplus
}
#endif

#endif //  R_PANELS_H
