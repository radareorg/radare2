#ifndef R_PANELS_H
#define R_PANELS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*RPanelDirectionCallback)(void *user, int direction);

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

typedef enum {
	PANEL_EDGE_NONE,
	PANEL_EDGE_RIGHT,
	PANEL_EDGE_BOTTOM
} RPanelEdge;

typedef struct r_panel_t {
	RPanelPos pos;
	RPanelPos prevPos;
	RPanelDirectionCallback directionCb;
	int sx; // scroll-x
	int sy; // scroll-y
	int curpos;
	char *cmd;
	char *title;
	bool refresh;
	RPanelType type;
	ut64 baseAddr;
	ut64 addr;
	bool caching;
	char *cmdStrCache;
	int edgeflag;
} RPanel;

#ifdef __cplusplus
}
#endif

#endif //  R_PANELS_H
