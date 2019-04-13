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

typedef struct r_panel_model_t {
	RPanelDirectionCallback directionCb;
	RPanelType type;
	char *cmd;
	char *title;
	ut64 baseAddr;
	ut64 addr;
	bool cache;
	char *cmdStrCache;
	char *funcName;
} RPanelModel;

typedef struct r_panel_view_t {
	RPanelPos pos;
	RPanelPos prevPos;
	int sx;
	int sy;
	int curpos;
	bool refresh;
	int edgeflag;
} RPanelView;

typedef struct r_panel_t {
    RPanelModel *model;
    RPanelView *view;
} RPanel;

#ifdef __cplusplus
}
#endif

#endif //  R_PANELS_H
