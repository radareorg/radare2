#ifndef R_PANELS_H
#define R_PANELS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	PANEL_LAYOUT_VERTICAL,
	PANEL_LAYOUT_HORIZONTAL,
	PANEL_LAYOUT_NONE
} RPanelLayout;

typedef enum {
	PANEL_TYPE_DEFAULT = 0,
	PANEL_TYPE_MENU = 1
} RPanelType;

typedef enum {
	PANEL_EDGE_NONE = 0,
	PANEL_EDGE_BOTTOM,
	PANEL_EDGE_RIGHT
} RPanelEdge;

typedef void (*RPanelMenuUpdateCallback)(void *user, const char *parent);
typedef void (*RPanelDirectionCallback)(void *user, int direction);
typedef void (*RPanelRotateCallback)(void *user, bool rev);
typedef void (*RPanelPrintCallback)(void *user, void *p);

typedef struct r_panel_pos_t {
	int x;
	int y;
	int w;
	int h;
} RPanelPos;

typedef struct r_panel_model_t {
	RPanelDirectionCallback directionCb;
	RPanelRotateCallback rotateCb;
	RPanelPrintCallback print_cb;
	RPanelType type;
	char *cmd;
	char *title;
	ut64 baseAddr;
	ut64 addr;
	bool cache;
	char *cmdStrCache;
	char *readOnly;
	char *funcName;
	char **filter;
	int n_filter;
	int rotate;
} RPanelModel;

typedef struct r_panel_view_t {
	RPanelPos pos;
	RPanelPos prevPos;
	int sx;
	int sy;
	int curpos;
	bool refresh;
	int edge;
} RPanelView;

typedef struct r_panel_t {
    RPanelModel *model;
    RPanelView *view;
} RPanel;

typedef void (*RPanelAlmightyCallback)(void *user, RPanel *panel, const RPanelLayout dir, R_NULLABLE const char *title);

#ifdef __cplusplus
}
#endif

#endif //  R_PANELS_H
