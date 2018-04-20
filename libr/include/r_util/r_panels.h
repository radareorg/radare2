#ifndef R_PANELS_H
#define R_PANELS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	PANEL_TYPE_FRAME = 0,
	PANEL_TYPE_MENU = 1
} PanelType;

typedef struct r_panel_t {
	int x;
	int y;
	int w;
	int h;
	int depth;
	int sx; // scroll-x
	int sy; // scroll-y
	char *cmd;
	char *title;
	bool refresh;
	PanelType type;
} RPanel;

#ifdef __cplusplus
}
#endif

#endif //  R_PANELS_H
