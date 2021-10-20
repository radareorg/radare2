#ifndef R2_CONS_UI_H
#define R2_CONS_UI_H

#ifndef R2_CONS_H
#include <r_cons.h>
#endif

typedef struct r_cons_ui_attributes_t {
	int w;
	int h;
} RConsUIAttributes;

typedef struct r_cons_ui_element_t {
	int x;
	int y;
	int w;
	int h;
	bool center_x;
	bool center_y;
	bool focusable;
	bool scrollable;
	char *buf;
} RConsUIElement;

typedef struct r_cons_ui_t {
	RConsCanvas *canvas;
	RConsUIElement root;
	RList *children;
	RConsUIAttributes attr;
} RConsUI;

R_API RConsUI *r_cons_ui_new();
R_API int r_cons_ui_run(RConsUI *ui);
R_API void r_cons_ui_render(RConsUI *ui, RConsUIElement *parent, RConsUIElement *node);
R_API char *r_cons_ui_tostring(RConsUI *ui);

#endif
