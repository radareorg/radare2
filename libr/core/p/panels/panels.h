/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

#ifndef R_CORE_PANELS_PRIVATE_H
#define R_CORE_PANELS_PRIVATE_H

#include <r_core.h>
#include "free.h"

#define MENU_Y 1
#define PANEL_HEADER_H 1
#define PANEL_FOOTER_H 1
#define PANEL_HL_COLOR core->cons->context->pal.graph_box2
#define PANEL_FRAME_BUTTON "[=]"
#define PANEL_CONFIG_SIDEPANEL_W 60
#define PANEL_CONFIG_MIN_SIZE    2
#define PANEL_CONFIG_RESIZE_W    4
#define PANEL_CONFIG_RESIZE_H    4
#define MAX_CANVAS_SIZE 0xffffff

#define PP(pos, off) (*(int *)((char *)&(pos) + (off)))

typedef struct {
	const char *name;
	const char *desc;
	RPanelsMenuCallback cb;
} MenuItem;

typedef struct {
	char *name;
	char *desc;
	char *args;
} AnalPluginMenuEntry;

typedef struct {
	const char *cmd;
	RPanelRotateCallback cb;
} RotateEntry;

typedef struct {
	char *name;
	RPanelAlmightyCallback cb;
} ModalEntry;

typedef struct {
	int x;
	int y;
	int height;
	int max_scroll;
	int thumb;
	int thumb_size;
} RPanelsScrollbar;

typedef struct {
	int address_x;
	int address_w;
	int undo_x;
	int redo_x;
	int prev_tabs_x;
	int prev_tab;
	int next_tabs_x;
	int next_tab;
	int tab_x[PANEL_NUM_LIMIT];
	int tab_w[PANEL_NUM_LIMIT];
	int menu_x;
} RPanelsNavLayout;

typedef struct {
	const char *name;
	const char *desc;
	RPanelsMenuCallback cb;
	bool (*state)(RCore *core, RPanel *panel); // optional, appends (on) or (off) to the name
} FrameMenuAction;

typedef enum {
	PANEL_CACHE_AUTO,
	PANEL_CACHE_ON,
	PANEL_CACHE_OFF
} PanelCacheMode;

typedef struct {
	const char *name;
	const char *cmd;
	RPanelAlmightyCallback cb;
	PanelCacheMode cache;
} ModalEntryDef;

typedef int Direction;

static void r_panels_set_geometry(RPanelPos *pos, int x, int y, int w, int h);
static unsigned int r_panels_adjust_side_panels(RCore *core);
static void r_panels_save_panel_pos(RPanel* panel);
static void r_panels_restore_panel_pos(RPanel* panel);
static void r_panels_maximize_panel_size(RPanels *panels);
static void r_panels_dismantle_del_panel(RCore *core, RPanel *p, int pi);
static void r_panels_prepare_layout(RCore *core);
static void print_notch(RCore *core);
static void r_panels_update_help(RCore *core, RPanels *ps);
static void r_panels_do_panels_refresh(RCore *core);
static void r_panels_refresh(RCore *core);
static RPanelsMenuItem *r_panels_get_selected_menu_item(RPanels *panels);
static char *r_panels_menu_status_line(RPanelsMenuItem *item);
static void r_panels_mht_free_kv(HtPPKv *kv);
static void r_panels_menu_bar_range(RPanelsMenuItem *root, int sel, int bar_room, int *out_first, int *out_last);
static int frame_maximize_cb(void *user);
static int frame_contents_cb(void *user);
static int frame_cache_cb(void *user);
static int frame_split_horizontal_cb(void *user);
static int frame_split_vertical_cb(void *user);
static int frame_close_cb(void *user);
static int frame_move_menu_cb(void *user);
static bool frame_maximize_state(RCore *core, RPanel *panel);
static bool frame_cache_state(RCore *core, RPanel *panel);
static void r_panels_frame_menu_update(RCore *core);
static int continue_cb(void *user);
static int step_cb(void *user);
static int step_over_cb(void *user);
static int break_points_cb(void *user);
static int show_all_decompiler_cb(void *user);
static void delegate_show_all_decompiler_cb(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title);
static int open_file_cb(void *user);
static int rw_cb(void *user);
static int debugger_cb(void *user);
static int load_layout_default_cb(void *user);
static int close_file_cb(void *user);
static int project_open_cb(void *user);
static int project_save_cb(void *user);
static int project_close_cb(void *user);
static int save_layout_cb(void *user);
static int clear_layout_cb(void *user);
static int copy_cb(void *user);
static int paste_cb(void *user);
static int write_str_cb(void *user);
static int write_hex_cb(void *user);
static int assemble_cb(void *user);
static int fill_cb(void *user);
static void init_menu_screen_settings_layout(void *_core, const char *parent);
static int calculator_cb(void *user);
static int r2_assembler_cb(void *user);
static int shell_r2_cb(void *user);
static int shell_system_cb(void *user);
static int shell_r2js_cb(void *user);
static int shell_mmc_cb(void *user);
static int shell_fs_cb(void *user);
static int string_whole_bin_cb(void *user);
static int string_data_sec_cb(void *user);
static int rop_cb(void *user);
static int magic_cb(void *user);
static int code_cb(void *user);
static int hexpairs_cb(void *user);
static int esil_init_cb(void *user);
static int esil_step_to_cb(void *user);
static int esil_step_range_cb(void *user);
static int io_cache_on_cb(void *user);
static int io_cache_off_cb(void *user);
static int reload_cb(void *user);
static int function_cb(void *user);
static int symbols_cb(void *user);
static int program_cb(void *user);
static int aap_cb(void *user);
static int basic_blocks_cb(void *user);
static int calls_cb(void *user);
static int watch_points_cb(void *user);
static int references_cb(void *user);
static int fortune_cb(void *user);
static int game_cb(void *user);
static int help_cb(void *user);
static int license_cb(void *user);
static int version2_cb(void *user);
static int version_cb(void *user);
static int r2rc_cb(void *user);
static int writeValueCb(void *user);
static int quit_cb(void *user);
static int open_menu_cb(void *user);
static void init_menu_color_settings_layout(void *_core, const char *parent);
static void init_menu_disasm_asm_settings_layout(void *_core, const char *parent);
static bool r_panels_handle_zoom_mode(RCore *core, const int key);
static void handlePrompt(RCore *core, RPanels *panels);
static int add_cmd_panel(void *user);
static void jmp_to_cursor_addr(RCore *core, RPanel *panel);
static void set_breakpoints_on_cursor(RCore *core, RPanel *panel);
static void insert_value(RCore *core, int wat);
static void cursor_del_breakpoints(RCore *core, RPanel *panel);
static void handle_refs(RCore *core, RPanel *panel, ut64 tmp);
static void set_dcb(RCore *core, RPanel *p);
static void prevOpcode(RCore *core);
static void nextOpcode(RCore *core);
static bool r_panels_tab_menu_is_open(RPanels *panels);
static void r_panels_handle_tab_new(RCore *core);
static void r_panels_handle_tab_key(RCore *core, bool shift);
static const char *r_panels_navbar_tab_name(RPanelsRoot *root, int index, char *number, size_t number_size);
static void r_panels_handle_tab_nth(RCore *core, int ch);
static void r_panels_move_panel_to_tab(RCore *core, int dst);
static void handle_tab_new_with_cur_panel(RCore *core);
static void r_panels_open_tab_menu(RCore *core);
static void r_panels_create_modal(RCore *core, RPanel *panel);
static void r_panels_set_rcb(RPanels *ps, RPanel *p);
static int add_cmdf_panel(RCore *core, char *input, char *str);
static void replace_cmd(RCore *core, const char *title, const char *cmd);
static void create_panel_input(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title);
static void replace_current_panel_input(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title);
static void search_strings_data_create(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title);
static void search_strings_bin_create(void *user, RPanel *panel, const RPanelLayout dir, const char * R_NULLABLE title);
static void update_disassembly_or_open(RCore *core);
static bool r_panels_default_cache(RCore *core, RPanel *panel);
static char *r_panels_search_db(RCore *core, const char *title);
static void init_all_dbs(RCore *core);
static void set_pcb(RPanel *p);
static char *r_panels_config_path(bool syspath);
static void init_new_panels_root(RCore *core);
static bool panels_root(RCore *core, RPanelsRoot *panels_root);

#endif
