#!/usr/bin/env python

# ragdiff2 - Copyright 2010-2011
#   nibble <develsec.org>

import sys
import os
import gtk
import gtk.gdk
import xdot
import time
import tempfile
from r2.r_core import *

class ViewWidget(gtk.VBox):
	ui = '''
	<ui>
		<toolbar name="ToolBar">
			<toolitem action="ZoomIn"/>
			<toolitem action="ZoomOut"/>
			<toolitem action="ZoomFit"/>
			<toolitem action="Zoom100"/>
		</toolbar>
	</ui>
	'''

	def __init__(self):
		gtk.VBox.__init__(self)
		# XDotWidget
		xdotwidget = self.xdotwidget = xdot.DotWidget()
		# Toolbar
		uimanager = gtk.UIManager()
		actiongroup = gtk.ActionGroup('Actions')
		actiongroup.add_actions((
			('ZoomIn', gtk.STOCK_ZOOM_IN, None, None, None, self.xdotwidget.on_zoom_in),
			('ZoomOut', gtk.STOCK_ZOOM_OUT, None, None, None, self.xdotwidget.on_zoom_out),
			('ZoomFit', gtk.STOCK_ZOOM_FIT, None, None, None, self.xdotwidget.on_zoom_fit),
			('Zoom100', gtk.STOCK_ZOOM_100, None, None, None, self.xdotwidget.on_zoom_100),
		))
		uimanager.insert_action_group(actiongroup, 0)
		uimanager.add_ui_from_string(self.ui)
		toolbar = uimanager.get_widget('/ToolBar')
		toolbar.set_icon_size(gtk.ICON_SIZE_SMALL_TOOLBAR)
		toolbar.set_style(gtk.TOOLBAR_ICONS)
		toolbar.set_show_arrow(False)
		label = self.label = gtk.Label()
		hbox = gtk.HBox(False, 5)
		hbox.pack_start(toolbar, False)
		hbox.pack_start(label, False)
		self.pack_start(hbox, False)
		self.pack_start(xdotwidget)

	def set_filename(self, name):
		self.label.set_text(name)

	def set_code(self, code, fit):
		self.xdotwidget.set_dotcode(code)
		if (fit):
			self.xdotwidget.zoom_to_fit()

class DiffWidget(gtk.VPaned):
	def __init__(self):
		gtk.VPaned.__init__(self)
		self.set_position (500)
		# Graph viewers
		hbox = gtk.HBox(True, 5)
		dw = self.dw = ViewWidget()
		dw2 = self.dw2 = ViewWidget()
		hbox.pack_start(dw)
		hbox.pack_start(dw2)
		self.add(hbox)
		# Function list
		scrolledwin = gtk.ScrolledWindow()
		scrolledwin.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
		liststore = self.liststore = gtk.ListStore(str, str, str, str, str)
		treeview = gtk.TreeView(liststore)
		# Column Address L
		tvcolumn0 = gtk.TreeViewColumn('Function L')
		treeview.append_column(tvcolumn0)
		cell0 = gtk.CellRendererText()
		tvcolumn0.pack_start(cell0, True)
		tvcolumn0.add_attribute(cell0, 'text', 0)
		tvcolumn0.set_sort_column_id(0)
		# Column Function L
		tvcolumn1 = gtk.TreeViewColumn('Address L')
		treeview.append_column(tvcolumn1)
		cell1 = gtk.CellRendererText()
		tvcolumn1.pack_start(cell1, True)
		tvcolumn1.add_attribute(cell1, 'text', 1)
		tvcolumn1.set_sort_column_id(1)
		# Column Address R
		tvcolumn2 = gtk.TreeViewColumn('Function R')
		treeview.append_column(tvcolumn2)
		cell2 = gtk.CellRendererText()
		tvcolumn2.pack_start(cell2, True)
		tvcolumn2.add_attribute(cell2, 'text', 2)
		tvcolumn2.set_sort_column_id(2)
		# Column Function R
		tvcolumn3 = gtk.TreeViewColumn('Address R')
		treeview.append_column(tvcolumn3)
		cell3 = gtk.CellRendererText()
		tvcolumn3.pack_start(cell3, True)
		tvcolumn3.add_attribute(cell3, 'text', 3)
		tvcolumn3.set_sort_column_id(3)
		# Column Diff
		tvcolumn4 = gtk.TreeViewColumn('Diff')
		treeview.append_column(tvcolumn4)
		cell4 = gtk.CellRendererText()
		tvcolumn4.pack_start(cell4, True)
		tvcolumn4.add_attribute(cell4, 'text', 4)
		tvcolumn4.set_sort_column_id(4)
		# Set treeview options and add it to scrolledwin
		treeview.set_reorderable(True)
		scrolledwin.add(treeview)
		self.add2(scrolledwin)
		treeview.connect('row-activated', self.on_row_activated)
	
	def on_row_activated(self, treeview, row, col):
		model = treeview.get_model()
		self.row_handler(self, model[row][1], model[row][3])

	def set_row_handler(self, handler):
		self.row_handler = handler

	def set_filename_l(self, name):
		self.dw.set_filename(name)

	def set_filename_r(self, name):
		self.dw2.set_filename(name)

	def set_code_l(self, code, fit):
		self.dw.set_code(code, fit)

	def set_code_r(self, code, fit):
		self.dw2.set_code(code, fit)

	def add_function(self, row):
		self.liststore.append(row)

	def clear_functions(self):
		self.liststore.clear()


class RagDiff2(gtk.Window):
	def __init__(self):
		gtk.Window.__init__(self)
		self.c = RCore()
		self.c2 = RCore()
		# Main window
		self.set_title('ragdiff2')
		self.set_default_size(512, 512)
		dw = self.dw = DiffWidget()
		dw.set_row_handler(self.update_graphs)
		self.add(dw)
		self.connect('destroy', gtk.main_quit)

	def update_graphs(self, dw, addr_l, addr_r):
		if addr_l != '':
			file_l = tempfile.gettempdir()+os.sep+'ragdiff2_l'
			self.c.cmd0('agd %s > %s' % (addr_l, file_l))
			fp = file(file_l)
			dw.set_code_l (fp.read(), True)
			fp.close()
			os.unlink(file_l)
		else:
			dw.set_code_l ('digraph code { }', False)
		if addr_r != '':
			file_r = tempfile.gettempdir()+os.sep+'ragdiff2_r'
			self.c2.cmd0('agd %s > %s' % (addr_r, file_r))
			fp = file(file_r)
			dw.set_code_r (fp.read(), True)
			fp.close()
			os.unlink(file_r)
		else:
			dw.set_code_r ('digraph code { }', False)
	
	def set_files(self, file_l, file_r):
		# Init cores
		self.c.config.set_i("io.va", 1)
		self.c.config.set_i("anal.split", 1)
		self.c.file_open(file_l, 0, 0)
		self.c.bin_load(None)
		self.c2.config.set_i("io.va", 1)
		self.c2.config.set_i("anal.split", 1)
		self.c2.file_open(file_r, 0, 0)
		self.c2.bin_load(None)
		# Clear treeview
		self.dw.clear_functions()
		self.dw.set_filename_l(file_l)
		self.dw.set_filename_r(file_r)
	
	def diff(self):
		# Diff
		self.c.gdiff(self.c2)
		# Fill treeview
		for fcn in self.c.anal.get_fcns():
			if (fcn.type == FcnType_FCN or fcn.type == FcnType_SYM):
				diffaddr = '0x%08x' % fcn.diff.addr
				if (fcn.diff.type == BlockDiff_MATCH):
					difftype = "MATCH"
				elif (fcn.diff.type == BlockDiff_UNMATCH):
					difftype = "UNMATCH"
				else:
					difftype = "NEW"
					diffaddr = ''
				self.dw.add_function([fcn.name, '0x%08x' % fcn.addr, fcn.diff.name, diffaddr, difftype])
		for fcn in self.c2.anal.get_fcns():
			if ((fcn.type == FcnType_FCN or fcn.type == FcnType_SYM) and fcn.diff.type == BlockDiff_NULL):
				self.dw.add_function(['', '', fcn.name, '0x%08x' % fcn.addr, "NEW"])

def main():
	# Check args
	if (len (sys.argv) != 3):
		sys.exit('  usage: %s <file> <file>' % sys.argv[0])
	# Create ragdiff2 win
	rd = RagDiff2()
	rd.show_all()
	# Set and Diff files
	rd.set_files(sys.argv[1], sys.argv[2])
	rd.diff()
	# Gtk main
	gtk.main()

if __name__ == '__main__':
	main()
