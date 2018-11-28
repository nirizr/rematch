from .idasix import QtCore, QtWidgets

import ida_idaapi

from . import config
from . import actions
from . import update


class RematchPlugin(ida_idaapi.plugin_t):
  # Load when IDA starts and don't unload until it exists
  flags = ida_idaapi.PLUGIN_FIX
  comment = "Rematch"
  help = ""
  wanted_name = "Rematch"
  wanted_hotkey = "Alt-F8"

  def __init__(self, *args, **kwargs):
    super(RematchPlugin, self).__init__(*args, **kwargs)

    self.mainwindow = None
    self.toolbar = None
    self.menu = None

    self.update_checker = update.UpdateChecker()
    self.statusbar_label = None

  def init(self):
    self.setup()

    return ida_idaapi.PLUGIN_KEEP

  def setup(self):
    if not self.get_mainwindow():
      self.delay_setup()
      return

    # self.toolbar = self.get_mainwindow().addToolBar("Rematch")
    # self.toolbar.setIconSize(QtCore.QSize(16, 16))

    if not self.get_mainwindow().menuWidget():
      self.delay_setup()
      return

    self.menu = QtWidgets.QMenu("Rematch")
    self.get_mainwindow().menuWidget().addMenu(self.menu)

    actions.login.LoginAction().register()
    actions.login.LogoutAction().register()

    actions.project.AddProjectAction().register()
    actions.project.AddFileAction().register()

    actions.upload.UploadAction().register()
    actions.match.MatchAction().register()

    actions.settings.SettingsAction().register()

    # set up status bar
    self.statusbar_label = QtWidgets.QLabel("Rematch loaded")
    self.get_mainwindow().statusBar().addPermanentWidget(self.statusbar_label)

    self.update_checker.check_update()

  def delay_setup(self):
    QtCore.QTimer.singleShot(1000, self.setup)

  def run(self, arg=0):
    actions.settings.SettingsAction().activate()

  def term(self):
    if ('token' in config['login'] and
        config['settings']['login']['autologout']):
      del config['login']['token']
    config.save()

  def __del__(self):
    self.term()

  def get_mainwindow(self):
    if self.mainwindow:
      return self.mainwindow

    app = QtWidgets.qApp
    widgets = [app.focusWidget(), app.activeWindow()] + app.topLevelWidgets()
    mainwidgets = list(filter(None, map(self.search_mainwindow, widgets)))

    if mainwidgets:
      self.mainwindow = mainwidgets[0]

    return self.mainwindow

  @staticmethod
  def search_mainwindow(widget):
    while widget is not None:
      if isinstance(widget, QtWidgets.QMainWindow):
        return widget
      widget = widget.parent()
    return None
