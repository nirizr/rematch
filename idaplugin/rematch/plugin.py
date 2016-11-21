from idasix import QtCore, QtWidgets

import idaapi

from . import config, user, logger
from . import actions
from . import updater


class RematchPlugin(idaapi.plugin_t):
  # Load when IDA starts and don't unload until it exists
  flags = idaapi.PLUGIN_FIX
  comment = "Rematch"
  help = ""
  wanted_name = "Rematch"
  wanted_hotkey = "Alt-F8"

  def __init__(self):
    idaapi.plugin_t.__init__(self)

    self.mainwindow = None
    self.toolbar = None
    self.menu = None
    self.statusbar_label = None
    self.statusbar_timer = None
    self.timespent_timer = None
    self.timespent = None

  def init(self):
    QtCore.QTimer.singleShot(100, lambda: updater.update())

    self.setup()

    return idaapi.PLUGIN_KEEP

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

    actions.login.LoginAction.register()
    actions.login.LogoutAction.register()

    actions.project.AddProjectAction.register()
    actions.project.AddFileAction.register()

    actions.match.MatchAction.register()

    actions.settings.SettingsAction.register()

    # set up status bar
    self.statusbar_label = QtWidgets.QLabel("Rematch loaded")
    self.get_mainwindow().statusBar().addPermanentWidget(self.statusbar_label)

    # start status bar periodic update
    self.statusbar_timer = QtCore.QTimer()
    self.statusbar_timer.setInterval(1000)
    self.statusbar_timer.timeout.connect(lambda: self.update_statusbar())
    self.statusbar_timer.start()

    self.timespent = QtWidgets.QProgressBar()
    self.timespent.setMaximumHeight(32)
    self.timespent.setMaximumWidth(250)
    self.timespent.setRange(0, 60 * 60)
    self.get_mainwindow().statusBar().addPermanentWidget(self.timespent)

    self.timespent_timer = QtCore.QTimer()
    self.timespent_timer.setInterval(1000)
    timespent = self.timespent

    def update_timespent():
        timespent.setValue((timespent.value() + 1) % (60 * 60 + 1))
    self.timespent_timer.timeout.connect(update_timespent)
    self.timespent_timer.start()

  def update_statusbar(self):
    if 'is_authenticated' in user and user['is_authenticated']:
      self.statusbar_label.setText("Connected as {}".format(user['username']))
    else:
      self.statusbar_label.setText("Rematch loaded")

  def delay_setup(self):
    QtCore.QTimer.singleShot(1000, lambda: self.setup())

  def run(self, arg=0):
    logger('main').debug("run with arg: {}".format(arg))

  def term(self):
    if self.timespent_timer:
      self.timespent_timer.stop()
      self.timespent_timer = None

    if self.statusbar_timer:
      self.statusbar_timer.stop()
      self.statusbar_timer = None

    if config['settings']['login']['autologout']:
      del config['login']['token']
    config.save()

  def __del__(self):
    self.term()

  def get_mainwindow(self):
    if self.mainwindow:
      return self.mainwindow

    app = QtWidgets.qApp
    widgets = [app.focusWidget(), app.activeWindow()] + app.topLevelWidgets()
    mainwidgets = filter(None, map(self.search_mainwindow, widgets))

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
