from .. import user, log, netnode, utils

import ida_kernwin
import idc


class Action(object):
  dialog = None
  reject_handler = None
  accept_handler = None
  finish_handler = None
  submit_handler = None
  response_handler = None
  exception_handler = None

  def __init__(self, ui_class=None):
    super(Action, self).__init__()
    if ui_class:
      self.dialog = ui_class
    self.ui = None
    self._running = False

  def __repr__(self):
    return "<Action: {}>".format(self.dialog)

  def running(self):
    return self._running


class IDAAction(Action, ida_kernwin.action_handler_t):
  """Actions are objects registered to IDA's interface and added to the
  rematch menu and toolbar"""

  def __init__(self, *args, **kwargs):
    super(IDAAction, self).__init__(*args, **kwargs)
    self._icon = None

  def __repr__(self):
    return "<{}: {}>".format(self.__class__.__name__, self.dialog)

  def __del__(self):
    try:
      super(IDAAction, self).__del__()
      if self._icon:
        ida_kernwin.free_custom_icon(self._icon)
    except AttributeError:
      pass

  def get_name(self):
    return self.name

  def get_id(self):
    return self.get_name().replace('&', '').replace(' ', '_').lower()

  def get_text(self):
    if hasattr(self, 'text'):
      return self.text
    else:
      return self.get_name().replace("&", "")

  def get_shortcut(self):
    if hasattr(self, 'shortcut'):
      return self.shortcut
    else:
      return ""

  def get_tooltip(self):
    if hasattr(self, 'tooltip'):
      return self.tooltip
    else:
      return self.get_text()

  def get_icon(self):
    if not self._icon:
      image_path = utils.get_plugin_path('images', self.get_id() + ".png")
      self._icon = ida_kernwin.py_load_custom_icon_fn(image_path)
    return self._icon

  def get_desc(self):
    return ida_kernwin.action_desc_t(
      self.get_id(),
      self.get_text(),
      self,
      self.get_shortcut(),
      self.get_tooltip(),
      self.get_icon())

  def get_action_group(self):
    if hasattr(self, 'group'):
      return self.group
    else:
      return ""

  def get_action_path(self):
    t = ["Rematch"]

    if self.get_action_group():
      t.append(self.get_action_group())

    t.append(self.get_name())

    return '/'.join(t)

  def register(self):
    r = ida_kernwin.register_action(self.get_desc())
    if not r:
      log('actions').warning("failed registering %s: %s", self, r)
      return
    ida_kernwin.attach_action_to_menu(
        self.get_action_path(),
        self.get_id(),
        ida_kernwin.SETMENU_APP)
    r = ida_kernwin.attach_action_to_toolbar(
        "AnalysisToolBar",
        self.get_id())
    if not r:
      log('actions').warn("registration of %s failed: %s", self, r)

  def update(self, ctx):
    if self.enabled(ctx):
      return ida_kernwin.AST_ENABLE
    else:
      return ida_kernwin.AST_DISABLE

  def activate(self, ctx):
    del ctx
    if self.running():
      return
    self._running = True

    if callable(self.dialog):
      try:
        self.ui = self.dialog(action=self)
        self.ui.show()
      except Exception:
        log('actions').exception("Exception thrown while showing dialog")
        self._running = False
        self.ui = None
    else:
      raise NotImplementedError("activation called on an action class with no "
                                "dialog defined")

  def finish_handler(self, status):
    del status
    log('actions').info("Action finished: %s", self)
    self._running = False


class IdbAction(IDAAction):
  """This action is only available when an idb file is loaded"""
  @staticmethod
  def enabled(ctx):
    del ctx
    return bool(idc.GetIdbPath())


class UnauthAction(IDAAction):
  """This action is only available when a user is logged off"""
  @staticmethod
  def enabled(ctx):
    del ctx
    return not bool(user['is_authenticated'])


class AuthAction(IDAAction):
  """This action is only available when a user is logged in"""
  @staticmethod
  def enabled(ctx):
    del ctx
    return bool(user['is_authenticated'])


class AuthIdbAction(AuthAction, IdbAction):
  """This action is only available when an idb file is loaded and a user is
  logged in"""
  @staticmethod
  def enabled(ctx):
    return AuthAction.enabled(ctx) and IdbAction.enabled(ctx)


class BoundFileAction(AuthIdbAction):
  """This action is only available when a file bound to the remote server is
  loaded"""
  @staticmethod
  def enabled(ctx):
    if not AuthIdbAction.enabled(ctx):
      return False

    return bool(netnode.bound_file_id)


class UnboundFileAction(AuthIdbAction):
  """This action is only available when no file is bound to the remote
  server"""
  @staticmethod
  def enabled(ctx):
    if not AuthIdbAction.enabled(ctx):
      return False

    return not bool(netnode.bound_file_id)
