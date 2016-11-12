from .. import user, logger, netnode, utils

import idaapi
import idc


class Action(idaapi.action_handler_t):
  """Actions are objects registered to IDA's interface and added to the
  rematch menu and toolbar"""
  dialog = None

  reject_handler = None
  finish_handler = None
  submit_handler = None
  response_handler = None
  exception_handler = None

  def __init__(self):
    self._icon = None
    self.dlg = None

  def __repr__(self):
    return "<Action: {}>".format(self.get_id())

  def __del__(self):
    if self._icon:
      idaapi.free_custom_icon(self._icon)

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
      image_path = utils.getPluginPath('images', self.get_id() + ".png")
      self._icon = idaapi.py_load_custom_icon_fn(image_path)
    return self._icon

  def get_desc(self):
    return idaapi.action_desc_t(
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

  @classmethod
  def register(cls):
    action = cls()
    r = idaapi.register_action(action.get_desc())
    if not r:
      logger('actions').warn("failed registering {}: {}".format(cls, r))
      return
    idaapi.attach_action_to_menu(
        action.get_action_path(),
        action.get_id(),
        idaapi.SETMENU_APP)
    r = idaapi.attach_action_to_toolbar(
        "AnalysisToolBar",
        action.get_id())
    if not r:
      logger('actions').warn("registration of {} failed: {}".format(cls, r))
    return action

  def update(self, ctx):
    return idaapi.AST_ENABLE if self.enabled(ctx) else idaapi.AST_DISABLE

  def activate(self, ctx):
    if self.dialog:
      self.dlg = self.dialog(reject_handler=self.reject_handler,
                             submit_handler=self.submit_handler,
                             response_handler=self.response_handler,
                             exception_handler=self.exception_handler)
      if self.finish_handler:
        self.dlg.finished.connect(self.finish_handler)
      self.dlg.finished.connect(self.force_update)
      self.dlg.show()
    else:
      logger('actions').warn("{}: no activation".format(self.__class__))
      logger('actions').debug(map(str, (ctx.form, ctx.form_type,
                                        ctx.form_title, ctx.chooser_selection,
                                        ctx.action, ctx.cur_flags)))

  @staticmethod
  def force_update():
    """Forcefuly requests IDA kernel to update all widgets and views. Useful
    for when delayed actions modify the program and/or plugin state without
    IDA's awareness"""
    iwid_all = 0xFFFFFFFF
    idaapi.request_refresh(iwid_all)


class IdbAction(Action):
  """This action is only available when an idb file is loaded"""
  @staticmethod
  def enabled(ctx):
    return bool(idc.GetIdbPath())


class UnauthAction(Action):
  """This action is only available when a user is logged off"""
  @staticmethod
  def enabled(ctx):
    return not bool(user['is_authenticated'])


class AuthAction(Action):
  """This action is only available when a user is logged in"""
  @staticmethod
  def enabled(ctx):
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
