from . import base
from .. import user
from .. import config
from .. import exceptions

from ..dialogs.login import LoginDialog


class LoginAction(base.Action):
  name = "&Login"
  group = "User"
  dialog = LoginDialog

  def submit_handler(self, username, password, server, remember):
    try:
      if user.login(username, password, server=server):
        self.dlg.statusLbl.setText("Connected!")
        self.dlg.statusLbl.setStyleSheet("color: green;")

        config['username'] = username
        config['server'] = server
        if remember:
          config['password'] = password
        else:
          config['password'] = ""
        config.save()

        self.dlg.accept()
        self.force_update()
    except (exceptions.ConnectionException, exceptions.ServerException):
      self.dlg.statusLbl.setText("Connection to server failed.")
      self.dlg.statusLbl.setStyleSheet("color: blue;")
    except (exceptions.QueryException, exceptions.AuthenticationException):
      self.dlg.statusLbl.setText("Invalid user name or password.")
      self.dlg.statusLbl.setStyleSheet("color: red;")

  @staticmethod
  def enabled(ctx):
    if 'is_authenticated' in user and user['is_authenticated']:
      return False
    else:
      return True


class LogoutAction(base.Action):
  name = "Log&out"
  group = "User"

  @staticmethod
  def activate(ctx):
    user.logout()

  @staticmethod
  def enabled(ctx):
    if 'is_authenticated' in user and user['is_authenticated']:
      return True
    else:
      return False
