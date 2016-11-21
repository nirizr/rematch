from . import base
from .. import user
from .. import config
from .. import exceptions

from ..dialogs.login import LoginDialog


class LoginAction(base.UnauthAction):
  name = "&Login"
  group = "User"
  dialog = LoginDialog

  def submit_handler(self, username, password, server, remember):
    try:
      if user.login(username, password, server=server):
        self.dlg.statusLbl.setText("Connected!")
        self.dlg.statusLbl.setStyleSheet("color: green;")

        config['login']['username'] = username
        config['login']['server'] = server
        if remember:
          config['login']['password'] = password
        else:
          config['login']['password'] = ""
        config.save()

        return True
    except (exceptions.ConnectionException, exceptions.ServerException):
      self.dlg.statusLbl.setText("Connection to server failed.")
      self.dlg.statusLbl.setStyleSheet("color: blue;")
    except (exceptions.QueryException, exceptions.AuthenticationException):
      self.dlg.statusLbl.setText("Invalid user name or password.")
      self.dlg.statusLbl.setStyleSheet("color: red;")
    return False


class LogoutAction(base.AuthAction):
  name = "Log&out"
  group = "User"

  @staticmethod
  def activate(ctx):
    del ctx
    user.logout()
