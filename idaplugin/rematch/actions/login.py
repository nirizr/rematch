from . import base
from .. import user

from ..dialogs.login import LoginDialog


class LoginAction(base.Action):
  name = "&Login"
  group = "User"

  @staticmethod
  def activate(ctx):
    LoginDialog().get()

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
