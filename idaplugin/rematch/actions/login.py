import idaapi

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
  def update(ctx):
    if 'is_authenticated' in user and user['is_authenticated']:
      return idaapi.AST_DISABLE
    else:
      return idaapi.AST_ENABLE


class LogoutAction(base.Action):
  name = "Log&out"
  group = "User"

  @staticmethod
  def activate(ctx):
    user.logout()

  @staticmethod
  def update(ctx):
    if 'is_authenticated' in user and user['is_authenticated']:
      return idaapi.AST_ENABLE
    else:
      return idaapi.AST_DISABLE
