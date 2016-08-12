import idaapi

from . import base
from .. import user

from ..dialogs.login import LoginDialog


class LoginAction(base.Action):
  name = "&Login"
  group = "User"

  def activate(self, ctx):
    LoginDialog().get()

  def update(self, ctx):
    if 'is_authenticated' in user and user['is_authenticated']:
      return idaapi.AST_DISABLE
    else:
      return idaapi.AST_ENABLE


class LogoutAction(base.Action):
  name = "Log&out"
  group = "User"

  def activate(self, ctx):
    user.logout()

  def update(self, ctx):
    if 'is_authenticated' in user and user['is_authenticated']:
      return idaapi.AST_ENABLE
    else:
      return idaapi.AST_DISABLE
