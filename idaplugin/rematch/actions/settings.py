import idaapi

from . import base

from ..dialogs.settings import SettingsDialog


class SettingsAction(base.Action):
  name = "&Settings"

  def activate(self, ctx):
    SettingsDialog().get()

  def update(self, ctx):
    return idaapi.AST_ENABLE_ALWAYS
