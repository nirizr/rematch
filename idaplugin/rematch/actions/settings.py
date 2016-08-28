import idaapi

from . import base

from ..dialogs.settings import SettingsDialog


class SettingsAction(base.Action):
  name = "&Settings"

  @staticmethod
  def activate(ctx):
    SettingsDialog().get()

  @staticmethod
  def update(ctx):
    return idaapi.AST_ENABLE_ALWAYS
