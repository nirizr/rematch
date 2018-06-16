import idaapi

from . import base
from .. import config, netnode


class SettingsAction(base.IDAAction):
  name = "&Settings"

  @staticmethod
  def submit_handler(autocheck, autoupdate, autologin, autologout, debug,
                     bound_file):
    config['settings']['update']['autocheck'] = autocheck
    config['settings']['update']['autoupdate'] = autoupdate
    config['settings']['login']['autologin'] = autologin
    config['settings']['login']['autologout'] = autologout
    config['debug'] = debug
    config.save()

    netnode.bound_file_id = bound_file

    return True

  @staticmethod
  def update(ctx):
    del ctx
    return idaapi.AST_ENABLE_ALWAYS
