import os
import idc


def get_plugin_base(*path):
  return os.path.join(idc.GetIdaDirectory(), "plugins", *path)


def get_plugin_path(*path):
  return get_plugin_base("rematch", *path)
