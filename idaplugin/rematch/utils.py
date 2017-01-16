import os
import idc


def getPluginBase(*path):
  return os.path.join(idc.GetIdaDirectory(), "plugins", *path)


def getPluginPath(*path):
  return getPluginBase("rematch", *path)
