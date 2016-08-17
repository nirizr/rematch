import os
import idc


def getPluginPath(*path):
  return os.path.join(idc.GetIdaDirectory(), "plugins", "rematch", *path)
