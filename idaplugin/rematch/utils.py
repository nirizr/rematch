import os
import sys

sys.path += [os.path.join(sys.prefix, "Lib", "site-packages")]

import idc

def getPluginPath(*path):
  return os.path.join(idc.GetIdaDirectory(), "plugins", "rematch", *path)
