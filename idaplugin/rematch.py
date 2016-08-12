import os
import sys

import rematch

# IDA hack
sys.path += [os.path.join(sys.prefix, "Lib", "site-packages")]


def PLUGIN_ENTRY():
  return rematch.plugin.RematchPlugin()
