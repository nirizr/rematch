import re
import os


original_expanduser = os.path.expanduser


def expanduser_mock(path):
  fixed_path = re.sub(r'([^\\]~|^~)', './tests/idaplugin/home/', path)
  return original_expanduser(fixed_path)


os.path.expanduser = expanduser_mock
