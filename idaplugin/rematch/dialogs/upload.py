import idaapi
import idc

import json

from .. idasix import QtGui, QtWidgets, QtCore

from . import base
from .. import network
from .. import exceptions


class UploadDialog(QtWidgets.QProgressDialog, base.BaseDialog):
  def __init__(self, *args, **kwargs):
    super(UploadDialog, self).__init__(*args, **kwargs)
