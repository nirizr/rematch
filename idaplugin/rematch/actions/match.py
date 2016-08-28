import idaapi
import idc
from idautils import Functions

try:
  from PyQt5 import QtGui, QtCore, QtWidgets
except:
  from PySide import QtGui, QtCore
  QtWidgets = QtGui

from .. import instances
from .. import network, netnode
from . import base


class MatchAllAction(base.BoundFileAction):
  name = "&Match all"
  group = "Match"

  def activate(self, ctx):
    self.file_id = netnode.bound_file_id

    self.function_gen = enumerate(Functions())
    pd = QtWidgets.QProgressDialog(labelText="Processing functions...",
                                   minimum=0, maximum=len(list(Functions())))
    self.progress = pd
    self.progress.canceled.connect(self.cancel)
    self.timer = QtCore.QTimer()
    self.timer.timeout.connect(self.perform)
    self.timer.start()

  def perform(self):
    try:
      i, offset = self.function_gen.next()

      func = instances.FunctionInstance(self.file_id, offset)
      network.query("POST", "collab/instances/", params=func.serialize(),
                    json=True)

      i = i + 1
      self.progress.setValue(i)
      if (i >= self.progress.maximum()):
        self.timer.stop()
    except:
      self.timer.stop()
      raise

  def cancel(self):
    self.timer.stop()


class MatchFunctionAction(base.BoundFileAction):
  name = "Match &Function"
  group = "Match"

  @staticmethod
  def activate(ctx):
    file_id = netnode.bound_file_id

    function = idaapi.choose_func("Choose function to match with database",
                                  idc.ScreenEA())
    if function is None:
      return

    data = instances.FunctionInstance(file_id, function.startEA)
    network.query("POST", "collab/instances/", params=data.serialize(),
                  json=True)
