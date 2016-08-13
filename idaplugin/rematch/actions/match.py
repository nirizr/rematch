import idaapi
import idc
from idautils import Functions

from .. import instances
from ..collectors.dummy import DummyVector
from .. import network
from . import base


class MatchAllAction(base.BoundFileAction):
  name = "&Match all"
  group = "Match"

  def activate(self, ctx):
    nn = idaapi.netnode("$rematch")
    file_id = nn.hashstr('bound_file_id')

    # this is horribly slow
    for fea in Functions():
      func = instances.FunctionInstance(file_id, fea)
      func.vectors.add(DummyVector())
      func.vectors.add(DummyVector())
      network.query("POST", "collab/instances/", params=func.serialize(),
                    json=True)


class MatchFunctionAction(base.BoundFileAction):
  name = "Match &Function"
  group = "Match"

  def activate(self, ctx):
    nn = idaapi.netnode("$rematch")
    file_id = nn.hashstr('bound_file_id')

    function = idaapi.choose_func("Choose function to match with database",
                                  idc.ScreenEA())
    if function is None:
      return

    data = instances.FunctionInstance(file_id, function.startEA)
    network.query("POST", "collab/instances/", params=data.serialize(),
                  json=True)
