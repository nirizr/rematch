import idaapi
import idc
from idautils import Functions

from .. import instances
from .. import network
from . import base


class Vector:
  def __init__(self, id):
    self.id = id

  def serialize(self):
    return {"instance": self.id, "type": "hash", "type_version": 0,
            "data": "NotEmpty"}


class MatchAllAction(base.BoundFileAction):
  name = "&Match all"
  group = "Match"

  def activate(self, ctx):
    nn = idaapi.netnode("$rematch")
    file_id = nn.hashstr('bound_file_id')

    # this is horribly slow
    fns = Functions()
    for f in fns:
      data = instances.FunctionInstance(file_id, f)
      r = network.query("POST", "collab/instances/", params=data.serialize(),
                        json=True)
      vec = Vector(r['id'])
      network.query("POST", "collab/vectors/", params=vec.serialize(),
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
    r = network.query("POST", "collab/instances/", params=data.serialize(),
                      json=True)
    vec = Vector(r['id'])
    r = network.query("POST", "collab/vectors/", params=[vec.serialize()],
                      json=True)
